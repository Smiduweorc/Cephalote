// Package scan walks a directory tree, routes each file to the appropriate
// detection tier, and aggregates findings. File reads and analysis run across
// a bounded worker pool for throughput on large trees.
package scan

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/Smiduweorc/Cephalote/internal/engine/goast"
	"github.com/Smiduweorc/Cephalote/internal/engine/ts"
	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/lang"
	"github.com/Smiduweorc/Cephalote/internal/scheme"
)

// Options configures a scan.
type Options struct {
	// IncludeUnknown enables the tier-3 regex fallback for files whose
	// language could not be identified.
	IncludeUnknown bool
	// MinConfidence drops findings below this confidence level.
	MinConfidence finding.Confidence
	// Workers is the analysis concurrency; <= 0 uses GOMAXPROCS.
	Workers int
	// MaxFileBytes skips files larger than this; <= 0 uses a 5 MiB default.
	MaxFileBytes int64
	// Schemes, when non-empty, switches the scan into search mode: instead of
	// the default weak-crypto rule set, every text file is searched for these
	// specific algorithms (weak or strong) regardless of language.
	Schemes []scheme.Scheme

	// The fields below are typically populated from a config file.

	// Exclude is a list of gitignore-style globs (supporting * and **) for
	// paths to skip, matched against the path relative to the scan root.
	Exclude []string
	// Disabled rule/scheme IDs are dropped from results.
	Disabled map[string]bool
	// SeverityOverrides remaps a rule/scheme ID's severity.
	SeverityOverrides map[string]finding.Severity
	// ExtraSchemes are user-defined schemes added to the default weak scan.
	ExtraSchemes []scheme.Scheme
}

// Result is the outcome of a scan.
type Result struct {
	Findings     []finding.Finding
	FilesScanned int
	FilesSkipped int
	Errors       []error
}

// skipDirs are directories never worth scanning (VCS metadata, vendored deps,
// build output). This is a pragmatic default until full .gitignore support
// lands.
var skipDirs = map[string]bool{
	".git": true, ".hg": true, ".svn": true,
	"node_modules": true, "vendor": true, "venv": true, ".venv": true,
	"dist": true, "build": true, "target": true, "out": true,
	"__pycache__": true, ".tox": true, ".mypy_cache": true,
	".idea": true, ".vscode": true,
}

const defaultMaxFileBytes = 5 << 20 // 5 MiB

// runner holds the resolved, immutable state shared by all workers.
type runner struct {
	opts     Options
	maxBytes int64
	excludes []globMatcher
	weakSet  []scheme.Scheme // default tier-3 set (catalog weak + custom)
}

// Run scans dir according to opts.
func Run(dir string, opts Options) (*Result, error) {
	maxBytes := opts.MaxFileBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxFileBytes
	}
	excludes, err := compileGlobs(opts.Exclude)
	if err != nil {
		return nil, err
	}
	r := &runner{
		opts:     opts,
		maxBytes: maxBytes,
		excludes: excludes,
		weakSet:  buildWeakSet(opts.ExtraSchemes),
	}

	workers := opts.Workers
	if workers <= 0 {
		workers = runtime.NumCPU()
	}

	paths := make(chan string)
	var (
		mu     sync.Mutex
		result Result
		wg     sync.WaitGroup
	)

	worker := func() {
		defer wg.Done()
		for path := range paths {
			fs, skipped, err := r.analyzeFile(path)
			mu.Lock()
			switch {
			case err != nil:
				result.Errors = append(result.Errors, err)
			case skipped:
				result.FilesSkipped++
			default:
				result.FilesScanned++
				result.Findings = append(result.Findings, fs...)
			}
			mu.Unlock()
		}
	}

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker()
	}

	walkErr := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			mu.Lock()
			result.Errors = append(result.Errors, err)
			mu.Unlock()
			return nil
		}
		rel := relPath(dir, path)
		if d.IsDir() {
			if skipDirs[d.Name()] || r.excluded(rel, d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || r.excluded(rel, d.Name()) {
			return nil
		}
		paths <- path
		return nil
	})
	close(paths)
	wg.Wait()

	if walkErr != nil {
		return &result, walkErr
	}

	result.Findings = r.postProcess(result.Findings)
	return &result, nil
}

// analyzeFile reads and analyzes one file. The skipped result distinguishes a
// deliberately ignored file (too large, binary, unrecognized) from an error.
func (r *runner) analyzeFile(path string) (fs []finding.Finding, skipped bool, err error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	if info.Size() > r.maxBytes {
		return nil, true, nil
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, false, err
	}
	if isBinary(src) {
		return nil, true, nil
	}

	fs, skipped, err = r.detect(path, src)
	if err != nil || skipped {
		return nil, skipped, err
	}
	return applySuppressions(fs, src), false, nil
}

// detect routes a file to a detection tier and returns its raw findings.
func (r *runner) detect(path string, src []byte) (fs []finding.Finding, skipped bool, err error) {
	// Search mode: look for the requested algorithms in every text file,
	// independent of language detection.
	if len(r.opts.Schemes) > 0 {
		fs, err = scheme.Scan(path, src, r.opts.Schemes)
		return fs, false, err
	}

	l := lang.Detect(path, src)
	switch l.Tier {
	case lang.TierGoAST:
		fs, err = goast.Analyze(path, src)
		// A parse error still yields whatever findings were produced from the
		// partial AST; surface findings, swallow the parse error.
		return fs, false, nil
	case lang.TierTreeSitter:
		// Use the tier-2 Tree-sitter analyzer when it is compiled in (the
		// `treesitter` build) and supports this language; otherwise fall back
		// to the tier-3 regex scan.
		if ts.Available() && ts.Supported(l.Name) {
			fs, err = ts.Analyze(l.Name, path, src)
			return fs, false, err
		}
		fs, err = scheme.Scan(path, src, r.weakSet)
		return fs, false, err
	case lang.TierRegex:
		fs, err = scheme.Scan(path, src, r.weakSet)
		return fs, false, err
	default: // TierNone
		if !r.opts.IncludeUnknown {
			return nil, true, nil
		}
		fs, err = scheme.Scan(path, src, r.weakSet)
		return fs, false, err
	}
}

// postProcess applies config-driven rule disabling and severity overrides,
// then confidence filtering and deterministic sorting.
func (r *runner) postProcess(fs []finding.Finding) []finding.Finding {
	minRank := r.opts.MinConfidence.Rank()
	out := fs[:0]
	for _, f := range fs {
		if r.opts.Disabled[f.RuleID] {
			continue
		}
		if f.Confidence.Rank() < minRank {
			continue
		}
		if sev, ok := r.opts.SeverityOverrides[f.RuleID]; ok {
			f.Severity = sev
		}
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.RuleID < b.RuleID
	})
	return out
}

func (r *runner) excluded(rel, base string) bool {
	for _, g := range r.excludes {
		if g.match(rel, base) {
			return true
		}
	}
	return false
}

// buildWeakSet returns a fresh slice of the default weak schemes plus any
// user-defined ones (fresh, so we never mutate the cached catalog slice).
func buildWeakSet(extra []scheme.Scheme) []scheme.Scheme {
	base := scheme.WeakSchemes()
	ws := make([]scheme.Scheme, 0, len(base)+len(extra))
	ws = append(ws, base...)
	ws = append(ws, extra...)
	return ws
}

func relPath(dir, path string) string {
	if rel, err := filepath.Rel(dir, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return filepath.ToSlash(path)
}

// isBinary heuristically treats a file as binary if its first chunk contains a
// NUL byte.
func isBinary(src []byte) bool {
	const sniff = 8000
	if len(src) > sniff {
		src = src[:sniff]
	}
	return bytes.IndexByte(src, 0) >= 0
}

// applySuppressions drops findings silenced by an inline `cephalote:ignore`
// directive on the finding's line or the line immediately above it.
func applySuppressions(fs []finding.Finding, src []byte) []finding.Finding {
	if len(fs) == 0 {
		return fs
	}
	lines := strings.Split(string(src), "\n")
	lineAt := func(n int) string {
		if n >= 1 && n <= len(lines) {
			return lines[n-1]
		}
		return ""
	}
	out := fs[:0]
	for _, f := range fs {
		if suppressed(lineAt(f.Line), f.RuleID) || suppressed(lineAt(f.Line-1), f.RuleID) {
			continue
		}
		out = append(out, f)
	}
	return out
}
