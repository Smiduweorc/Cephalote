package scan

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/engine/ts"
	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/scheme"
)

// schemeFromConfigLike builds the custom scheme used by the disabled/custom test.
func schemeFromConfigLike(t *testing.T) ([]scheme.Scheme, error) {
	t.Helper()
	s, err := scheme.New("internal-xor", "Home-grown XOR", scheme.Broken, "", "Use AEAD.", `(?i)\bxor_encrypt\b`)
	if err != nil {
		return nil, err
	}
	return []scheme.Scheme{s}, nil
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRun_RoutingAndFiltering(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package a\nimport \"crypto/md5\"\nvar _ = md5.New()\n")
	// Ruby is a tier-2 language, so its finding is high confidence in the
	// treesitter profile and low (regex) in the default one.
	writeFile(t, dir, "b.rb", "require 'digest'\nDigest::MD5.hexdigest('x')\n")
	writeFile(t, dir, "vendor/skip.go", "package v\nimport \"crypto/md5\"\nvar _ = md5.New()\n")
	writeFile(t, dir, "notes.txt", "uses md5 somewhere\n")

	rubyTier2 := ts.Available() && ts.Supported("ruby")

	// Default: Go (high) + Ruby; .txt unknown is skipped.
	res, err := Run(dir, Options{MinConfidence: finding.Low})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Findings); got != 2 {
		t.Fatalf("default findings = %d, want 2: %+v", got, res.Findings)
	}

	// vendor/ must be skipped entirely.
	for _, f := range res.Findings {
		if filepath.Base(filepath.Dir(f.File)) == "vendor" {
			t.Errorf("vendor file should have been skipped: %s", f.File)
		}
	}

	// min-confidence high drops every regex finding, which in the default
	// profile includes the Ruby one.
	wantHigh := 1
	if rubyTier2 {
		wantHigh = 2
	}
	res, err = Run(dir, Options{MinConfidence: finding.High})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Findings); got != wantHigh {
		t.Fatalf("high-confidence findings = %d, want %d: %+v", got, wantHigh, res.Findings)
	}

	// include-unknown picks up the .txt file.
	res, err = Run(dir, Options{MinConfidence: finding.Low, IncludeUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Findings); got != 3 {
		t.Fatalf("include-unknown findings = %d, want 3: %+v", got, res.Findings)
	}
}

func TestRun_SuppressionAndOverrides(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go",
		"package a\nimport (\"crypto/md5\"; \"crypto/sha1\")\n"+
			"var _ = md5.New()\n"+
			"var _ = sha1.New() // cephalote:ignore weak-hash-sha1\n")
	writeFile(t, dir, "skip/x.go", "package s\nimport \"crypto/md5\"\nvar _ = md5.New()\n")

	res, err := Run(dir, Options{
		MinConfidence:     finding.Low,
		Exclude:           []string{"skip/**"},
		SeverityOverrides: map[string]finding.Severity{"weak-hash-md5": finding.LowSev},
	})
	if err != nil {
		t.Fatal(err)
	}
	// sha1 suppressed, skip/ excluded -> only the md5 finding remains.
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.RuleID != "weak-hash-md5" || f.Severity != finding.LowSev {
		t.Errorf("override not applied: %+v", f)
	}
}

func TestRun_DisabledAndCustomScheme(t *testing.T) {
	dir := t.TempDir()
	// Ruby stays tier-3 in both builds, so this resolves to scheme:md5.
	writeFile(t, dir, "a.rb", "require 'digest'\nDigest::MD5.hexdigest('x')\n") // scheme:md5 (tier3)
	writeFile(t, dir, "b.txt", "call xor_encrypt(data) here\n")                 // custom, needs include-unknown

	custom, err := schemeFromConfigLike(t)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(dir, Options{
		MinConfidence:  finding.Low,
		IncludeUnknown: true,
		Disabled:       map[string]bool{"scheme:md5": true},
		ExtraSchemes:   custom,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int{}
	for _, f := range res.Findings {
		ids[f.RuleID]++
	}
	if ids["scheme:md5"] != 0 {
		t.Errorf("scheme:md5 should be disabled: %v", ids)
	}
	if ids["scheme:internal-xor"] != 1 {
		t.Errorf("custom scheme not detected: %v", ids)
	}
}

func TestRun_DeterministicOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "z.go", "package z\nimport \"crypto/md5\"\nvar _ = md5.New()\n")
	writeFile(t, dir, "a.go", "package a\nimport \"crypto/des\"\nvar _ = des.NewCipher(nil)\n")

	res, err := Run(dir, Options{MinConfidence: finding.Low})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(res.Findings))
	}
	if filepath.Base(res.Findings[0].File) != "a.go" {
		t.Errorf("findings not sorted by file: %s before %s",
			res.Findings[0].File, res.Findings[1].File)
	}
}

func TestRun_SkipsBinaryFiles(t *testing.T) {
	dir := t.TempDir()
	// A NUL byte in the first chunk marks the file as binary; without the skip
	// its bytes would be regex-scanned as if they were source.
	writeFile(t, dir, "blob.txt", "md5\x00\x01\x02md5\n")
	writeFile(t, dir, "real.txt", "md5 here\n")

	res, err := Run(dir, Options{MinConfidence: finding.Low, IncludeUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesSkipped != 1 || res.FilesScanned != 1 {
		t.Errorf("scanned=%d skipped=%d, want 1/1", res.FilesScanned, res.FilesSkipped)
	}
	for _, f := range res.Findings {
		if filepath.Base(f.File) == "blob.txt" {
			t.Errorf("binary file produced a finding: %+v", f)
		}
	}
}

func TestRun_SkipsOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "big.go", "package a\nimport \"crypto/md5\"\nvar _ = md5.New()\n")

	res, err := Run(dir, Options{MinConfidence: finding.Low, MaxFileBytes: 10})
	if err != nil {
		t.Fatal(err)
	}
	if res.FilesSkipped != 1 || len(res.Findings) != 0 {
		t.Errorf("skipped=%d findings=%d, want 1 skipped and no findings", res.FilesSkipped, len(res.Findings))
	}
}

func TestRun_SkipsWellKnownDirectories(t *testing.T) {
	dir := t.TempDir()
	weak := "package a\nimport \"crypto/md5\"\nvar _ = md5.New()\n"
	writeFile(t, dir, "keep.go", weak)
	for _, d := range []string{"node_modules", ".git", "dist", "target", "__pycache__", "venv"} {
		writeFile(t, dir, filepath.Join(d, "x.go"), weak)
	}
	res, err := Run(dir, Options{MinConfidence: finding.Low})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Errorf("findings = %d, want only the one outside the skipped dirs: %+v", len(res.Findings), res.Findings)
	}
}

func TestRun_ExcludeGlobs(t *testing.T) {
	dir := t.TempDir()
	weak := "package a\nimport \"crypto/md5\"\nvar _ = md5.New()\n"
	writeFile(t, dir, "keep.go", weak)
	writeFile(t, dir, "gen/api.go", weak)
	writeFile(t, dir, "a/b/thing_generated.go", weak)

	res, err := Run(dir, Options{
		MinConfidence: finding.Low,
		Exclude:       []string{"gen/**", "**/*_generated.go"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || filepath.Base(res.Findings[0].File) != "keep.go" {
		t.Errorf("findings = %+v, want only keep.go", res.Findings)
	}
}

// Exclude patterns are globs, not regexes: metacharacters must be literal, or
// a pattern like "a.go" would quietly exclude "axgo" too.
func TestRun_ExcludeMetacharactersAreLiteral(t *testing.T) {
	dir := t.TempDir()
	weak := "package a\nimport \"crypto/md5\"\nvar _ = md5.New()\n"
	writeFile(t, dir, "axgo.go", weak)
	writeFile(t, dir, "a.go", weak)

	res, err := Run(dir, Options{MinConfidence: finding.Low, Exclude: []string{"a.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || filepath.Base(res.Findings[0].File) != "axgo.go" {
		t.Errorf("findings = %+v, want only axgo.go (the dot must not match any character)", res.Findings)
	}
}

func TestRun_MissingDirectory(t *testing.T) {
	res, err := Run(filepath.Join(t.TempDir(), "absent"), Options{})
	// The walk error is surfaced either as the returned error or on the
	// result; what must not happen is a silent empty success.
	if err == nil && len(res.Errors) == 0 {
		t.Error("scanning a missing directory reported no error")
	}
}

func TestRun_EmptyDirectory(t *testing.T) {
	res, err := Run(t.TempDir(), Options{MinConfidence: finding.Low})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.FilesScanned != 0 || len(res.Errors) != 0 {
		t.Errorf("empty scan = %+v", res)
	}
}

// Results are aggregated across a worker pool, so ordering must come from the
// sort in postProcess rather than from scheduling.
func TestRun_OrderIsStableAcrossWorkerCounts(t *testing.T) {
	dir := t.TempDir()
	weak := "package a\nimport (\"crypto/md5\"; \"crypto/sha1\")\nvar _ = md5.New()\nvar _ = sha1.New()\n"
	for _, n := range []string{"a", "b", "c", "d", "e", "f", "g", "h"} {
		writeFile(t, dir, n+"/x.go", weak)
	}

	var reference []string
	for _, workers := range []int{1, 2, 4, 16} {
		res, err := Run(dir, Options{MinConfidence: finding.Low, Workers: workers})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, f := range res.Findings {
			got = append(got, fmt.Sprintf("%s:%d:%d:%s", f.File, f.Line, f.Column, f.RuleID))
		}
		if len(got) != 16 {
			t.Fatalf("workers=%d: findings = %d, want 16", workers, len(got))
		}
		if reference == nil {
			reference = got
			continue
		}
		for i := range got {
			if got[i] != reference[i] {
				t.Fatalf("workers=%d: order differs at %d: %s vs %s", workers, i, got[i], reference[i])
			}
		}
	}
}

// A file that cannot be read is an error, not a silent skip: the scan would
// otherwise report a clean tree it never actually looked at.
func TestRun_UnreadableFileIsReportedAsAnError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read any file")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "secret.go")
	writeFile(t, dir, "secret.go", "package a\n")
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })

	res, err := Run(dir, Options{MinConfidence: finding.Low})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Errors) == 0 {
		t.Error("an unreadable file should be reported in Errors")
	}
	if res.FilesScanned != 0 {
		t.Errorf("FilesScanned = %d, want 0", res.FilesScanned)
	}
}

func TestRun_SuppressionOnPrecedingLine(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go",
		"package a\nimport \"crypto/md5\"\n// cephalote:ignore weak-hash-md5\nvar _ = md5.New()\n")
	res, err := Run(dir, Options{MinConfidence: finding.Low})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("an ignore on the line above should suppress: %+v", res.Findings)
	}
}

func TestRun_SchemeSearchModeIgnoresLanguageTier(t *testing.T) {
	dir := t.TempDir()
	// Search mode runs over every text file regardless of language, and finds
	// strong algorithms the default weak scan would never report.
	writeFile(t, dir, "a.go", "package a\n// sha256 is used here\n")
	writeFile(t, dir, "notes.txt", "sha256 again\n")

	want, err := scheme.Resolve([]string{"sha256"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(dir, Options{MinConfidence: finding.Low, Schemes: want})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Errorf("findings = %+v, want one per file", res.Findings)
	}
}

func TestRun_SeverityOverrideAndDisableApplyToSchemeFindings(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "notes.txt", "md5 here\n")

	res, err := Run(dir, Options{
		MinConfidence:     finding.Low,
		IncludeUnknown:    true,
		SeverityOverrides: map[string]finding.Severity{"scheme:md5": finding.Info},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Severity != finding.Info {
		t.Fatalf("findings = %+v, want the override applied", res.Findings)
	}

	res, err = Run(dir, Options{
		MinConfidence:  finding.Low,
		IncludeUnknown: true,
		Disabled:       map[string]bool{"scheme:md5": true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want the rule disabled", res.Findings)
	}
}
