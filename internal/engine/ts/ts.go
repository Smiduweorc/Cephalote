//go:build treesitter

// Package ts is the tier-2 Tree-sitter analyzer. This build (tag `treesitter`,
// cgo enabled) provides real AST analysis for every language in the registry
// in lang_specs.go. The analyzer itself is language-agnostic: it walks the
// tree, renders dotted names out of whatever nodes the grammar uses for them,
// and matches those names against per-language tables. Adding a language means
// adding a table entry, not an analyzer.
package ts

import (
	"context"
	"errors"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/rules"
)

// Available reports that tier-2 Tree-sitter analysis is compiled in.
func Available() bool { return true }

// Supported reports whether a grammar+ruleset exists for a language.
func Supported(lang string) bool {
	_, ok := specs[lang]
	return ok
}

// Analyze runs the tier-2 analyzer for a supported language. Unsupported
// languages return nil so the caller falls back to tier 3. The path is used
// both to label findings and to pick between dialect grammars (.ts vs .tsx).
func Analyze(lang, path string, src []byte) ([]finding.Finding, error) {
	sp, ok := specs[lang]
	if !ok {
		return nil, nil
	}
	parser := sitter.NewParser()
	parser.SetLanguage(sp.syntax.language(path))
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil, err
	}
	defer tree.Close()
	return sp.analyze(tree.RootNode(), path, src), nil
}

func (sp spec) analyze(root *sitter.Node, path string, src []byte) []finding.Finding {
	lines := strings.Split(string(src), "\n")

	// aliases resolves names bound by an import, so a bare `md5(...)` after
	// `from hashlib import md5` matches the same table entry as `hashlib.md5`.
	var aliases map[string]string
	if sp.aliases != nil {
		aliases = sp.aliases(root, src)
	}

	// Nested nodes describe the same construct from different angles: an
	// attribute and the call wrapping it share a start (`hashlib.md5(...)`),
	// while a qualified name and its tail share an end (`CryptoPP::Weak::MD5`).
	// Reporting a rule once per start and once per end collapses both without
	// merging genuinely separate uses.
	type key struct {
		row, col uint32
		rule     string
	}
	seenStart, seenEnd := map[key]bool{}, map[key]bool{}
	var out []finding.Finding
	emit := func(ids []string, n *sitter.Node) {
		start, end := n.StartPoint(), n.EndPoint()
		for _, id := range ids {
			ks := key{start.Row, start.Column, id}
			ke := key{end.Row, end.Column, id}
			if seenStart[ks] || seenEnd[ke] {
				continue
			}
			seenStart[ks], seenEnd[ke] = true, true
			out = append(out, mkFinding(id, path, int(start.Row)+1, int(start.Column)+1, lines))
		}
	}

	s := sp.syntax
	walk(root, func(n *sitter.Node) {
		t := n.Type()
		_, isCall := s.call[t]
		if _, isMember := s.member[t]; isMember && !isCall {
			// A name used without calling it: `CipherMode.ECB`,
			// `Digest::MD5`, `CryptoPP::Weak::MD5`.
			if ids, ok := suffixLookup(sp.targets, s.dotted(n, src)); ok {
				emit(ids, n)
			}
		}
		if !isCall {
			return
		}
		name := resolveAlias(s.calleeName(n, src), aliases)
		if ids, ok := suffixLookup(sp.targets, name); ok {
			emit(ids, n)
		}
		if idx, ok := suffixLookup(sp.algoCalls, name); ok {
			if str, ok := s.stringArg(s.args(n), idx, src); ok {
				emit(classifyAlgorithm(str), n)
			}
		}
		if br, ok := suffixLookup(sp.bitsCalls, name); ok {
			if bits, ok := s.minIntArg(s.args(n), src); ok && br.flags(bits) {
				emit([]string{rules.RSASmall}, n)
			}
		}
	})
	return out
}

// flags reports whether a key size is one this rule considers undersized.
func (b bitsRule) flags(bits int) bool {
	if len(b.only) > 0 {
		for _, v := range b.only {
			if v == bits {
				return true
			}
		}
		return false
	}
	return b.max > 0 && bits < b.max
}

// resolveAlias rewrites an unqualified name to its imported canonical form.
func resolveAlias(name string, aliases map[string]string) string {
	if aliases == nil || strings.Contains(name, ".") {
		return name
	}
	if canon, ok := aliases[name]; ok {
		return canon
	}
	return name
}

// suffixLookup finds the table entry for a dotted name, matching either the
// whole name or a trailing run of its components, so that one entry covers
// every way the name can be qualified: "DES.new" matches
// `Crypto.Cipher.DES.new`. The longest matching key wins, which keeps the
// result independent of map iteration order.
func suffixLookup[T any](m map[string]T, dotted string) (T, bool) {
	if v, ok := m[dotted]; ok {
		return v, true
	}
	best := ""
	for k := range m {
		if len(k) > len(best) && strings.HasSuffix(dotted, "."+k) {
			best = k
		}
	}
	if best == "" {
		var zero T
		return zero, false
	}
	return m[best], true
}

var errNotInt = errors.New("not an integer literal")

// parseInt reads the decimal value of an integer literal, tolerating the digit
// separators and type suffixes that some languages allow (1_024, 1024u32,
// 1024L). Non-decimal literals are rejected rather than truncated to their
// leading "0".
func parseInt(s string) (int, error) {
	s = strings.ReplaceAll(s, "_", "")
	if len(s) > 1 && s[0] == '0' && !isDigit(s[1]) {
		return 0, errNotInt // 0x..., 0b..., 0o...
	}
	i := 0
	for i < len(s) && isDigit(s[i]) {
		i++
	}
	if i == 0 {
		return 0, errNotInt
	}
	return strconv.Atoi(s[:i])
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func mkFinding(ruleID, path string, line, col int, lines []string) finding.Finding {
	r := rules.MustGet(ruleID)
	f := finding.Finding{
		RuleID:      r.ID,
		Title:       r.Title,
		Description: r.Description,
		Severity:    r.Severity,
		Confidence:  finding.High,
		Remediation: r.Remediation,
		File:        path,
		Line:        line,
		Column:      col,
	}
	if line >= 1 && line <= len(lines) {
		f.Snippet = strings.TrimSpace(lines[line-1])
	}
	return f
}
