//go:build treesitter

// Package ts is the tier-2 Tree-sitter analyzer. This build (tag `treesitter`,
// cgo enabled) provides real AST analysis for Python as the design's proof
// language; more grammars slot in behind the same Analyze entry point.
package ts

import (
	"context"
	"strconv"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/python"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/rules"
)

// Available reports that tier-2 Tree-sitter analysis is compiled in.
func Available() bool { return true }

// Supported reports whether a grammar+ruleset exists for a language.
func Supported(lang string) bool { return lang == "python" }

// Analyze runs the tier-2 analyzer for a supported language. Unsupported
// languages return nil so the caller falls back to tier 3.
func Analyze(lang, path string, src []byte) ([]finding.Finding, error) {
	if lang != "python" {
		return nil, nil
	}
	return analyzePython(path, src)
}

// pyTargets maps a dotted call/attribute suffix to the rule it triggers. These
// are presence-based: seeing the construct at all is the finding. Suffix
// matching means both `hashlib.md5(...)` and `Crypto.Cipher.DES.new(...)` work.
var pyTargets = map[string]string{
	// hashlib / pycryptodome / cryptography hashes
	"hashlib.md5":  rules.MD5,
	"hashlib.sha1": rules.SHA1,
	"hashes.MD5":   rules.MD5,
	"hashes.SHA1":  rules.SHA1,
	"MD5.new":      rules.MD5,
	"SHA1.new":     rules.SHA1,
	// symmetric ciphers (pycryptodome / cryptography)
	"DES.new":              rules.DES,
	"DES3.new":             rules.TripleDES,
	"ARC4.new":             rules.RC4,
	"Blowfish.new":         rules.Blowfish,
	"algorithms.TripleDES": rules.TripleDES,
	"algorithms.ARC4":      rules.RC4,
	"algorithms.Blowfish":  rules.Blowfish,
	"modes.ECB":            rules.ECB,
	// insecure randomness for secrets
	"random.random":      rules.WeakRand,
	"random.randint":     rules.WeakRand,
	"random.randrange":   rules.WeakRand,
	"random.getrandbits": rules.WeakRand,
	"random.choice":      rules.WeakRand,
	// deprecated transport
	"ssl.PROTOCOL_TLSv1":   rules.WeakTLS,
	"ssl.PROTOCOL_TLSv1_1": rules.WeakTLS,
	"ssl.PROTOCOL_SSLv3":   rules.WeakTLS,
	"ssl.PROTOCOL_SSLv2":   rules.WeakTLS,
	"ssl.PROTOCOL_SSLv23":  rules.WeakTLS,
}

// weakHashNames maps the string argument of hashlib.new("md5") to a rule.
var weakHashNames = map[string]string{
	"md5": rules.MD5, "md4": rules.MD4, "sha1": rules.SHA1, "sha": rules.SHA1,
}

func analyzePython(path string, src []byte) ([]finding.Finding, error) {
	parser := sitter.NewParser()
	parser.SetLanguage(python.GetLanguage())
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		return nil, err
	}
	defer tree.Close()
	root := tree.RootNode()
	lines := strings.Split(string(src), "\n")

	// localImports maps a bound name to its canonical "module.name", so a bare
	// `md5(...)` after `from hashlib import md5` resolves correctly.
	localImports := collectFromImports(root, src)

	// Dedupe by (row, col, rule): an attribute and its enclosing call can both
	// resolve to the same location.
	type key struct {
		row, col uint32
		rule     string
	}
	seen := map[key]bool{}
	var out []finding.Finding
	emit := func(ruleID string, n *sitter.Node) {
		p := n.StartPoint()
		k := key{p.Row, p.Column, ruleID}
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, mkFinding(ruleID, path, int(p.Row)+1, int(p.Column)+1, lines))
	}

	walk(root, func(n *sitter.Node) {
		switch n.Type() {
		case "attribute":
			if id, ok := suffixLookup(dotted(n, src)); ok {
				emit(id, n)
			}
		case "call":
			handleCall(n, src, localImports, emit)
		}
	})
	return out, nil
}

// handleCall covers the value-dependent and bare-identifier cases that the
// generic attribute pass cannot: RSA key size, hashlib.new("md5"), and calls to
// names imported via `from ... import`.
func handleCall(call *sitter.Node, src []byte, localImports map[string]string, emit func(string, *sitter.Node)) {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return
	}
	switch fn.Type() {
	case "identifier":
		if canon, ok := localImports[fn.Content(src)]; ok {
			if id, ok := pyTargets[canon]; ok {
				emit(id, call)
			}
		}
	case "attribute":
		d := dotted(fn, src)
		switch {
		case suffixHas(d, "RSA.generate"):
			if bits, ok := firstIntArg(call, src); ok && bits < 2048 {
				emit(rules.RSASmall, call)
			}
		case suffixHas(d, "hashlib.new"):
			if name, ok := firstStringArg(call, src); ok {
				if id, ok := weakHashNames[strings.ToLower(name)]; ok {
					emit(id, call)
				}
			}
		}
	}
}

// collectFromImports builds name -> "module.name" for `from M import a, b as c`.
func collectFromImports(root *sitter.Node, src []byte) map[string]string {
	m := map[string]string{}
	walk(root, func(n *sitter.Node) {
		if n.Type() != "import_from_statement" {
			return
		}
		modNode := n.ChildByFieldName("module_name")
		if modNode == nil {
			return
		}
		module := modNode.Content(src)
		for i := 0; i < int(n.NamedChildCount()); i++ {
			c := n.NamedChild(i)
			if c.StartByte() <= modNode.EndByte() {
				continue // this is the module_name itself (or before it)
			}
			switch c.Type() {
			case "dotted_name", "identifier":
				name := c.Content(src)
				m[name] = module + "." + name
			case "aliased_import":
				orig := c.ChildByFieldName("name")
				alias := c.ChildByFieldName("alias")
				if orig != nil && alias != nil {
					m[alias.Content(src)] = module + "." + orig.Content(src)
				}
			}
		}
	})
	return m
}

// dotted renders an identifier/attribute chain as "a.b.c".
func dotted(n *sitter.Node, src []byte) string {
	switch n.Type() {
	case "identifier", "dotted_name":
		return n.Content(src)
	case "attribute":
		obj := n.ChildByFieldName("object")
		attr := n.ChildByFieldName("attribute")
		if obj == nil || attr == nil {
			return n.Content(src)
		}
		return dotted(obj, src) + "." + attr.Content(src)
	case "call":
		if fn := n.ChildByFieldName("function"); fn != nil {
			return dotted(fn, src)
		}
	}
	return n.Content(src)
}

func suffixLookup(d string) (string, bool) {
	if id, ok := pyTargets[d]; ok {
		return id, true
	}
	for k, id := range pyTargets {
		if suffixHas(d, k) {
			return id, true
		}
	}
	return "", false
}

// suffixHas reports whether dotted name d equals suffix or ends with ".suffix"
// (component boundary), so "Crypto.Cipher.DES.new" matches "DES.new".
func suffixHas(d, suffix string) bool {
	return d == suffix || strings.HasSuffix(d, "."+suffix)
}

func firstIntArg(call *sitter.Node, src []byte) (int, bool) {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return 0, false
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		c := args.NamedChild(i)
		if c.Type() == "integer" {
			n, err := strconv.Atoi(c.Content(src))
			if err == nil {
				return n, true
			}
		}
	}
	return 0, false
}

func firstStringArg(call *sitter.Node, src []byte) (string, bool) {
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return "", false
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		c := args.NamedChild(i)
		if c.Type() == "string" {
			return strings.Trim(c.Content(src), `"'`), true
		}
	}
	return "", false
}

func walk(n *sitter.Node, fn func(*sitter.Node)) {
	fn(n)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		walk(n.NamedChild(i), fn)
	}
}

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
