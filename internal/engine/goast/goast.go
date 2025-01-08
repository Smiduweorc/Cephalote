// Package goast implements tier-1 detection: high-fidelity analysis of Go
// source using the standard library go/ast. It resolves imports to their full
// paths so a renamed import (e.g. `import foo "crypto/md5"`) is still caught,
// and inspects call arguments for value-dependent rules such as RSA key size.
package goast

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/rules"
)

// weakFuncs maps an import path to the functions within it that are inherently
// weak, and the rule each triggers.
var weakFuncs = map[string]map[string]string{
	"crypto/md5":  {"New": rules.MD5, "Sum": rules.MD5},
	"crypto/sha1": {"New": rules.SHA1, "Sum": rules.SHA1},
	"crypto/des": {
		"NewCipher":          rules.DES,
		"NewTripleDESCipher": rules.TripleDES,
	},
	"crypto/rc4":                   {"NewCipher": rules.RC4},
	"golang.org/x/crypto/md4":      {"New": rules.MD4, "Sum": rules.MD4},
	"golang.org/x/crypto/blowfish": {"NewCipher": rules.Blowfish, "NewSaltedCipher": rules.Blowfish},
}

// weakRandPaths are non-cryptographic PRNG packages; any call into them in a
// codebase that also touches crypto is suspicious. We flag all calls and let
// users filter by severity.
var weakRandPaths = map[string]bool{
	"math/rand":    true,
	"math/rand/v2": true,
}

// weakTLSVersions are crypto/tls version constants that are deprecated.
var weakTLSVersions = map[string]bool{
	"VersionSSL30": true,
	"VersionTLS10": true,
	"VersionTLS11": true,
}

// pkgFunc identifies a function by its import path and name.
type pkgFunc struct{ path, fn string }

// keyArg maps a key/MAC-consuming constructor to the argument index holding its
// secret. A literal at that position is a hardcoded key.
var keyArg = map[pkgFunc]int{
	{"crypto/aes", "NewCipher"}:                         0,
	{"crypto/des", "NewCipher"}:                         0,
	{"crypto/des", "NewTripleDESCipher"}:                0,
	{"crypto/rc4", "NewCipher"}:                         0,
	{"golang.org/x/crypto/blowfish", "NewCipher"}:       0,
	{"golang.org/x/crypto/blowfish", "NewSaltedCipher"}: 0,
	{"crypto/hmac", "New"}:                              1,
}

// ivConstructors are crypto/cipher mode constructors whose 2nd argument is the
// IV/nonce. A literal or inline zero buffer there is a static IV.
var ivConstructors = map[string]bool{
	"NewCBCEncrypter": true,
	"NewCBCDecrypter": true,
	"NewCTR":          true,
	"NewOFB":          true,
	"NewCFBEncrypter": true,
	"NewCFBDecrypter": true,
}

// Analyze parses Go source and returns high-confidence findings. A parse error
// is returned to the caller; partial ASTs are still walked when the parser
// recovers.
func Analyze(path string, src []byte) ([]finding.Finding, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, parser.ParseComments|parser.SkipObjectResolution)
	if file == nil {
		return nil, err
	}

	lines := splitLines(src)
	imports := importMap(file)

	var out []finding.Finding
	emit := func(ruleID string, pos token.Pos) {
		p := fset.Position(pos)
		out = append(out, mkFinding(ruleID, path, p, lines))
	}

	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		pkgPath := imports[pkgIdent.Name]
		if pkgPath == "" {
			return true
		}
		fn := sel.Sel.Name

		// A single call can trip more than one rule (e.g. des.NewCipher with a
		// literal key is both a weak cipher and a hardcoded key), so these are
		// independent checks with no early return.

		// Inherently weak constructors/hashes.
		if fns, ok := weakFuncs[pkgPath]; ok {
			if ruleID, ok := fns[fn]; ok {
				emit(ruleID, call.Pos())
			}
		}

		// Value-dependent: RSA key size.
		if pkgPath == "crypto/rsa" && (fn == "GenerateKey" || fn == "GenerateMultiPrimeKey") {
			if bits, ok := rsaKeyBits(call); ok && bits < 2048 {
				emit(rules.RSASmall, call.Pos())
			}
		}

		// Insecure randomness.
		if weakRandPaths[pkgPath] {
			emit(rules.WeakRand, call.Pos())
		}

		// Hardcoded key/MAC secret built from a source literal.
		if idx, ok := keyArg[pkgFunc{pkgPath, fn}]; ok {
			if idx < len(call.Args) && isByteSliceLiteral(call.Args[idx]) {
				emit(rules.HardcodedKey, call.Args[idx].Pos())
			}
		}

		// Static or zero IV/nonce passed inline to a cipher-mode constructor.
		if pkgPath == "crypto/cipher" && ivConstructors[fn] && len(call.Args) >= 2 {
			iv := call.Args[1]
			if isByteSliceLiteral(iv) || isInlineMakeByteSlice(iv) {
				emit(rules.StaticIV, iv.Pos())
			}
		}
		return true
	})

	// Deprecated TLS versions referenced as values, e.g.
	// `tls.Config{MinVersion: tls.VersionTLS10}`.
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkgIdent, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		if imports[pkgIdent.Name] == "crypto/tls" && weakTLSVersions[sel.Sel.Name] {
			p := fset.Position(sel.Pos())
			out = append(out, mkFinding(rules.WeakTLS, path, p, lines))
		}
		return true
	})

	return out, err
}

// importMap returns local-name -> import-path for a file. The local name is
// the explicit alias when present, otherwise the final path segment (which
// matches the package name for all packages we care about here).
func importMap(file *ast.File) map[string]string {
	m := make(map[string]string)
	for _, imp := range file.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			continue
		}
		name := p
		if i := strings.LastIndex(p, "/"); i >= 0 {
			name = p[i+1:]
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				continue
			}
			name = imp.Name.Name
		}
		m[name] = p
	}
	return m
}

// rsaKeyBits extracts the integer key-size argument from an rsa.GenerateKey
// call (the 2nd argument). It only resolves untyped integer literals; computed
// sizes are left to deeper analysis and not flagged here to avoid noise.
func rsaKeyBits(call *ast.CallExpr) (int, bool) {
	if len(call.Args) < 2 {
		return 0, false
	}
	lit, ok := call.Args[1].(*ast.BasicLit)
	if !ok || lit.Kind != token.INT {
		return 0, false
	}
	n, err := strconv.Atoi(lit.Value)
	if err != nil {
		return 0, false
	}
	return n, true
}

func mkFinding(ruleID, path string, p token.Position, lines []string) finding.Finding {
	r := rules.MustGet(ruleID)
	f := finding.Finding{
		RuleID:      r.ID,
		Title:       r.Title,
		Description: r.Description,
		Severity:    r.Severity,
		Confidence:  finding.High,
		Remediation: r.Remediation,
		File:        path,
		Line:        p.Line,
		Column:      p.Column,
	}
	if p.Line >= 1 && p.Line <= len(lines) {
		f.Snippet = strings.TrimSpace(lines[p.Line-1])
	}
	return f
}

// isByteSliceLiteral reports whether e is a compile-time-constant secret: a
// string literal, []byte("..."), or []byte{...}.
func isByteSliceLiteral(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.CompositeLit:
		return isByteSliceType(v.Type)
	case *ast.CallExpr:
		// Conversion such as []byte("secret") or []byte(`secret`).
		if isByteSliceType(v.Fun) && len(v.Args) == 1 {
			if lit, ok := v.Args[0].(*ast.BasicLit); ok {
				return lit.Kind == token.STRING
			}
		}
	}
	return false
}

// isInlineMakeByteSlice reports whether e is an inline make([]byte, ...): an
// IV/nonce buffer that is never randomized (all zeros).
func isInlineMakeByteSlice(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	id, ok := call.Fun.(*ast.Ident)
	if !ok || id.Name != "make" || len(call.Args) < 1 {
		return false
	}
	return isByteSliceType(call.Args[0])
}

// isByteSliceType reports whether e is the type expression []byte (a slice, not
// a fixed-size array).
func isByteSliceType(e ast.Expr) bool {
	at, ok := e.(*ast.ArrayType)
	if !ok || at.Len != nil {
		return false
	}
	id, ok := at.Elt.(*ast.Ident)
	return ok && id.Name == "byte"
}

func splitLines(src []byte) []string {
	return strings.Split(string(src), "\n")
}
