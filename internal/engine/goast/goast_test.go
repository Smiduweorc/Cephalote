package goast

import (
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/rules"
)

func ruleIDs(fs []finding.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.RuleID]++
	}
	return m
}

func TestAnalyze_WeakConstructs(t *testing.T) {
	src := `package x

import (
	"crypto/md5"
	"crypto/des"
	"crypto/rsa"
	"crypto/rand"
	"crypto/tls"
	mrand "math/rand"
)

func f() {
	_ = md5.New()
	_, _ = des.NewCipher(nil)
	_, _ = des.NewTripleDESCipher(nil)
	_, _ = rsa.GenerateKey(rand.Reader, 1024)
	_, _ = rsa.GenerateKey(rand.Reader, 4096)
	_ = mrand.Intn(3)
	_ = tls.Config{MinVersion: tls.VersionTLS11}
}
`
	fs, err := Analyze("x.go", []byte(src))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	got := ruleIDs(fs)
	want := map[string]int{
		rules.MD5:       1,
		rules.DES:       1,
		rules.TripleDES: 1,
		rules.RSASmall:  1, // only the 1024-bit key, not the 4096-bit one
		rules.WeakRand:  1,
		rules.WeakTLS:   1,
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("rule %s: got %d, want %d (all: %v)", id, got[id], n, got)
		}
	}
	if len(fs) != 6 {
		t.Errorf("total findings = %d, want 6: %v", len(fs), got)
	}
	for _, f := range fs {
		if f.Confidence != finding.High {
			t.Errorf("%s confidence = %s, want high", f.RuleID, f.Confidence)
		}
	}
}

func TestAnalyze_RenamedImportStillCaught(t *testing.T) {
	src := `package x
import secret "crypto/md5"
func f() { _ = secret.New() }
`
	fs, err := Analyze("x.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if ruleIDs(fs)[rules.MD5] != 1 {
		t.Errorf("renamed md5 import not caught: %v", fs)
	}
}

func TestAnalyze_NoFalsePositiveOnStrongCrypto(t *testing.T) {
	src := `package x
import (
	"crypto/sha256"
	"crypto/aes"
)
func f() {
	_ = sha256.New()
	_, _ = aes.NewCipher(nil)
}
`
	fs, err := Analyze("x.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("expected no findings, got %v", fs)
	}
}

func TestAnalyze_HardcodedKey(t *testing.T) {
	src := `package x
import (
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
)
func f(realKey []byte) {
	_, _ = aes.NewCipher([]byte("hardcoded-16byte"))   // flag
	_, _ = aes.NewCipher([]byte{1, 2, 3, 4})           // flag
	_, _ = aes.NewCipher(realKey)                      // OK: variable
	_ = hmac.New(sha256.New, []byte("mac-secret"))     // flag (arg 1)
}
`
	fs, err := Analyze("x.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleIDs(fs)[rules.HardcodedKey]; got != 3 {
		t.Errorf("hardcoded-key count = %d, want 3: %v", got, ruleIDs(fs))
	}
}

func TestAnalyze_StaticIV(t *testing.T) {
	src := `package x
import "crypto/cipher"
func f(block cipher.Block, goodIV []byte) {
	_ = cipher.NewCBCEncrypter(block, []byte("0123456789abcdef")) // flag: literal
	_ = cipher.NewCTR(block, make([]byte, 16))                    // flag: zero IV
	_ = cipher.NewCBCEncrypter(block, goodIV)                     // OK: variable
}
`
	fs, err := Analyze("x.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if got := ruleIDs(fs)[rules.StaticIV]; got != 2 {
		t.Errorf("static-iv count = %d, want 2: %v", got, ruleIDs(fs))
	}
}

func TestAnalyze_WeakCipherAndHardcodedKeyOnSameCall(t *testing.T) {
	// des.NewCipher with a literal key must trip BOTH rules.
	src := `package x
import "crypto/des"
func f() { _, _ = des.NewCipher([]byte("8bytekey")) }
`
	fs, err := Analyze("x.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	ids := ruleIDs(fs)
	if ids[rules.DES] != 1 || ids[rules.HardcodedKey] != 1 {
		t.Errorf("want DES=1 and HardcodedKey=1, got %v", ids)
	}
}

func TestAnalyze_LocalIdentNotConfusedWithPackage(t *testing.T) {
	// A local variable named "md5" must not trigger the import-based rule.
	src := `package x
func f() {
	md5 := struct{ New func() int }{}
	_ = md5.New()
}
`
	fs, err := Analyze("x.go", []byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("local ident md5 should not match import rule, got %v", fs)
	}
}

func TestAnalyze_RSAKeySizes(t *testing.T) {
	cases := []struct {
		name    string
		expr    string
		flagged bool
	}{
		{"512", "rsa.GenerateKey(rand.Reader, 512)", true},
		{"1024", "rsa.GenerateKey(rand.Reader, 1024)", true},
		{"2047", "rsa.GenerateKey(rand.Reader, 2047)", true},
		{"2048 is the boundary and is allowed", "rsa.GenerateKey(rand.Reader, 2048)", false},
		{"4096", "rsa.GenerateKey(rand.Reader, 4096)", false},
		// Named constants and constant expressions resolve to their value.
		{"named constant", "rsa.GenerateKey(rand.Reader, keySize)", true},
		{"strong named constant", "rsa.GenerateKey(rand.Reader, strongSize)", false},
		{"expression", "rsa.GenerateKey(rand.Reader, 512*2)", true},
		{"strong expression", "rsa.GenerateKey(rand.Reader, 1<<12)", false},
		{"constant built from constants", "rsa.GenerateKey(rand.Reader, derived)", true},
		{"typed constant", "rsa.GenerateKey(rand.Reader, typedSize)", true},
		{"hex literal", "rsa.GenerateKey(rand.Reader, 0x400)", true},
		// The size is the third argument here; nprimes is not a key size.
		{"multi-prime weak", "rsa.GenerateMultiPrimeKey(rand.Reader, 3, keySize)", true},
		{"multi-prime strong", "rsa.GenerateMultiPrimeKey(rand.Reader, 3, 4096)", false},
		// A size only known at run time is not guessed at.
		{"variable", "rsa.GenerateKey(rand.Reader, runtimeSize)", false},
		// Malformed calls must not panic or misreport.
		{"too few args", "rsa.GenerateKey(rand.Reader)", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package x\n\nimport (\n\t\"crypto/rand\"\n\t\"crypto/rsa\"\n)\n\nconst keySize = 1024\nconst strongSize = 4096\nconst derived = keySize / 2\nconst typedSize int = 768\n\nvar runtimeSize = 1024\n\nfunc f() { _, _ = " + c.expr + " }\n"
			fs, err := Analyze("a.go", []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			got := ruleIDs(fs)[rules.RSASmall]
			if (got > 0) != c.flagged {
				t.Errorf("%s: rsa findings = %d, want flagged=%v", c.expr, got, c.flagged)
			}
		})
	}
}

func TestAnalyze_RSAKeySizeScoping(t *testing.T) {
	cases := []struct {
		name    string
		src     string
		flagged bool
	}{
		{"local constant", "func f() {\n\tconst bits = 1024\n\t_, _ = rsa.GenerateKey(rand.Reader, bits)\n}\n", true},
		{"local constant shadows a weak one", "const bits = 1024\n\nfunc f() {\n\tconst bits = 4096\n\t_, _ = rsa.GenerateKey(rand.Reader, bits)\n}\n", false},
		{"local variable shadows a weak constant", "const bits = 1024\n\nfunc f() {\n\tbits := 4096\n\t_, _ = rsa.GenerateKey(rand.Reader, bits)\n}\n", false},
		{"iota", "const (\n\tsmall = (iota + 1) * 1024\n\tlarge\n)\n\nfunc f() { _, _ = rsa.GenerateKey(rand.Reader, small) }\n", true},
		{"parameter", "func f(bits int) { _, _ = rsa.GenerateKey(rand.Reader, bits) }\n", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package x\n\nimport (\n\t\"crypto/rand\"\n\t\"crypto/rsa\"\n)\n\n" + c.src
			fs, err := Analyze("a.go", []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if got := ruleIDs(fs)[rules.RSASmall] > 0; got != c.flagged {
				t.Errorf("flagged = %v, want %v", got, c.flagged)
			}
		})
	}
}

func TestAnalyze_VersionedImportPath(t *testing.T) {
	cases := []struct {
		name    string
		imports string
		call    string
		flagged bool
	}{
		// math/rand/v2 declares package rand: the name is not "v2".
		{"math/rand/v2", `"math/rand/v2"`, "rand.IntN(3)", true},
		{"math/rand/v2 aliased", `mr "math/rand/v2"`, "mr.IntN(3)", true},
		{"math/rand", `"math/rand"`, "rand.Intn(3)", true},
		{"crypto/rand is not weak", `"crypto/rand"`, "rand.Int(nil, nil)", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package x\n\nimport " + c.imports + "\n\nfunc f() { _, _ = " + c.call + ", 0 }\n"
			fs, err := Analyze("a.go", []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if got := ruleIDs(fs)[rules.WeakRand] > 0; got != c.flagged {
				t.Errorf("flagged = %v, want %v (findings: %v)", got, c.flagged, ruleIDs(fs))
			}
		})
	}
}

func TestImportName(t *testing.T) {
	for path, want := range map[string]string{
		"crypto/md5":          "md5",
		"math/rand/v2":        "rand",
		"gopkg.in/yaml.v3":    "yaml",
		"example.com/mod/v10": "mod",
		"v2":                  "v2",
		"example.com/vx":      "vx",
	} {
		if got := importName(path); got != want {
			t.Errorf("importName(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestAnalyze_ImportForms(t *testing.T) {
	cases := []struct {
		name    string
		imports string
		call    string
		flagged bool
	}{
		{"plain", `"crypto/md5"`, "md5.New()", true},
		{"aliased", `weak "crypto/md5"`, "weak.New()", true},
		// A blank import binds no name, so a later md5.New() refers to
		// something else entirely.
		{"blank import", `_ "crypto/md5"`, "md5.New()", false},
		// A dot import puts New in scope unqualified; the analyzer does not
		// resolve that, and must not mistake an unrelated md5.New() for it.
		{"dot import", `. "crypto/md5"`, "md5.New()", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package x\n\nimport " + c.imports + "\n\nvar md5 struct{ New func() any }\n\nfunc f() { _ = " + c.call + " }\n"
			if c.name == "plain" || c.name == "aliased" {
				src = "package x\n\nimport " + c.imports + "\n\nfunc f() { _ = " + c.call + " }\n"
			}
			fs, err := Analyze("a.go", []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if got := ruleIDs(fs)[rules.MD5] > 0; got != c.flagged {
				t.Errorf("%s: flagged = %v, want %v (findings: %v)", c.name, got, c.flagged, ruleIDs(fs))
			}
		})
	}
}

func TestAnalyze_HardcodedKeyForms(t *testing.T) {
	cases := []struct {
		name    string
		arg     string
		flagged bool
	}{
		{"string literal", `"0123456789abcdef"`, true},
		{"byte slice conversion", `[]byte("0123456789abcdef")`, true},
		{"raw string conversion", "[]byte(`0123456789abcdef`)", true},
		{"byte slice composite", `[]byte{1, 2, 3, 4}`, true},
		// Not compile-time constants: these are the correct way to do it.
		{"variable", `key`, false},
		{"function call", `loadKey()`, false},
		// A fixed-size array type is not a []byte literal.
		{"array literal", `[4]byte{1, 2, 3, 4}`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package x\n\nimport \"crypto/aes\"\n\nvar key []byte\n\nfunc loadKey() []byte { return nil }\n\nfunc f() { _, _ = aes.NewCipher(" + c.arg + ") }\n"
			fs, err := Analyze("a.go", []byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if got := ruleIDs(fs)[rules.HardcodedKey] > 0; got != c.flagged {
				t.Errorf("%s: flagged = %v, want %v (findings: %v)", c.arg, got, c.flagged, ruleIDs(fs))
			}
		})
	}
}

// A file that does not parse must return an error rather than pretending the
// tree is clean.
func TestAnalyze_ParseError(t *testing.T) {
	fs, err := Analyze("a.go", []byte("package x\n\nfunc f( {\n"))
	if err == nil && len(fs) == 0 {
		t.Error("a syntactically invalid file reported neither an error nor findings")
	}
}

func TestAnalyze_EmptyAndCommentOnlyFiles(t *testing.T) {
	for _, src := range []string{
		"package x\n",
		"package x\n\n// md5 and des are mentioned only in a comment\n",
	} {
		fs, err := Analyze("a.go", []byte(src))
		if err != nil {
			t.Fatalf("Analyze(%q): %v", src, err)
		}
		if len(fs) != 0 {
			t.Errorf("Analyze(%q) = %+v, want no findings", src, fs)
		}
	}
}
