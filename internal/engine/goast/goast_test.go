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
		// A computed or named size is not resolved; flagging it would be a
		// guess, so these are deliberately silent.
		{"named constant", "rsa.GenerateKey(rand.Reader, keySize)", false},
		{"expression", "rsa.GenerateKey(rand.Reader, 512*2)", false},
		// Malformed calls must not panic or misreport.
		{"too few args", "rsa.GenerateKey(rand.Reader)", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := "package x\n\nimport (\n\t\"crypto/rand\"\n\t\"crypto/rsa\"\n)\n\nconst keySize = 1024\n\nfunc f() { _, _ = " + c.expr + " }\n"
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
