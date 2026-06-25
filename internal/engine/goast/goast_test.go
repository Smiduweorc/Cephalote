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
