//go:build treesitter

package ts

import (
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/rules"
)

func ids(fs []finding.Finding) map[string]int {
	m := map[string]int{}
	for _, f := range fs {
		m[f.RuleID]++
	}
	return m
}

func TestAnalyzePython(t *testing.T) {
	src := []byte(`import hashlib, ssl
from hashlib import md5 as digest
from Crypto.Cipher import DES
from Crypto.PublicKey import RSA
import random

a = hashlib.md5(b"x")
b = digest(b"y")
c = DES.new(key, DES.MODE_ECB)
weak = RSA.generate(1024)
strong = RSA.generate(4096)
p = ssl.PROTOCOL_TLSv1
tok = random.random()
n = hashlib.new("md5")
ok = hashlib.sha256(b"z")
`)
	fs, err := Analyze("python", "app.py", src)
	if err != nil {
		t.Fatal(err)
	}
	got := ids(fs)
	want := map[string]int{
		rules.MD5:      3, // hashlib.md5, digest alias, hashlib.new("md5")
		rules.DES:      1,
		rules.RSASmall: 1, // 1024 only, not 4096
		rules.WeakTLS:  1,
		rules.WeakRand: 1,
	}
	for id, n := range want {
		if got[id] != n {
			t.Errorf("rule %s = %d, want %d (all: %v)", id, got[id], n, got)
		}
	}
	for _, f := range fs {
		if f.Confidence != finding.High {
			t.Errorf("%s confidence = %s, want high", f.RuleID, f.Confidence)
		}
	}
}

func TestAnalyzePython_NoFalsePositiveOnStrong(t *testing.T) {
	fs, err := Analyze("python", "ok.py", []byte("import hashlib\nh = hashlib.sha256(b'x')\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Errorf("strong crypto should not flag: %v", fs)
	}
}
