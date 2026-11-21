package goast

import (
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/rules"
)

// FuzzAnalyze feeds arbitrary bytes to the Go analyzer: it must never panic,
// and whatever it reports must point at a real line under a known rule.
func FuzzAnalyze(f *testing.F) {
	for _, s := range []string{
		"",
		"package p\nimport \"crypto/md5\"\nvar _ = md5.New()\n",
		"package p\nimport foo \"crypto/sha1\"\nfunc f() { foo.Sum(nil) }\n",
		"package p\nimport \"crypto/rsa\"\nimport \"crypto/rand\"\nfunc f() { rsa.GenerateKey(rand.Reader, 1<<10) }\n",
		"package p\nimport \"crypto/rsa\"\nconst n = 512\nfunc f() { rsa.GenerateKey(nil, n*2) }\n",
		"package p\nfunc f() { (((((",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		fs, err := Analyze("f.go", src)
		if err != nil {
			return
		}
		if err := finding.Validate("f.go", src, fs); err != nil {
			t.Fatal(err)
		}
		for _, x := range fs {
			if _, ok := rules.Get(x.RuleID); !ok {
				t.Fatalf("unknown rule %q", x.RuleID)
			}
		}
	})
}
