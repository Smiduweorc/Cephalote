package scheme

import (
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
)

// FuzzScan runs the whole scheme catalog over arbitrary text.
func FuzzScan(f *testing.F) {
	for _, s := range []string{"", "x := xor_encrypt(p)\n", "rot13(s)\r\nbase64 'encryption'\n", "\xff\xfe\n\n\n"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		fs, err := Scan("f.txt", src, All())
		if err != nil {
			return
		}
		if err := finding.Validate("f.txt", src, fs); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzNew compiles user-supplied scheme patterns from config: a bad pattern
// must be refused with an error, never a panic.
func FuzzNew(f *testing.F) {
	for _, p := range []string{`xor_\w+`, `(`, `(?i)rot\d+`, `a{1000000}`, ""} {
		f.Add(p)
	}
	f.Fuzz(func(t *testing.T, pattern string) {
		s, err := New("fuzz", "Fuzz", Weak, "", "", pattern)
		if err != nil {
			return
		}
		_, _ = Scan("f.txt", []byte(pattern+"\n"+pattern), []Scheme{s})
	})
}
