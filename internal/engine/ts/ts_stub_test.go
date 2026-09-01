//go:build !treesitter

package ts

import "testing"

// The default build compiles the stub. scan.go relies on this exact contract
// to fall back to the tier-3 regex scan: if the stub ever claimed availability
// or support, tier-2 languages would be routed to a no-op analyzer and silently
// produce nothing.
func TestStubReportsUnavailable(t *testing.T) {
	if Available() {
		t.Error("Available() = true without the treesitter build tag")
	}
	for _, lang := range []string{
		"python", "javascript", "typescript", "java", "kotlin", "scala",
		"csharp", "ruby", "php", "rust", "swift", "c", "cpp", "go", "",
	} {
		if Supported(lang) {
			t.Errorf("Supported(%q) = true in the stub build", lang)
		}
	}
}

func TestStubAnalyzeIsANoOp(t *testing.T) {
	fs, err := Analyze("python", "a.py", []byte("import hashlib\nhashlib.md5(b'x')\n"))
	if err != nil {
		t.Errorf("Analyze() = error %v, want nil so the caller falls through", err)
	}
	if fs != nil {
		t.Errorf("Analyze() = %+v, want nil findings", fs)
	}
}
