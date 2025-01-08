package scan

import "testing"

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, rel, base string
		want               bool
	}{
		{"*.min.js", "a/b/app.min.js", "app.min.js", true},
		{"*.min.js", "a/b/app.js", "app.js", false},
		{"testdata/**", "testdata/x/y.go", "y.go", true},
		{"testdata/**", "src/testdata/y.go", "y.go", false},
		{"**/generated.go", "a/b/generated.go", "generated.go", true},
		{"build", "build", "build", true},
	}
	for _, c := range cases {
		gs, err := compileGlobs([]string{c.pattern})
		if err != nil {
			t.Fatalf("compile %q: %v", c.pattern, err)
		}
		got := gs[0].match(c.rel, c.base)
		if got != c.want {
			t.Errorf("glob %q vs rel=%q base=%q = %v, want %v", c.pattern, c.rel, c.base, got, c.want)
		}
	}
}

func TestSuppressed(t *testing.T) {
	cases := []struct {
		line, rule string
		want       bool
	}{
		{"x := md5.New() // cephalote:ignore", "weak-hash-md5", true},
		{"x := md5.New() // cephalote:ignore weak-hash-md5", "weak-hash-md5", true},
		{"x := md5.New() // cephalote:ignore weak-hash-sha1", "weak-hash-md5", false},
		{"x := md5.New() # cephalote:ignore weak-hash-md5,weak-cipher-des", "weak-cipher-des", true},
		{"x := md5.New()", "weak-hash-md5", false},
		{"x := md5.New() // cephalote:ignore all", "anything", true},
	}
	for _, c := range cases {
		if got := suppressed(c.line, c.rule); got != c.want {
			t.Errorf("suppressed(%q, %q) = %v, want %v", c.line, c.rule, got, c.want)
		}
	}
}
