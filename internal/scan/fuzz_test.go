package scan

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// FuzzGlob checks that any valid-UTF-8 glob from config or the command line
// becomes a regexp that compiles, and that a glob with no wildcards matches
// exactly itself.
func FuzzGlob(f *testing.F) {
	for _, g := range []string{"*.go", "vendor/**", "**/testdata/*", "a?c", "[x]", "(a|b)", `\`, "{a,b}"} {
		f.Add(g)
	}
	f.Fuzz(func(t *testing.T, glob string) {
		if !utf8.ValidString(glob) {
			return
		}
		re, err := regexp.Compile(globToRegex(glob))
		if err != nil {
			t.Fatalf("glob %q: %v", glob, err)
		}
		if !strings.ContainsAny(glob, "*?") && !re.MatchString(glob) {
			t.Fatalf("literal glob %q does not match itself", glob)
		}
	})
}

// FuzzSuppressed: the directive parser sees every scanned line.
func FuzzSuppressed(f *testing.F) {
	for _, l := range []string{"x // cephalote:ignore", "x # cephalote:ignore CEPH001 reason */", "<!-- cephalote:ignore all -->", "cephalote:ignore scheme:x,y"} {
		f.Add(l, "CEPH001")
	}
	f.Fuzz(func(t *testing.T, line, id string) {
		got := suppressed(line, id)
		if !strings.Contains(line, "cephalote:ignore") && got {
			t.Fatalf("suppressed without a directive: %q", line)
		}
	})
}
