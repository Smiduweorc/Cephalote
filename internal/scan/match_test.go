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
		name, line, rule string
		want             bool
	}{
		{"a bare directive silences every rule", "x := md5.New() // cephalote:ignore", "weak-hash-md5", true},
		{"a listed id is silenced", "x := md5.New() // cephalote:ignore weak-hash-md5", "weak-hash-md5", true},
		{"an id that is not listed is not silenced", "x := md5.New() // cephalote:ignore weak-hash-sha1", "weak-hash-md5", false},
		{"no directive silences nothing", "x := md5.New()", "weak-hash-md5", false},
		{"all silences every rule", "x := md5.New() // cephalote:ignore all", "anything", true},
		{"a comma list honours every id", "x # cephalote:ignore weak-hash-md5,weak-cipher-des", "weak-cipher-des", true},
		{"a comma-and-space list honours every id", "x # cephalote:ignore weak-hash-md5, weak-cipher-des", "weak-cipher-des", true},
		{"a space list honours the first id", "x // cephalote:ignore weak-hash-md5 weak-cipher-des", "weak-hash-md5", true},
		{"a space list honours the second id", "x // cephalote:ignore weak-hash-md5 weak-cipher-des", "weak-cipher-des", true},
		{"a space list leaves unlisted ids alone", "x // cephalote:ignore weak-hash-md5 weak-cipher-des", "weak-hash-sha1", false},
		{"a reason alone is a bare directive", "x // cephalote:ignore legacy checksum", "weak-hash-md5", true},
		{"a reason alone silences scheme ids too", "x // cephalote:ignore legacy checksum", "scheme:md5", true},
		{"a reason after an id keeps the id list", "x // cephalote:ignore weak-hash-md5 legacy checksum", "weak-hash-md5", true},
		{"a reason after an id does not widen the list", "x // cephalote:ignore weak-hash-md5 legacy checksum", "weak-hash-sha1", false},
		{"a reason that names a rule id after it starts is still reason", "x // cephalote:ignore weak-hash-md5 legacy, not weak-hash-sha1", "weak-hash-sha1", false},
		{"a reason may follow all", "x // cephalote:ignore all generated code", "weak-hash-sha1", true},
		{"a scheme id is honoured", "x # cephalote:ignore scheme:md5", "scheme:md5", true},
		{"a scheme id does not silence the built-in rule", "x # cephalote:ignore scheme:md5", "weak-hash-md5", false},
		{"an unknown scheme id is an id that silences nothing else", "x # cephalote:ignore scheme:nope", "scheme:md5", false},
		{"a custom scheme id is honoured", "x # cephalote:ignore scheme:internal-xor", "scheme:internal-xor", true},
		{"a misspelled id reads as reason and silences the line", "x // cephalote:ignore weak-hash-md55", "weak-hash-md5", true},
		{"the directive must stand alone", "x // cephalote:ignored weak-hash-sha1", "weak-hash-md5", false},
		{"an upper-case id is not a rule id, so it starts the reason", "x // cephalote:ignore WEAK-HASH-MD5 weak-hash-sha1", "weak-hash-sha1", true},
		{"a block comment closer is not part of the id", "x /* cephalote:ignore weak-hash-md5*/", "weak-hash-md5", true},
		{"a block comment closer does not widen the list", "x /* cephalote:ignore weak-hash-md5 */", "weak-hash-sha1", false},
		{"an html comment closer is not part of the id", "<!-- cephalote:ignore weak-hash-md5-->", "weak-hash-md5", true},
		{"an html comment closer does not widen the list", "<!-- cephalote:ignore weak-hash-md5 -->", "weak-hash-sha1", false},
		{"code after a block comment is not reason or id", "x /* cephalote:ignore weak-hash-md5 */ weak-hash-sha1", "weak-hash-sha1", false},
		{"a tab separates ids", "x // cephalote:ignore\tweak-hash-md5\tweak-hash-sha1", "weak-hash-sha1", true},
		{"an sql comment carries the directive", "SELECT md5(x) -- cephalote:ignore scheme:md5", "scheme:md5", true},
		{"a lisp comment carries the directive", "(md5 x) ; cephalote:ignore scheme:md5", "scheme:md5", true},
		{"a basic comment carries the directive", "x = MD5(y) ' cephalote:ignore scheme:md5", "scheme:md5", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := suppressed(c.line, c.rule); got != c.want {
				t.Errorf("suppressed(%q, %q) = %v, want %v", c.line, c.rule, got, c.want)
			}
		})
	}
}
