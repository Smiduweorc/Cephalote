package lang

import (
	"strings"
	"testing"
)

func TestDetect_ByExtension(t *testing.T) {
	cases := []struct {
		path string
		name string
		tier Tier
	}{
		{"a/b/main.go", "go", TierGoAST},
		{"x.py", "python", TierTreeSitter},
		{"x.js", "javascript", TierTreeSitter},
		{"x.unknownext", "unknown", TierNone},
		{"Makefile", "unknown", TierNone},
	}
	for _, c := range cases {
		got := Detect(c.path, nil)
		if got.Name != c.name || got.Tier != c.tier {
			t.Errorf("Detect(%q) = %+v, want {%s %d}", c.path, got, c.name, c.tier)
		}
	}
}

func TestDetect_Shebang(t *testing.T) {
	cases := []struct {
		content string
		name    string
	}{
		{"#!/usr/bin/env python3\nprint(1)", "python"},
		{"#!/usr/bin/python\n", "python"},
		{"#!/usr/bin/node\n", "javascript"},
		{"no shebang here", "unknown"},
	}
	for _, c := range cases {
		got := Detect("script", []byte(c.content))
		if got.Name != c.name {
			t.Errorf("Detect(shebang %q) = %s, want %s", c.content, got.Name, c.name)
		}
	}
}

func TestDetect_ExtensionIsCaseInsensitive(t *testing.T) {
	for _, p := range []string{"X.PY", "X.Py", "Main.GO"} {
		if got := Detect(p, nil); got.Name == "unknown" {
			t.Errorf("Detect(%q) = unknown, want a language", p)
		}
	}
}

// An extension always wins over the file's contents: a .go file that happens
// to open with a shebang is still Go.
func TestDetect_ExtensionBeatsShebang(t *testing.T) {
	got := Detect("x.go", []byte("#!/usr/bin/env python3\n"))
	if got.Name != "go" || got.Tier != TierGoAST {
		t.Errorf("Detect = %+v, want go/TierGoAST", got)
	}
}

func TestDetectShebang_Forms(t *testing.T) {
	cases := []struct {
		content string
		name    string
	}{
		{"#!/usr/bin/env python3\n", "python"},
		{"#!/usr/bin/env python\n", "python"},
		{"#!/usr/bin/python3\n", "python"},
		{"#!/bin/ruby\n", "ruby"},
		{"#!/usr/bin/env node\n", "javascript"},
		{"#!/usr/bin/php\n", "php"},
		// Interpreter flags: the last token is not the interpreter, so the
		// first one has to be consulted.
		{"#!/usr/bin/python -u\n", "python"},
		// Not a shebang, or an interpreter we do not map.
		{"", "unknown"},
		{"#\n", "unknown"},
		{"#!\n", "unknown"},
		{"#!/bin/sh\n", "unknown"},
		{"#!/usr/bin/env perl\n", "unknown"},
		{" #!/usr/bin/env python3\n", "unknown"}, // must be the first bytes
	}
	for _, c := range cases {
		got := Detect("script", []byte(c.content))
		if got.Name != c.name {
			t.Errorf("Detect(%q) = %s, want %s", c.content, got.Name, c.name)
		}
	}
}

// Every extension must map to a language whose tier makes sense, and no entry
// may be blank — a typo here silently drops a whole file type.
func TestByExtTableIsWellFormed(t *testing.T) {
	for ext, l := range byExt {
		if ext == "" || ext[0] != '.' {
			t.Errorf("extension %q should start with a dot", ext)
		}
		if ext != strings.ToLower(ext) {
			t.Errorf("extension %q must be lowercase; Detect lowercases before lookup", ext)
		}
		if l.Name == "" || l.Name == "unknown" {
			t.Errorf("%s maps to %q", ext, l.Name)
		}
		if l.Tier == TierNone {
			t.Errorf("%s maps to TierNone; it would never be analyzed", ext)
		}
	}
	for interp, l := range shebangLang {
		if l.Name == "" || l.Tier == TierNone {
			t.Errorf("shebang %q maps to %+v", interp, l)
		}
	}
}
