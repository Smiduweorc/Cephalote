package lang

import "testing"

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
