package scheme

import (
	"strings"
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
)

func names(ss []Scheme) map[string]bool {
	m := map[string]bool{}
	for _, s := range ss {
		m[s.Name] = true
	}
	return m
}

func TestResolve_NamesAndAliases(t *testing.T) {
	cases := []struct {
		token string
		want  string
	}{
		{"sha256", "sha256"},
		{"sha-256", "sha256"}, // alias via the scheme's own matcher
		{"des3", "3des"},
		{"arcfour", "rc4"},
		{"AES", "aes"},
	}
	for _, c := range cases {
		got, err := Resolve([]string{c.token})
		if err != nil {
			t.Errorf("Resolve(%q) error: %v", c.token, err)
			continue
		}
		if !names(got)[c.want] {
			t.Errorf("Resolve(%q) = %v, want to include %s", c.token, names(got), c.want)
		}
	}
}

func TestResolve_ClassSelectors(t *testing.T) {
	weak, err := Resolve([]string{"weak"})
	if err != nil {
		t.Fatal(err)
	}
	n := names(weak)
	// "weak" must include both broken and weak classes...
	for _, want := range []string{"md5", "des", "rc4", "sha1", "3des"} {
		if !n[want] {
			t.Errorf("--scheme weak missing %s", want)
		}
	}
	// ...but never strong algorithms.
	for _, notWant := range []string{"sha256", "aes", "ed25519"} {
		if n[notWant] {
			t.Errorf("--scheme weak should not include strong %s", notWant)
		}
	}
}

func TestResolve_Unknown(t *testing.T) {
	if _, err := Resolve([]string{"sha999"}); err == nil {
		t.Error("expected error for unknown scheme")
	}
}

func TestScan_FindsRequestedScheme(t *testing.T) {
	src := []byte("import hashlib\nh = hashlib.sha256()\nlabel = \"SHA-256\"\nunrelated\n")
	want, err := Resolve([]string{"sha256"})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Scan("x.py", src, want)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.RuleID != "scheme:sha256" {
			t.Errorf("unexpected rule id %s", f.RuleID)
		}
		if f.Severity != finding.Info || f.Confidence != finding.Low {
			t.Errorf("sha256 should be info/low, got %s/%s", f.Severity, f.Confidence)
		}
	}
}

func TestScan_DoesNotMatchUnrelatedWords(t *testing.T) {
	// "ideas" must not match, and "des" must not fire inside "described".
	want, _ := Resolve([]string{"des"})
	fs, _ := Scan("x.txt", []byte("this described nothing; ideas only\n"), want)
	if len(fs) != 0 {
		t.Errorf("false positive: %+v", fs)
	}
}

func TestSeverityByClass(t *testing.T) {
	cases := map[Class]finding.Severity{
		Broken:     finding.HighSev,
		Weak:       finding.Medium,
		Legacy:     finding.LowSev,
		Strong:     finding.Info,
		Contextual: finding.Info,
	}
	for class, want := range cases {
		got := Scheme{Class: class}.Severity()
		if got != want {
			t.Errorf("class %s severity = %s, want %s", class, got, want)
		}
	}
}

func TestNew_CustomScheme(t *testing.T) {
	s, err := New("internal-xor", "Home-grown XOR", Broken, "note", "Use AEAD.", `(?i)\bxor_encrypt\b`)
	if err != nil {
		t.Fatal(err)
	}
	if s.Name != "internal-xor" || s.Title != "Home-grown XOR" || s.Class != Broken {
		t.Errorf("New() = %+v", s)
	}
	// A custom remediation wins over the class-based fallback.
	if got := s.Remediation(); got != "Use AEAD." {
		t.Errorf("Remediation() = %q, want the custom text", got)
	}
	fs, err := Scan("a.go", []byte("x := xor_encrypt(p)\n"), []Scheme{s})
	if err != nil {
		t.Fatal(err)
	}
	// Scheme findings carry a "scheme:" prefix so they never collide with a
	// tier-1/2 rule ID in config or in SARIF.
	if len(fs) != 1 || fs[0].RuleID != "scheme:internal-xor" {
		t.Errorf("custom scheme findings = %+v", fs)
	}
}

func TestNew_Defaults(t *testing.T) {
	// An empty title falls back to the name, and an empty class to Weak, so a
	// minimal config entry still produces a usable scheme.
	s, err := New("thing", "", "", "", "", `\bthing\b`)
	if err != nil {
		t.Fatal(err)
	}
	if s.Title != "thing" {
		t.Errorf("Title = %q, want it to default to the name", s.Title)
	}
	if s.Class != Weak {
		t.Errorf("Class = %q, want it to default to Weak", s.Class)
	}
}

func TestNew_InvalidPattern(t *testing.T) {
	_, err := New("bad", "Bad", Broken, "", "", `([unclosed`)
	if err == nil {
		t.Fatal("New() with an invalid regex returned no error")
	}
	if !strings.Contains(err.Error(), "bad") {
		t.Errorf("error = %q, want it to name the offending scheme", err)
	}
}

func TestRemediation(t *testing.T) {
	byName := map[string]bool{}
	for _, s := range All() {
		byName[s.Name] = true
		got := s.Remediation()
		switch s.Class {
		case Broken, Weak, Legacy:
			if got == "" {
				t.Errorf("%s (%s) has no remediation", s.Name, s.Class)
			}
		case Strong:
			if got != "" {
				t.Errorf("%s is strong but offers remediation %q", s.Name, got)
			}
		}
	}
	// Named guidance is preferred over the generic class-based text.
	for _, s := range All() {
		if s.Name == "md5" && !strings.Contains(s.Remediation(), "SHA-256") {
			t.Errorf("md5 remediation = %q, want the specific guidance", s.Remediation())
		}
	}
}

func TestAllAndWeakSchemes(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("All() is empty")
	}
	names := map[string]bool{}
	for _, s := range all {
		if s.Name == "" || s.Title == "" {
			t.Errorf("catalog entry %+v is missing a name or title", s)
		}
		if names[s.Name] {
			t.Errorf("duplicate scheme name %q", s.Name)
		}
		names[s.Name] = true
	}

	weak := WeakSchemes()
	if len(weak) == 0 || len(weak) >= len(all) {
		t.Fatalf("WeakSchemes() = %d of %d, want a non-empty proper subset", len(weak), len(all))
	}
	for _, s := range weak {
		if s.Class != Broken && s.Class != Weak {
			t.Errorf("WeakSchemes() includes %s of class %s", s.Name, s.Class)
		}
	}
}

// WeakSchemes backs the default tier-3 scan; handing callers the cached slice
// would let one scan's custom schemes leak into the next.
func TestWeakSchemesIsNotAliasedByCallers(t *testing.T) {
	first := WeakSchemes()
	n := len(first)
	grown := append(first, Scheme{Name: "injected"}) //nolint:gocritic // deliberate
	_ = grown
	if got := len(WeakSchemes()); got != n {
		t.Errorf("WeakSchemes() = %d after a caller appended, want %d", got, n)
	}
	if WeakSchemes()[n-1].Name == "injected" {
		t.Error("a caller's append mutated the cached weak set")
	}
}

func TestResolve_EmptyAndBlankTokens(t *testing.T) {
	got, err := Resolve([]string{"", "  "})
	if err != nil {
		t.Fatalf("blank tokens should be ignored, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Resolve(blank) = %d schemes, want 0", len(got))
	}
	if got, err := Resolve(nil); err != nil || len(got) != 0 {
		t.Errorf("Resolve(nil) = %v, %v", got, err)
	}
}

func TestResolve_Deduplicates(t *testing.T) {
	// The same scheme reached by name, by alias, and by class selector must
	// appear once.
	got, err := Resolve([]string{"md5", "md5", "broken"})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, s := range got {
		seen[s.Name]++
	}
	for name, n := range seen {
		if n != 1 {
			t.Errorf("scheme %s appears %d times", name, n)
		}
	}
}

func TestResolve_CaseAndWhitespaceInsensitive(t *testing.T) {
	got, err := Resolve([]string{" MD5 "})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "md5" {
		t.Errorf("Resolve(\" MD5 \") = %+v, want md5", got)
	}
}

func TestScan_MultipleSchemesPerLine(t *testing.T) {
	want, err := Resolve([]string{"md5", "des"})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Scan("a.txt", []byte("we use md5 and des together\n"), want)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want one per scheme: %+v", len(fs), fs)
	}
	for _, f := range fs {
		if f.Line != 1 {
			t.Errorf("%s line = %d, want 1", f.RuleID, f.Line)
		}
		if f.Confidence != finding.Low {
			t.Errorf("%s confidence = %s, want low for a regex match", f.RuleID, f.Confidence)
		}
	}
}

func TestScan_ReportsEveryMatchingLine(t *testing.T) {
	want, _ := Resolve([]string{"md5"})
	fs, err := Scan("a.txt", []byte("md5 one\nclean\nmd5 three\n"), want)
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2: %+v", len(fs), fs)
	}
	if fs[0].Line != 1 || fs[1].Line != 3 {
		t.Errorf("lines = %d, %d; want 1, 3", fs[0].Line, fs[1].Line)
	}
}

func TestScan_EmptyInput(t *testing.T) {
	want, _ := Resolve([]string{"md5"})
	for _, src := range [][]byte{nil, {}, []byte("\n\n")} {
		fs, err := Scan("a.txt", src, want)
		if err != nil || len(fs) != 0 {
			t.Errorf("Scan(%q) = %+v, %v; want no findings", src, fs, err)
		}
	}
}
