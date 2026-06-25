package scheme

import (
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
