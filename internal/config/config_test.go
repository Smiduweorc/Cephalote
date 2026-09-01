package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cephalote.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_Full(t *testing.T) {
	p := write(t, `
min_confidence: high
include_unknown: true
exclude:
  - "testdata/**"
rules:
  disable:
    - weak-hash-sha1
  severity:
    weak-hash-md5: low
custom_schemes:
  - id: internal-xor
    title: Home-grown XOR
    class: broken
    pattern: "(?i)\\bxor_encrypt\\b"
    remediation: Use AEAD.
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.HasMinConf || c.MinConfidence != finding.High {
		t.Errorf("min_confidence not parsed: %+v", c)
	}
	if !c.IncludeUnknown {
		t.Error("include_unknown should be true")
	}
	if len(c.Exclude) != 1 || c.Exclude[0] != "testdata/**" {
		t.Errorf("exclude = %v", c.Exclude)
	}
	if !c.Disabled["weak-hash-sha1"] {
		t.Error("sha1 should be disabled")
	}
	if c.Severity["weak-hash-md5"] != finding.LowSev {
		t.Errorf("severity override = %v", c.Severity)
	}
	if len(c.CustomSchemes) != 1 || c.CustomSchemes[0].Name != "internal-xor" {
		t.Errorf("custom schemes = %+v", c.CustomSchemes)
	}
}

func TestLoad_InvalidSeverity(t *testing.T) {
	p := write(t, "rules:\n  severity:\n    weak-hash-md5: bogus\n")
	if _, err := Load(p); err == nil {
		t.Error("expected error for invalid severity")
	}
}

func TestLoad_CustomSchemeNeedsPattern(t *testing.T) {
	p := write(t, "custom_schemes:\n  - id: x\n")
	if _, err := Load(p); err == nil {
		t.Error("expected error for custom scheme missing pattern")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("Load(missing) returned no error")
	}
}

func TestLoad_MalformedYAML(t *testing.T) {
	_, err := Load(write(t, "exclude: [unclosed\n"))
	if err == nil {
		t.Fatal("Load(malformed) returned no error")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("error = %q, want it to say what failed", err)
	}
}

// An empty file is valid: it means "no overrides", not an error.
func TestLoad_EmptyFile(t *testing.T) {
	c, err := Load(write(t, ""))
	if err != nil {
		t.Fatalf("empty config should load: %v", err)
	}
	if c.HasMinConf {
		t.Error("HasMinConf should be false when min_confidence is unset")
	}
	if c.IncludeUnknown || len(c.Exclude) != 0 || len(c.CustomSchemes) != 0 {
		t.Errorf("empty config = %+v, want zero values", c)
	}
	// The maps must be usable, not nil, since the scanner indexes them.
	if c.Disabled == nil || c.Severity == nil {
		t.Error("Disabled and Severity must be non-nil")
	}
}

func TestLoad_MinConfidence(t *testing.T) {
	for _, s := range []string{"low", "high"} {
		c, err := Load(write(t, "min_confidence: "+s+"\n"))
		if err != nil {
			t.Fatalf("min_confidence %q: %v", s, err)
		}
		if !c.HasMinConf || string(c.MinConfidence) != s {
			t.Errorf("min_confidence %q -> %+v", s, c)
		}
	}
	// HasMinConf is what lets an explicit flag win over the config, so an
	// invalid value must fail loudly rather than silently defaulting.
	for _, s := range []string{"medium", "HIGH", "none"} {
		_, err := Load(write(t, "min_confidence: "+s+"\n"))
		if err == nil {
			t.Errorf("min_confidence %q should be rejected", s)
		} else if !strings.Contains(err.Error(), "min_confidence") {
			t.Errorf("error = %q, want it to name the field", err)
		}
	}
}

func TestLoad_AllSeveritiesAccepted(t *testing.T) {
	for _, s := range []string{"critical", "high", "medium", "low", "info"} {
		c, err := Load(write(t, "rules:\n  severity:\n    weak-hash-md5: "+s+"\n"))
		if err != nil {
			t.Fatalf("severity %q: %v", s, err)
		}
		if string(c.Severity["weak-hash-md5"]) != s {
			t.Errorf("severity %q -> %+v", s, c.Severity)
		}
	}
}

func TestLoad_CustomSchemeNeedsID(t *testing.T) {
	_, err := Load(write(t, "custom_schemes:\n  - pattern: '\\bfoo\\b'\n"))
	if err == nil {
		t.Fatal("a custom scheme without an id should be rejected")
	}
	if !strings.Contains(err.Error(), "custom_schemes[0]") {
		t.Errorf("error = %q, want it to point at the offending entry", err)
	}
}

func TestLoad_CustomSchemeInvalidPattern(t *testing.T) {
	_, err := Load(write(t, "custom_schemes:\n  - id: bad\n    pattern: '([unclosed'\n"))
	if err == nil {
		t.Fatal("an invalid regex should be rejected")
	}
}

// Error messages name the config file, since a scan may be run from anywhere.
func TestLoad_ErrorsNameTheFile(t *testing.T) {
	p := write(t, "min_confidence: bogus\n")
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), p) {
		t.Errorf("error = %v, want it to include the path %q", err, p)
	}
}
