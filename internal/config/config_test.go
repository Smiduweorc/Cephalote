package config

import (
	"os"
	"path/filepath"
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
