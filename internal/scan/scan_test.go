package scan

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/scheme"
)

// schemeFromConfigLike builds the custom scheme used by the disabled/custom test.
func schemeFromConfigLike(t *testing.T) ([]scheme.Scheme, error) {
	t.Helper()
	s, err := scheme.New("internal-xor", "Home-grown XOR", scheme.Broken, "", "Use AEAD.", `(?i)\bxor_encrypt\b`)
	if err != nil {
		return nil, err
	}
	return []scheme.Scheme{s}, nil
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRun_RoutingAndFiltering(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go", "package a\nimport \"crypto/md5\"\nvar _ = md5.New()\n")
	// Ruby has no tier-2 grammar, so it stays tier-3 (low) in both build
	// profiles, keeping this test independent of the treesitter tag.
	writeFile(t, dir, "b.rb", "require 'digest'\nDigest::MD5.hexdigest('x')\n")
	writeFile(t, dir, "vendor/skip.go", "package v\nimport \"crypto/md5\"\nvar _ = md5.New()\n")
	writeFile(t, dir, "notes.txt", "uses md5 somewhere\n")

	// Default: Go (high) + Ruby regex (low); .txt unknown is skipped.
	res, err := Run(dir, Options{MinConfidence: finding.Low})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Findings); got != 2 {
		t.Fatalf("default findings = %d, want 2: %+v", got, res.Findings)
	}

	// vendor/ must be skipped entirely.
	for _, f := range res.Findings {
		if filepath.Base(filepath.Dir(f.File)) == "vendor" {
			t.Errorf("vendor file should have been skipped: %s", f.File)
		}
	}

	// min-confidence high drops the regex (python) finding.
	res, err = Run(dir, Options{MinConfidence: finding.High})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Findings); got != 1 {
		t.Fatalf("high-confidence findings = %d, want 1: %+v", got, res.Findings)
	}

	// include-unknown picks up the .txt file.
	res, err = Run(dir, Options{MinConfidence: finding.Low, IncludeUnknown: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(res.Findings); got != 3 {
		t.Fatalf("include-unknown findings = %d, want 3: %+v", got, res.Findings)
	}
}

func TestRun_SuppressionAndOverrides(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.go",
		"package a\nimport (\"crypto/md5\"; \"crypto/sha1\")\n"+
			"var _ = md5.New()\n"+
			"var _ = sha1.New() // cephalote:ignore weak-hash-sha1\n")
	writeFile(t, dir, "skip/x.go", "package s\nimport \"crypto/md5\"\nvar _ = md5.New()\n")

	res, err := Run(dir, Options{
		MinConfidence:     finding.Low,
		Exclude:           []string{"skip/**"},
		SeverityOverrides: map[string]finding.Severity{"weak-hash-md5": finding.LowSev},
	})
	if err != nil {
		t.Fatal(err)
	}
	// sha1 suppressed, skip/ excluded -> only the md5 finding remains.
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(res.Findings), res.Findings)
	}
	f := res.Findings[0]
	if f.RuleID != "weak-hash-md5" || f.Severity != finding.LowSev {
		t.Errorf("override not applied: %+v", f)
	}
}

func TestRun_DisabledAndCustomScheme(t *testing.T) {
	dir := t.TempDir()
	// Ruby stays tier-3 in both builds, so this resolves to scheme:md5.
	writeFile(t, dir, "a.rb", "require 'digest'\nDigest::MD5.hexdigest('x')\n") // scheme:md5 (tier3)
	writeFile(t, dir, "b.txt", "call xor_encrypt(data) here\n")                 // custom, needs include-unknown

	custom, err := schemeFromConfigLike(t)
	if err != nil {
		t.Fatal(err)
	}
	res, err := Run(dir, Options{
		MinConfidence:  finding.Low,
		IncludeUnknown: true,
		Disabled:       map[string]bool{"scheme:md5": true},
		ExtraSchemes:   custom,
	})
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]int{}
	for _, f := range res.Findings {
		ids[f.RuleID]++
	}
	if ids["scheme:md5"] != 0 {
		t.Errorf("scheme:md5 should be disabled: %v", ids)
	}
	if ids["scheme:internal-xor"] != 1 {
		t.Errorf("custom scheme not detected: %v", ids)
	}
}

func TestRun_DeterministicOrder(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "z.go", "package z\nimport \"crypto/md5\"\nvar _ = md5.New()\n")
	writeFile(t, dir, "a.go", "package a\nimport \"crypto/des\"\nvar _ = des.NewCipher(nil)\n")

	res, err := Run(dir, Options{MinConfidence: finding.Low})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("want 2 findings, got %d", len(res.Findings))
	}
	if filepath.Base(res.Findings[0].File) != "a.go" {
		t.Errorf("findings not sorted by file: %s before %s",
			res.Findings[0].File, res.Findings[1].File)
	}
}
