package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
)

// run executes the CLI in-process and returns its combined output.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := rootCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return buf.String(), err
}

// fixtureDir is a small tree with one weak Go file and one clean file.
func fixtureDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("weak.go", "package a\nimport \"crypto/md5\"\nvar _ = md5.New()\n")
	write("ok.go", "package a\nimport \"crypto/sha256\"\nvar _ = sha256.New()\n")
	return dir
}

func TestScanTextOutput(t *testing.T) {
	out, err := run(t, "scan", fixtureDir(t))
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	if !strings.Contains(out, "weak-hash-md5") {
		t.Errorf("expected an MD5 finding:\n%s", out)
	}
	if !strings.Contains(out, "Scanned 2 files") {
		t.Errorf("expected a summary line:\n%s", out)
	}
}

func TestScanJSONOutput(t *testing.T) {
	out, err := run(t, "scan", fixtureDir(t), "--format", "json")
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	var rep struct {
		Tool     string `json:"tool"`
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("--format json did not produce valid JSON: %v\n%s", err, out)
	}
	if rep.Tool != "cephalote" || len(rep.Findings) != 1 {
		t.Errorf("report = %+v", rep)
	}
}

func TestScanSARIFOutput(t *testing.T) {
	out, err := run(t, "scan", fixtureDir(t), "--format", "sarif")
	if err != nil {
		t.Fatalf("scan: %v\n%s", err, out)
	}
	var log map[string]any
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatalf("--format sarif did not produce valid JSON: %v\n%s", err, out)
	}
	if log["version"] != "2.1.0" {
		t.Errorf("sarif version = %v", log["version"])
	}
}

func TestScanInvalidFlags(t *testing.T) {
	dir := fixtureDir(t)
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad format", []string{"scan", dir, "--format", "xml"}, "unknown format"},
		{"bad confidence", []string{"scan", dir, "--min-confidence", "medium"}, "invalid --min-confidence"},
		{"bad scheme", []string{"scan", dir, "--scheme", "not-an-algorithm"}, "not-an-algorithm"},
		{"missing config", []string{"scan", dir, "--config", filepath.Join(dir, "nope.yaml")}, "no such file"},
		{"no args", []string{"scan"}, "arg"},
		{"too many args", []string{"scan", dir, dir}, "arg"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, err := run(t, c.args...)
			if err == nil {
				t.Fatalf("expected an error, got output:\n%s", out)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Errorf("error = %q, want it to mention %q", err, c.want)
			}
		})
	}
}

func TestScanRejectsNonDirectory(t *testing.T) {
	dir := fixtureDir(t)
	file := filepath.Join(dir, "weak.go")
	_, err := run(t, "scan", file)
	if err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("scan <file> error = %v, want 'not a directory'", err)
	}
	_, err = run(t, "scan", filepath.Join(dir, "does-not-exist"))
	if err == nil {
		t.Error("scan <missing> should fail")
	}
}

func TestScanMinConfidenceFiltersRegexFindings(t *testing.T) {
	dir := t.TempDir()
	// A .txt file is only ever reached via --include-unknown, and then only at
	// low confidence.
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("we use md5 here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "scan", dir, "--include-unknown")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "md5") {
		t.Errorf("--include-unknown should surface the regex match:\n%s", out)
	}

	out, err = run(t, "scan", dir, "--include-unknown", "--min-confidence", "high")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "md5") {
		t.Errorf("--min-confidence high should drop the low-confidence match:\n%s", out)
	}
}

func TestScanSchemeSearchMode(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.go"),
		[]byte("package a\n// we use sha256 for digests\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Search mode finds strong algorithms too, which the default weak scan
	// would never report.
	out, err := run(t, "scan", dir, "--scheme", "sha256")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "sha256") {
		t.Errorf("--scheme sha256 should find the mention:\n%s", out)
	}
}

func TestScanWithConfigFile(t *testing.T) {
	dir := fixtureDir(t)
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(cfg, []byte("rules:\n  disable:\n    - weak-hash-md5\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "scan", dir, "--config", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "weak-hash-md5") {
		t.Errorf("the config disabled this rule:\n%s", out)
	}
	if !strings.Contains(out, "0 finding(s)") {
		t.Errorf("expected no findings:\n%s", out)
	}
}

func TestExplicitFlagOverridesConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("md5 here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(cfg, []byte("min_confidence: low\ninclude_unknown: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, "scan", dir, "--config", cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "md5") {
		t.Errorf("config include_unknown should apply:\n%s", out)
	}

	out, err = run(t, "scan", dir, "--config", cfg, "--min-confidence", "high")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "md5") {
		t.Errorf("explicit --min-confidence should override the config:\n%s", out)
	}
}

func TestSchemesCommand(t *testing.T) {
	out, err := run(t, "schemes")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"NAME", "CLASS", "TITLE", "md5", "aes", "broken", "strong"} {
		if !strings.Contains(out, want) {
			t.Errorf("schemes output missing %q:\n%s", want, out)
		}
	}
	if _, err := run(t, "schemes", "extra-arg"); err == nil {
		t.Error("schemes takes no arguments")
	}
}

func TestParseConfidence(t *testing.T) {
	for _, s := range []string{"low", "high"} {
		got, err := parseConfidence(s)
		if err != nil || string(got) != s {
			t.Errorf("parseConfidence(%q) = %q, %v", s, got, err)
		}
	}
	for _, s := range []string{"", "medium", "HIGH", "none"} {
		if _, err := parseConfidence(s); err == nil {
			t.Errorf("parseConfidence(%q) should fail", s)
		}
	}
	// The parsed value must be what the scanner filters on.
	got, _ := parseConfidence("high")
	if got != finding.High {
		t.Errorf("parseConfidence(high) = %q, want finding.High", got)
	}
}

// --- exit codes -----------------------------------------------------------
//
// The scan command calls os.Exit for --exit-code, so these run the CLI as a
// subprocess. CI gates on these codes: 1 means "findings", 2 means "the tool
// failed", and conflating them would either hide breakage or fail builds for
// the wrong reason.

const subprocessEnv = "CEPHALOTE_TEST_SUBPROCESS"

func TestMain(m *testing.M) {
	if os.Getenv(subprocessEnv) == "1" {
		main()
		return
	}
	os.Exit(m.Run())
}

func exitCodeOf(t *testing.T, args ...string) int {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), subprocessEnv+"=1")
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("running subprocess: %v", err)
	}
	return ee.ExitCode()
}

func TestExitCodes(t *testing.T) {
	dir := fixtureDir(t)
	clean := t.TempDir()
	if err := os.WriteFile(filepath.Join(clean, "ok.go"),
		[]byte("package a\nimport \"crypto/sha256\"\nvar _ = sha256.New()\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		args []string
		want int
	}{
		{"findings without --exit-code", []string{"scan", dir}, 0},
		{"findings with --exit-code", []string{"scan", dir, "--exit-code"}, 1},
		{"no findings with --exit-code", []string{"scan", clean, "--exit-code"}, 0},
		{"usage error", []string{"scan", dir, "--format", "xml"}, 2},
		{"missing directory", []string{"scan", filepath.Join(dir, "nope")}, 2},
		{"unknown command", []string{"frobnicate"}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := exitCodeOf(t, c.args...); got != c.want {
				t.Errorf("exit code = %d, want %d", got, c.want)
			}
		})
	}
}
