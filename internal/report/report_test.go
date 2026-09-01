package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/rules"
	"github.com/Smiduweorc/Cephalote/internal/scan"
)

// sampleResult covers the shapes the renderers have to handle: two severities,
// a finding with a snippet and remediation, one without, and a scan error.
func sampleResult() *scan.Result {
	return &scan.Result{
		FilesScanned: 3,
		FilesSkipped: 1,
		Findings: []finding.Finding{
			{
				RuleID: rules.MD5, Title: "Use of MD5",
				Description: "MD5 is broken.", Severity: finding.HighSev,
				Confidence: finding.High, Remediation: "Use SHA-256.",
				File: "a/x.py", Line: 7, Column: 3, Snippet: "hashlib.md5(b'x')",
			},
			{
				RuleID: rules.SHA1, Title: "Use of SHA-1",
				Description: "SHA-1 is deprecated.", Severity: finding.Medium,
				Confidence: finding.Low,
				File:       "b/y.rb", Line: 2,
			},
		},
		Errors: []error{errors.New("read c/z.go: permission denied")},
	}
}

func TestParseFormat(t *testing.T) {
	for _, s := range []string{"text", "json", "sarif"} {
		got, err := ParseFormat(s)
		if err != nil || string(got) != s {
			t.Errorf("ParseFormat(%q) = %q, %v; want %q, nil", s, got, err, s)
		}
	}
	for _, s := range []string{"", "xml", "TEXT", "sarif "} {
		if _, err := ParseFormat(s); err == nil {
			t.Errorf("ParseFormat(%q) = nil error, want failure", s)
		}
	}
}

func TestRenderDispatch(t *testing.T) {
	res := sampleResult()
	cases := []struct {
		format Format
		probe  string
	}{
		{Text, "Scanned 3 files"},
		{JSON, `"tool": "cephalote"`},
		{SARIF, `"version": "2.1.0"`},
		// An unset format falls back to text rather than producing nothing.
		{Format("unset"), "Scanned 3 files"},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		if err := Render(&buf, res, c.format); err != nil {
			t.Fatalf("Render(%s): %v", c.format, err)
		}
		if !strings.Contains(buf.String(), c.probe) {
			t.Errorf("Render(%s) missing %q in:\n%s", c.format, c.probe, buf.String())
		}
	}
}

func TestRenderText(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, sampleResult(), Text); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"a/x.py:7:3 high [weak-hash-md5] Use of MD5 (high)",
		"    hashlib.md5(b'x')",
		"    fix: Use SHA-256.",
		"b/y.rb:2:0 medium [weak-hash-sha1] Use of SHA-1 (low)",
		"Scanned 3 files (1 skipped); 2 finding(s): high=1 medium=1",
		"1 error(s) during scan",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q in:\n%s", want, out)
		}
	}
	// The finding with no snippet/remediation must not emit empty detail lines.
	if strings.Contains(out, "    fix: \n") || strings.Contains(out, "\n    \n") {
		t.Errorf("text output has empty detail lines:\n%s", out)
	}
}

func TestRenderTextSummaryOrdersBySeverity(t *testing.T) {
	res := &scan.Result{Findings: []finding.Finding{
		{Severity: finding.Info}, {Severity: finding.Critical},
		{Severity: finding.LowSev}, {Severity: finding.HighSev},
		{Severity: finding.Medium},
	}}
	var buf bytes.Buffer
	if err := Render(&buf, res, Text); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	want := "critical=1 high=1 medium=1 low=1 info=1"
	if !strings.Contains(got, want) {
		t.Errorf("summary = %q, want it to contain %q", got, want)
	}
}

func TestRenderTextEmptyResult(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, &scan.Result{}, Text); err != nil {
		t.Fatal(err)
	}
	got := strings.TrimSpace(buf.String())
	// No findings means no per-severity breakdown and no error line.
	if got != "Scanned 0 files (0 skipped); 0 finding(s)" {
		t.Errorf("empty summary = %q", got)
	}
}

func TestRenderJSON(t *testing.T) {
	Version = "v1.2.3"
	t.Cleanup(func() { Version = "dev" })

	var buf bytes.Buffer
	if err := Render(&buf, sampleResult(), JSON); err != nil {
		t.Fatal(err)
	}
	var rep jsonReport
	if err := json.Unmarshal(buf.Bytes(), &rep); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if rep.Tool != "cephalote" || rep.Version != "v1.2.3" {
		t.Errorf("envelope = %+v, want tool=cephalote version=v1.2.3", rep)
	}
	if rep.FilesScanned != 3 || rep.FilesSkipped != 1 {
		t.Errorf("counts = %d/%d, want 3/1", rep.FilesScanned, rep.FilesSkipped)
	}
	if len(rep.Findings) != 2 || rep.Findings[0].RuleID != rules.MD5 {
		t.Errorf("findings = %+v", rep.Findings)
	}
	if len(rep.Errors) != 1 || !strings.Contains(rep.Errors[0], "permission denied") {
		t.Errorf("errors = %v, want the scan error rendered as a string", rep.Errors)
	}
}

// A null findings array breaks consumers that iterate it, so an empty scan must
// still emit [].
func TestRenderJSONEmptyFindingsIsArrayNotNull(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, &scan.Result{}, JSON); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"findings": []`) {
		t.Errorf("want an empty array, got:\n%s", buf.String())
	}
	var generic map[string]any
	if err := json.Unmarshal(buf.Bytes(), &generic); err != nil {
		t.Fatal(err)
	}
	if _, ok := generic["errors"]; ok {
		t.Error("errors should be omitted when there are none")
	}
}

func TestRenderSARIF(t *testing.T) {
	Version = "v1.2.3"
	t.Cleanup(func() { Version = "dev" })

	var buf bytes.Buffer
	if err := Render(&buf, sampleResult(), SARIF); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" || !strings.Contains(log.Schema, "sarif-schema-2.1.0") {
		t.Errorf("schema/version = %q / %q", log.Schema, log.Version)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(log.Runs))
	}
	run := log.Runs[0]
	if run.Tool.Driver.Name != "cephalote" || run.Tool.Driver.Version != "v1.2.3" {
		t.Errorf("driver = %+v", run.Tool.Driver)
	}

	if len(run.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(run.Results))
	}
	r := run.Results[0]
	if r.RuleID != rules.MD5 || r.Level != "error" {
		t.Errorf("result[0] = %s / %s, want %s / error", r.RuleID, r.Level, rules.MD5)
	}
	if r.Properties.Confidence != "high" {
		t.Errorf("result[0] confidence = %q, want high", r.Properties.Confidence)
	}
	loc := r.Locations[0].PhysicalLocation
	if loc.ArtifactLocation.URI != "a/x.py" || loc.Region.StartLine != 7 || loc.Region.StartColumn != 3 {
		t.Errorf("result[0] location = %+v", loc)
	}
	if run.Results[1].Level != "warning" {
		t.Errorf("medium severity = %q, want warning", run.Results[1].Level)
	}

	// Every result must reference a declared rule, and help text comes from
	// the rules catalog rather than the finding.
	declared := map[string]sarifRule{}
	for _, rd := range run.Tool.Driver.Rules {
		declared[rd.ID] = rd
	}
	if len(declared) != 2 {
		t.Errorf("declared rules = %d, want 2", len(declared))
	}
	for _, res := range run.Results {
		if _, ok := declared[res.RuleID]; !ok {
			t.Errorf("result references undeclared rule %q", res.RuleID)
		}
	}
	if got := declared[rules.MD5].Help.Text; got != rules.MustGet(rules.MD5).Remediation {
		t.Errorf("help = %q, want the catalog remediation", got)
	}
	if tags := declared[rules.MD5].Properties.Tags; len(tags) == 0 {
		t.Error("rule properties should carry tags for code-scanning filters")
	}
}

// Rules are declared once even when they fire many times, and in first-seen
// order.
func TestRenderSARIFDedupesRuleDefinitions(t *testing.T) {
	res := &scan.Result{Findings: []finding.Finding{
		{RuleID: rules.SHA1, Severity: finding.Medium, Line: 1},
		{RuleID: rules.MD5, Severity: finding.HighSev, Line: 2},
		{RuleID: rules.SHA1, Severity: finding.Medium, Line: 3},
	}}
	var buf bytes.Buffer
	if err := Render(&buf, res, SARIF); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	got := log.Runs[0].Tool.Driver.Rules
	if len(got) != 2 || got[0].ID != rules.SHA1 || got[1].ID != rules.MD5 {
		t.Errorf("rules = %+v, want [sha1 md5] declared once each", got)
	}
	if n := len(log.Runs[0].Results); n != 3 {
		t.Errorf("results = %d, want 3", n)
	}
}

// GitHub's ingest rejects null where it expects an array.
func TestRenderSARIFEmptyArraysAreNotNull(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, &scan.Result{}, SARIF); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, `"results": []`) || !strings.Contains(out, `"rules": []`) {
		t.Errorf("want empty arrays, got:\n%s", out)
	}
}

func TestSARIFLevel(t *testing.T) {
	cases := map[finding.Severity]string{
		finding.Critical:          "error",
		finding.HighSev:           "error",
		finding.Medium:            "warning",
		finding.LowSev:            "note",
		finding.Info:              "note",
		finding.Severity("bogus"): "note",
	}
	for sev, want := range cases {
		if got := sarifLevel(sev); got != want {
			t.Errorf("sarifLevel(%s) = %q, want %q", sev, got, want)
		}
	}
}

// A finding whose rule is not in the catalog (a custom scheme) must still
// render, just without help text.
func TestSARIFRuleDefForUnknownRuleID(t *testing.T) {
	def := ruleDef(finding.Finding{RuleID: "internal-xor", Title: "Home-grown XOR", Description: "d"})
	if def.ID != "internal-xor" || def.Help.Text != "" {
		t.Errorf("ruleDef = %+v, want no help text for an uncatalogued rule", def)
	}
}

func TestSeverityRank(t *testing.T) {
	ordered := []finding.Severity{
		finding.Critical, finding.HighSev, finding.Medium, finding.LowSev, finding.Info,
	}
	for i := 1; i < len(ordered); i++ {
		if severityRank(ordered[i-1]) <= severityRank(ordered[i]) {
			t.Errorf("%s should outrank %s", ordered[i-1], ordered[i])
		}
	}
	if severityRank(finding.Severity("bogus")) != severityRank(finding.Info) {
		t.Error("an unknown severity should rank lowest")
	}
}

// The renderers must surface write errors rather than silently succeeding.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRenderPropagatesWriteErrors(t *testing.T) {
	for _, f := range []Format{Text, JSON, SARIF} {
		if err := Render(failWriter{}, sampleResult(), f); err == nil {
			t.Errorf("Render(%s) to a failing writer returned nil error", f)
		}
	}
}
