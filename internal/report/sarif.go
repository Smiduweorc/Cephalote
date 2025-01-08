package report

import (
	"encoding/json"
	"io"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/rules"
	"github.com/Smiduweorc/Cephalote/internal/scan"
)

// Minimal SARIF 2.1.0 model, enough for GitHub/GitLab code-scanning ingest.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	HelpURI          string         `json:"helpUri,omitempty"`
	Help             sarifText      `json:"help,omitempty"`
	Properties       sarifRuleProps `json:"properties"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string           `json:"ruleId"`
	Level      string           `json:"level"`
	Message    sarifText        `json:"message"`
	Locations  []sarifLocation  `json:"locations"`
	Properties sarifResultProps `json:"properties,omitempty"`
}

type sarifResultProps struct {
	Confidence string `json:"confidence,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func renderSARIF(w io.Writer, result *scan.Result) error {
	// Emit only rules that actually fired, deduplicated, preserving order.
	seen := map[string]bool{}
	var ruleDefs []sarifRule
	var results []sarifResult

	for _, f := range result.Findings {
		if !seen[f.RuleID] {
			seen[f.RuleID] = true
			ruleDefs = append(ruleDefs, ruleDef(f))
		}
		results = append(results, sarifResult{
			RuleID:  f.RuleID,
			Level:   sarifLevel(f.Severity),
			Message: sarifText{Text: f.Description},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysical{
					ArtifactLocation: sarifArtifact{URI: f.File},
					Region:           sarifRegion{StartLine: f.Line, StartColumn: f.Column},
				},
			}},
			Properties: sarifResultProps{Confidence: string(f.Confidence)},
		})
	}
	if results == nil {
		results = []sarifResult{}
	}
	if ruleDefs == nil {
		ruleDefs = []sarifRule{}
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "cephalote",
				Version:        Version,
				InformationURI: "https://github.com/Smiduweorc/Cephalote",
				Rules:          ruleDefs,
			}},
			Results: results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func ruleDef(f finding.Finding) sarifRule {
	r := sarifRule{
		ID:               f.RuleID,
		Name:             f.Title,
		ShortDescription: sarifText{Text: f.Title},
		FullDescription:  sarifText{Text: f.Description},
		Properties:       sarifRuleProps{Tags: []string{"cryptography", "security"}},
	}
	if rule, ok := rules.Get(f.RuleID); ok && rule.Remediation != "" {
		r.Help = sarifText{Text: rule.Remediation}
	}
	return r
}

// sarifLevel maps a severity to a SARIF result level.
func sarifLevel(s finding.Severity) string {
	switch s {
	case finding.Critical, finding.HighSev:
		return "error"
	case finding.Medium:
		return "warning"
	default:
		return "note"
	}
}
