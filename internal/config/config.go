// Package config loads the optional declarative configuration file that lets
// users tune a scan without touching engine code: excluding paths, disabling
// or re-rating rules, and adding custom regex detections.
package config

import (
	"fmt"
	"os"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/scheme"
	"gopkg.in/yaml.v3"
)

// File is the on-disk YAML schema.
type File struct {
	MinConfidence  string   `yaml:"min_confidence"`
	IncludeUnknown bool     `yaml:"include_unknown"`
	Exclude        []string `yaml:"exclude"`
	Rules          struct {
		Disable  []string          `yaml:"disable"`
		Severity map[string]string `yaml:"severity"`
	} `yaml:"rules"`
	CustomSchemes []struct {
		ID          string `yaml:"id"`
		Title       string `yaml:"title"`
		Class       string `yaml:"class"`
		Note        string `yaml:"note"`
		Pattern     string `yaml:"pattern"`
		Remediation string `yaml:"remediation"`
	} `yaml:"custom_schemes"`
}

// Config is the validated, ready-to-apply configuration.
type Config struct {
	MinConfidence  finding.Confidence
	HasMinConf     bool
	IncludeUnknown bool
	Exclude        []string
	Disabled       map[string]bool
	Severity       map[string]finding.Severity
	CustomSchemes  []scheme.Scheme
}

// Load reads and validates a YAML config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return f.compile(path)
}

func (f File) compile(path string) (*Config, error) {
	c := &Config{
		IncludeUnknown: f.IncludeUnknown,
		Exclude:        f.Exclude,
		Disabled:       map[string]bool{},
		Severity:       map[string]finding.Severity{},
	}

	if f.MinConfidence != "" {
		mc, ok := parseConfidence(f.MinConfidence)
		if !ok {
			return nil, fmt.Errorf("%s: invalid min_confidence %q", path, f.MinConfidence)
		}
		c.MinConfidence, c.HasMinConf = mc, true
	}

	for _, id := range f.Rules.Disable {
		c.Disabled[id] = true
	}
	for id, sev := range f.Rules.Severity {
		s, ok := parseSeverity(sev)
		if !ok {
			return nil, fmt.Errorf("%s: invalid severity %q for rule %q", path, sev, id)
		}
		c.Severity[id] = s
	}

	for i, cs := range f.CustomSchemes {
		if cs.ID == "" || cs.Pattern == "" {
			return nil, fmt.Errorf("%s: custom_schemes[%d] needs both id and pattern", path, i)
		}
		s, err := scheme.New(cs.ID, cs.Title, scheme.Class(cs.Class), cs.Note, cs.Remediation, cs.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		c.CustomSchemes = append(c.CustomSchemes, s)
	}
	return c, nil
}

func parseConfidence(s string) (finding.Confidence, bool) {
	switch finding.Confidence(s) {
	case finding.Low, finding.High:
		return finding.Confidence(s), true
	default:
		return "", false
	}
}

func parseSeverity(s string) (finding.Severity, bool) {
	switch finding.Severity(s) {
	case finding.Critical, finding.HighSev, finding.Medium, finding.LowSev, finding.Info:
		return finding.Severity(s), true
	default:
		return "", false
	}
}
