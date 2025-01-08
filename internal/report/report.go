// Package report renders scan findings in text, JSON, or SARIF formats.
package report

import (
	"fmt"
	"io"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/scan"
)

// Version is the tool version embedded in machine-readable output. It is
// overridden by the CLI at startup (e.g. from a build-time ldflag).
var Version = "dev"

// Format is an output format selector.
type Format string

const (
	Text  Format = "text"
	JSON  Format = "json"
	SARIF Format = "sarif"
)

// ParseFormat validates a format string.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case Text, JSON, SARIF:
		return Format(s), nil
	default:
		return "", fmt.Errorf("unknown format %q (want text, json, or sarif)", s)
	}
}

// Render writes the result to w in the given format.
func Render(w io.Writer, result *scan.Result, format Format) error {
	switch format {
	case JSON:
		return renderJSON(w, result)
	case SARIF:
		return renderSARIF(w, result)
	default:
		return renderText(w, result)
	}
}

// severityRank orders severities for summaries (higher = worse).
func severityRank(s finding.Severity) int {
	switch s {
	case finding.Critical:
		return 5
	case finding.HighSev:
		return 4
	case finding.Medium:
		return 3
	case finding.LowSev:
		return 2
	default:
		return 1
	}
}
