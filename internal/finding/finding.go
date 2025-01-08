// Package finding defines the shared data types emitted by every detection
// tier and consumed by the report renderers.
package finding

// Confidence reflects which detection tier produced a finding. AST-backed
// tiers (1 and 2) yield high-confidence findings; the regex fallback (tier 3)
// yields low-confidence findings.
type Confidence string

const (
	High Confidence = "high"
	Low  Confidence = "low"
)

// Rank gives a total order for confidence levels, used for --min-confidence
// filtering.
func (c Confidence) Rank() int {
	switch c {
	case High:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// Severity classifies the security impact of a finding.
type Severity string

const (
	Critical Severity = "critical"
	HighSev  Severity = "high"
	Medium   Severity = "medium"
	LowSev   Severity = "low"
	Info     Severity = "info"
)

// Finding is a single reported issue at a specific source location.
type Finding struct {
	RuleID      string     `json:"rule_id"`
	Title       string     `json:"title"`
	Description string     `json:"description"`
	Severity    Severity   `json:"severity"`
	Confidence  Confidence `json:"confidence"`
	Remediation string     `json:"remediation,omitempty"`

	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column,omitempty"`

	// Snippet is the offending source line (trimmed), shown for context.
	Snippet string `json:"snippet,omitempty"`
}
