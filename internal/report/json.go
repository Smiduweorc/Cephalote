package report

import (
	"encoding/json"
	"io"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/scan"
)

// jsonReport is the stable JSON envelope.
type jsonReport struct {
	Tool         string            `json:"tool"`
	Version      string            `json:"version"`
	FilesScanned int               `json:"files_scanned"`
	FilesSkipped int               `json:"files_skipped"`
	Findings     []finding.Finding `json:"findings"`
	Errors       []string          `json:"errors,omitempty"`
}

func renderJSON(w io.Writer, result *scan.Result) error {
	rep := jsonReport{
		Tool:         "cephalote",
		Version:      Version,
		FilesScanned: result.FilesScanned,
		FilesSkipped: result.FilesSkipped,
		Findings:     result.Findings,
	}
	if rep.Findings == nil {
		rep.Findings = []finding.Finding{}
	}
	for _, e := range result.Errors {
		rep.Errors = append(rep.Errors, e.Error())
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
