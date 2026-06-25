package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/Smiduweorc/Cephalote/internal/finding"
	"github.com/Smiduweorc/Cephalote/internal/scan"
)

func renderText(w io.Writer, result *scan.Result) error {
	for _, f := range result.Findings {
		if _, err := fmt.Fprintf(w, "%s:%d:%d %s [%s] %s (%s)\n",
			f.File, f.Line, f.Column,
			f.Severity, f.RuleID, f.Title, f.Confidence); err != nil {
			return err
		}
		if f.Snippet != "" {
			fmt.Fprintf(w, "    %s\n", f.Snippet)
		}
		if f.Remediation != "" {
			fmt.Fprintf(w, "    fix: %s\n", f.Remediation)
		}
	}

	bySev := map[finding.Severity]int{}
	for _, f := range result.Findings {
		bySev[f.Severity]++
	}
	fmt.Fprintf(w, "\nScanned %d files (%d skipped); %d finding(s)",
		result.FilesScanned, result.FilesSkipped, len(result.Findings))
	if len(bySev) > 0 {
		sevs := make([]finding.Severity, 0, len(bySev))
		for s := range bySev {
			sevs = append(sevs, s)
		}
		sort.Slice(sevs, func(i, j int) bool {
			return severityRank(sevs[i]) > severityRank(sevs[j])
		})
		fmt.Fprint(w, ":")
		for _, s := range sevs {
			fmt.Fprintf(w, " %s=%d", s, bySev[s])
		}
	}
	fmt.Fprintln(w)
	if len(result.Errors) > 0 {
		fmt.Fprintf(w, "%d error(s) during scan\n", len(result.Errors))
	}
	return nil
}
