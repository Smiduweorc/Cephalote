package finding

import (
	"bytes"
	"fmt"
)

// Validate reports the first way fs breaks the promises every analyzer makes
// about a scan of src at path: each finding names that file and a line that
// exists in it. Fuzz targets use it so every engine is held to one contract.
func Validate(path string, src []byte, fs []Finding) error {
	lines := bytes.Count(src, []byte("\n")) + 1
	for _, f := range fs {
		switch {
		case f.RuleID == "":
			return fmt.Errorf("finding without a rule id: %+v", f)
		case f.File != path:
			return fmt.Errorf("finding names %q, scanned %q", f.File, path)
		case f.Line < 1 || f.Line > lines:
			return fmt.Errorf("line %d outside 1..%d: %+v", f.Line, lines, f)
		case f.Column < 0:
			return fmt.Errorf("negative column: %+v", f)
		}
	}
	return nil
}
