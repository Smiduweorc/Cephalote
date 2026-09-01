package finding

import "testing"

// Rank backs --min-confidence filtering, so its ordering decides whether a
// finding is reported at all.
func TestConfidenceRank(t *testing.T) {
	if Low.Rank() >= High.Rank() {
		t.Errorf("Low.Rank() = %d, High.Rank() = %d; high must outrank low", Low.Rank(), High.Rank())
	}
	// An unset or unrecognized confidence must rank below every real level, so
	// that --min-confidence low still filters it out rather than letting a
	// malformed finding through.
	for _, c := range []Confidence{"", "medium", "HIGH"} {
		if c.Rank() >= Low.Rank() {
			t.Errorf("Confidence(%q).Rank() = %d, want below Low (%d)", c, c.Rank(), Low.Rank())
		}
	}
}

func TestConfidenceRankFiltering(t *testing.T) {
	cases := []struct {
		min, have Confidence
		reported  bool
	}{
		{Low, High, true},
		{Low, Low, true},
		{High, High, true},
		{High, Low, false},
	}
	for _, c := range cases {
		got := c.have.Rank() >= c.min.Rank()
		if got != c.reported {
			t.Errorf("min=%s have=%s reported=%v, want %v", c.min, c.have, got, c.reported)
		}
	}
}
