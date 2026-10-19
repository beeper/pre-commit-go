package rules

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestMSS(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), MSSAnalyzer, "mss")
}

func TestBS(t *testing.T) {
	analysistest.RunWithSuggestedFixes(t, analysistest.TestData(), BSAnalyzer, "bs")
}

func TestLP(t *testing.T) {
	analysistest.RunWithSuggestedFixes(t, analysistest.TestData(), LPAnalyzer, "lp")
}

func TestEP(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), EPAnalyzer, "ep", "epnetlib")
}

func TestGR(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), GRAnalyzer, "gr")
}

func TestWrapVerbArgs(t *testing.T) {
	cases := map[string][]int{
		"x: %w":          {0},
		"%d %s: %w":      {2},
		"100%% %v %w %w": {1, 2},
		"%*d %w":         {2},
		"no verbs":       nil,
	}
	for format, want := range cases {
		got := wrapVerbArgs(format)
		if len(got) != len(want) {
			t.Errorf("wrapVerbArgs(%q) = %v, want %v", format, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("wrapVerbArgs(%q) = %v, want %v", format, got, want)
			}
		}
	}
}
