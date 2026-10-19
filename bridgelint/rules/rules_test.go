package rules

import (
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestMSS(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), MSSAnalyzer, "mss")
}

func TestBS(t *testing.T) {
	MautrixVersion = "local"
	defer func() { MautrixVersion = "" }()
	analysistest.RunWithSuggestedFixes(t, analysistest.TestData(), BSAnalyzer, "bs")
}

func TestFrameworkHas(t *testing.T) {
	cases := map[string]bool{
		"":                                      false,
		"local":                                 true,
		"v0.32.0":                               false,
		"v0.32.1":                               true,
		"v0.33.0":                               true,
		"v0.32.1-0.20261017155816-789c6d4faeb3": false,
		"v0.32.1-0.20261019120000-0123456789ab": true,
	}
	for v, want := range cases {
		MautrixVersion = v
		if got := FrameworkHas(FeatureReloginDefault); got != want {
			t.Errorf("FrameworkHas(relogin) with %q = %v, want %v", v, got, want)
		}
	}
	MautrixVersion = ""
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
