package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/tools/go/analysis/analysistest"
)

func TestMSS(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), MSSAnalyzer, "mss")
}

func TestBS(t *testing.T) {
	MautrixVersion = "local"
	defer func() { MautrixVersion = "" }()
	analysistest.Run(t, analysistest.TestData(), BSAnalyzer, "bs")
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
		"local@2026-10-19T00:49:15+03:00":       false,
		"local@2026-10-20T09:00:00Z":            true,
		"local@unreadable":                      true,
	}
	for v, want := range cases {
		MautrixVersion = v
		if got := FrameworkHas(FeatureReloginDefault); got != want {
			t.Errorf("FrameworkHas(relogin) with %q = %v, want %v", v, got, want)
		}
	}
	MautrixVersion = ""
}

func TestConfigValidation(t *testing.T) {
	cases := map[string]string{
		"":                           "",
		"status_mapper: [wrapErr]\n": "field status_mapper not found",
		"disable: [GR012]\n":         "disable: unknown rule GR012",
		"severity: {XX001: info}\n":  "severity: unknown rule XX001",
		"severity: {MSS001: warn}\n": "severity: warn for MSS001 must be error, warning or info",
	}
	defer func() { ConfigOverride = "" }()
	for content, want := range cases {
		ConfigOverride = filepath.Join(t.TempDir(), ConfigFileName)
		if err := os.WriteFile(ConfigOverride, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := LoadConfig("")
		switch {
		case want == "" && err != nil:
			t.Errorf("config %q: unexpected error %v", content, err)
		case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
			t.Errorf("config %q: error %v, want %q", content, err, want)
		}
	}
}

func TestDisconnectEventsAddToDefaults(t *testing.T) {
	defer func() { ConfigOverride = "" }()
	ConfigOverride = filepath.Join(t.TempDir(), ConfigFileName)
	if err := os.WriteFile(ConfigOverride, []byte("disconnect_events:\n  example.com/lib: [\"*Gone\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.DisconnectEvents) != len(DefaultDisconnectEvents)+1 {
		t.Errorf("disconnect events = %v, want the defaults plus example.com/lib", cfg.DisconnectEvents)
	}
	if _, ok := DefaultDisconnectEvents["example.com/lib"]; ok {
		t.Error("loading a config changed DefaultDisconnectEvents")
	}
}

// TestCrossPackage runs in module mode, where errors are followed into other packages of the module.
func TestCrossPackage(t *testing.T) {
	analysistest.Run(t, filepath.Join(analysistest.TestData(), "crossmod"), MSSAnalyzer, "./...")
}

func TestLP(t *testing.T) {
	analysistest.RunWithSuggestedFixes(t, analysistest.TestData(), LPAnalyzer, "lp")
}

func TestEP(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), EPAnalyzer, "ep", "epnetlib", "epmain")
}

func TestGR(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), GRAnalyzer, "gr")
}

func TestBL(t *testing.T) {
	analysistest.Run(t, analysistest.TestData(), BLAnalyzer, "bl")
}

// A reasonless ignore can't be covered by analysistest: the `// want` text on the directive's own line
// would be read as the reason.
func TestParseIgnore(t *testing.T) {
	cases := []struct {
		text   string
		rules  []string
		reason string
	}{
		{text: "// just a comment"},
		{text: "//bridgelint:ignore MSS002 the reason", rules: []string{"MSS002"}, reason: "the reason"},
		{text: "//bridgelint:ignore MSS002 BS004 two rules", rules: []string{"MSS002", "BS004"}, reason: "two rules"},
		{text: "//bridgelint:ignore all everything here", rules: []string{"all"}, reason: "everything here"},
		{text: "//bridgelint:ignore MSS002", rules: []string{"MSS002"}},
		{text: "//bridgelint:ignore because I said so", reason: "because I said so"},
		{text: "//bridgelint:ignore"},
	}
	for _, c := range cases {
		entry := parseIgnore(c.text)
		if entry == nil {
			if c.rules != nil || c.reason != "" {
				t.Errorf("parseIgnore(%q) = nil, want rules %v reason %q", c.text, c.rules, c.reason)
			}
			continue
		}
		if entry.reason != c.reason {
			t.Errorf("parseIgnore(%q) reason = %q, want %q", c.text, entry.reason, c.reason)
		}
		if len(entry.rules) != len(c.rules) {
			t.Errorf("parseIgnore(%q) rules = %v, want %v", c.text, entry.rules, c.rules)
			continue
		}
		for _, want := range c.rules {
			if _, ok := entry.rules[want]; !ok {
				t.Errorf("parseIgnore(%q) rules = %v, missing %q", c.text, entry.rules, want)
			}
		}
	}
}

func TestWrapVerbArgs(t *testing.T) {
	cases := map[string][]int{
		"x: %w":          {0},
		"%d %s: %w":      {2},
		"100%% %v %w %w": {1, 2},
		"%*d %w":         {2},
		"no verbs":       nil,
		"%[2]w":          {1},
		"a %s: %[1]w":    {0},
		"%v %[1]w %w":    {0, 1},
		"%[w":            nil,
		"%[0]w":          nil, // an index must be 1-based; fmt rejects this, so nothing is wrapped
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
