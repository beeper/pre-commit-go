package rules

import (
	"strings"
	"time"

	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

type Feature struct {
	// Commit time of the mautrix/go change; pseudo-versions at or after it include the feature.
	Since time.Time
	// LastTagWithout is the newest release tag known not to include it.
	LastTagWithout string
}

var (
	// mautrix/go 5142cc4: BridgeState.Fill defaults BAD_CREDENTIALS to RELOGIN.
	FeatureReloginDefault = Feature{Since: time.Date(2026, 10, 19, 10, 47, 39, 0, time.UTC), LastTagWithout: "v0.32.0"}
	// mautrix/go 5c03a378: UserLogin always calls Disconnect after LogoutRemote.
	FeatureDisconnectAfterLogout = Feature{Since: time.Date(2026, 10, 19, 10, 41, 37, 0, time.UTC), LastTagWithout: "v0.32.0"}
	// mautrix/go 69c19fed: the media proxy sends errors passing exhttp.IsNetworkError as 502 instead of 404.
	FeatureMediaProxyNetworkErrors = Feature{Since: time.Date(2026, 10, 13, 12, 2, 0, 0, time.UTC), LastTagWithout: "v0.31.0"}
	// mautrix/go 29f550d4: bridgev2.RespError has an As method that fills a mautrix.RespError, so the media
	// proxy recognises it, as a value or a pointer.
	FeatureBridgeRespErrorAs = Feature{Since: time.Date(2026, 10, 13, 11, 58, 38, 0, time.UTC), LastTagWithout: "v0.31.0"}
)

// MautrixVersion is the maunium.net/go/mautrix version of the module being linted, set by the driver.
// "local@<RFC 3339 time>" is a local checkout whose git HEAD was committed then; plain "local" is one
// whose HEAD couldn't be read, assumed to be recent. Empty means unknown.
var MautrixVersion string

// FrameworkHas reports whether the linted module's mautrix includes f. Unknown versions report false,
// so rules that depend on newer framework behaviour stay quiet rather than guess.
func FrameworkHas(f Feature) bool {
	v := MautrixVersion
	switch {
	case v == "local":
		return true
	case strings.HasPrefix(v, "local@"):
		t, err := time.Parse(time.RFC3339, strings.TrimPrefix(v, "local@"))
		return err != nil || !t.Before(f.Since)
	case v == "" || !semver.IsValid(v):
		return false
	case module.IsPseudoVersion(v):
		t, err := module.PseudoVersionTime(v)
		return err == nil && !t.Before(f.Since)
	default:
		return semver.Compare(v, f.LastTagWithout) > 0
	}
}

// FrameworkLacks reports whether the linted module's mautrix is known not to include f. Unknown versions
// report false, so rules about older framework behaviour stay quiet rather than guess.
func FrameworkLacks(f Feature) bool {
	v := MautrixVersion
	known := v == "local" || strings.HasPrefix(v, "local@") || semver.IsValid(v)
	return known && !FrameworkHas(f)
}
