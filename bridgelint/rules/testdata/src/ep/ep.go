package ep

import (
	"errors"
	"strings"

	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"
)

var _ = bridgev2.ErrNotLoggedIn

func match(err error) bool {
	if err.Error() == "no_reaction" { // want `EP001: error matched by comparing err.Error\(\)`
		return true
	}
	switch err.Error() { // want `EP001: switch on err.Error\(\)`
	case "token_revoked":
		return true
	}
	if strings.Contains(err.Error(), "http 401") { // want `EP001: error matched with strings.Contains`
		return true
	}
	return errors.Is(err, bridgev2.ErrNotLoggedIn)
}

func joined(a, b error) status.BridgeState {
	return status.BridgeState{StateEvent: status.StateUnknownError, Error: "ex-x", Message: errors.Join(a, b).Error()} // want `EP003: errors.Join text used as a user-facing message`
}
