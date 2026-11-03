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
	if strings.Contains(err.Error(), "http 401") {
		return true
	}
	if strings.EqualFold(err.Error(), "Not_Found") { // want `EP001: error matched with strings.EqualFold`
		return true
	}
	return errors.Is(err, bridgev2.ErrNotLoggedIn)
}

func sameError(err, last error, seen map[string]bool, text string) bool {
	if last != nil && err.Error() == last.Error() {
		return true
	}
	if err.Error() == text || strings.EqualFold(err.Error(), text) {
		return true
	}
	switch err.Error() {
	case last.Error():
		return true
	}
	return seen[err.Error()]
}

// Declared without a body, like cgo's generated stubs and assembly functions.
func noBody()

func joined(a, b error) status.BridgeState {
	return status.BridgeState{StateEvent: status.StateUnknownError, Error: "ex-x", Message: errors.Join(a, b).Error()} // want `EP003: errors.Join text used as a user-facing message`
}
