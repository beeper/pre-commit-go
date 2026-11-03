// Package state sends the bridge's states, using error types from another package of the module.
package state

import (
	"example.com/crossmod/errs"
	"example.com/crossmod/lib"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"
)

var _ = bridgev2.ErrNotLoggedIn

func noticeState(n errs.NoticeError) status.BridgeState {
	return status.BridgeState{StateEvent: status.StateUnknownError, Error: "crossmod-notice", Message: n.Error()}
}

func libState(e *lib.Error) status.BridgeState {
	return status.BridgeState{StateEvent: status.StateUnknownError, Error: "crossmod-lib", Message: e.Error()} // want `BS003: bridge state Message is built from raw error text`
}
