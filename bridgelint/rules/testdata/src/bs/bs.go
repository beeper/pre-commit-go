package bs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"example.com/netlib"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/bridgev2/status"
)

type Client struct {
	client    *netlib.Client
	UserLogin *bridgev2.UserLogin
}

var _ bridgev2.NetworkAPI = (*Client)(nil)

func init() {
	status.BridgeStateHumanErrors.Update(status.BridgeStateErrorMap{
		"ex-invalid-auth": "Your session expired, log in again",
	})
}

func (c *Client) IsLoggedIn() bool                 { return true }
func (c *Client) Disconnect()                      {}
func (c *Client) LogoutRemote(ctx context.Context) { c.client.Disconnect() }
func (c *Client) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	return nil, nil
}

func (c *Client) Connect(ctx context.Context) {
	err := c.client.Connect(ctx)
	if err != nil {
		c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateUnknownError, Error: "ex-connect-failed", Message: "failed to connect"}) // want `BS006: UNKNOWN_ERROR for an unclassified raw error from netlib.Connect`
		return
	}
	go c.pollLoop(ctx)
	go c.giveUpLoop(ctx)
}

func (c *Client) states(err error) {
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: "ex-invalid-auth", UserAction: status.UserActionRelogin})                      // want `BS001: BAD_CREDENTIALS already defaults to RELOGIN`
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: "ex-account-suspended", Message: "suspended"})                                 // want `BS002: "ex-account-suspended" looks like a restriction`
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: "ex-checkpoint", Message: "checkpoint", UserAction: status.UserActionRestart}) // want `BS002: "ex-checkpoint" looks like a restriction`
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: "ex-banned", Message: "banned", UserAction: status.UserActionOpenNative})
	c.UserLogin.BridgeState.Send(status.BridgeState{
		StateEvent: status.StateTransientDisconnect,
		Error:      "ex-ws-error",
		Message:    err.Error(), // want `BS003: bridge state Message is built from raw error text; move`
	})
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: "ex-invalid-auth", Message: fmt.Sprintf("auth failed: %v", err)})        // want `BS003: .*silently discarded`
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateUnknownError, Message: "something broke"})                                                      // want `BS004: UNKNOWN_ERROR state has no Error code`
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateUnknownError, Error: status.BridgeStateErrorCode(fmt.Sprintf("ex-error-%d", 5)), Message: "x"}) // want `BS004: code built with fmt.Sprintf\("ex-error-%d"\)`
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateTransientDisconnect, Error: "ex-no-message"})                                                   // want `BS005: code "ex-no-message" has no Message`
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: "ex-invalid-auth"})
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateConnected})
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateTransientDisconnect, Error: "ExBadShape", Message: "x"}) // want `BS004: code "ExBadShape" doesn't match ex-<reason>`

	state := status.BridgeState{StateEvent: status.StateTransientDisconnect}
	state.Error = "ex-later"
	state.Message = "set later"
	c.UserLogin.BridgeState.Send(state)
}

func (c *Client) pollLoop(ctx context.Context) {
	for {
		_, err := c.client.Poll(ctx)
		if err != nil {
			zlog.Err(err).Msg("poll failed")
			continue
		}
	}
}

func (c *Client) giveUpLoop(ctx context.Context) {
	for attempt := 0; attempt < 5; attempt++ {
		if err := c.client.Connect(ctx); err == nil {
			return
		} else if errors.Is(err, netlib.ErrRateLimited) {
			time.Sleep(time.Second)
		}
	}
	c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateTransientDisconnect, Error: "ex-gave-up", Message: "gave up"}) // want `BS007: TRANSIENT_DISCONNECT followed by giving up`
	return
}

func (c *Client) authCheck(statusCode int) {
	if statusCode == 401 {
		c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateTransientDisconnect, Error: "ex-unauthorized", Message: "x"}) // want `BS010: TRANSIENT_DISCONNECT under an auth check`
	}
}

func (c *Client) catchAll(ctx context.Context) {
	if err := c.client.Connect(ctx); err != nil {
		c.UserLogin.BridgeState.Send(status.BridgeState{StateEvent: status.StateBadCredentials, Error: "ex-logged-out", Message: "logged out"}) // want `BS011: BAD_CREDENTIALS sent for every connect error`
	}
}

type logger struct{}
type logEvent struct{}

func (logger) Err(err error) *logEvent { return &logEvent{} }
func (*logEvent) Msg(msg string)       {}

var zlog logger

func (c *Client) handleEvent(evt any) {
	switch evt.(type) { // want `BS009: event handler for netlib has no case for \*DisconnectEvent`
	case *netlib.MessageEvent:
	case *netlib.ReadyEvent:
	}
}

func (c *Client) multiLine() {
	c.UserLogin.BridgeState.Send(status.BridgeState{ // want `BS002: "ex-temporary-ban" looks like a restriction`
		StateEvent: status.StateBadCredentials,
		Error:      "ex-temporary-ban",
		Message:    "temporarily banned",
	})
}
