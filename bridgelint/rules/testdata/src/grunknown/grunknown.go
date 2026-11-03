// Package grunknown is linted with an unknown mautrix version, where GR013 stays quiet.
package grunknown

import (
	"context"

	"maunium.net/go/mautrix/bridgev2"
)

type Client struct{ meta any }

var _ bridgev2.NetworkAPI = (*Client)(nil)

func (c *Client) Connect(ctx context.Context)      {}
func (c *Client) Disconnect()                      {}
func (c *Client) IsLoggedIn() bool                 { return true }
func (c *Client) LogoutRemote(ctx context.Context) { c.meta = nil }
func (c *Client) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	return nil, nil
}
