package connector

import (
	"context"

	"example.com/crossmod/conv"
	"example.com/crossmod/lib"
	"example.com/netlib"
	"maunium.net/go/mautrix/bridgev2"
)

type Client struct {
	lib *lib.Client
	net *netlib.Client
}

var _ bridgev2.NetworkAPI = (*Client)(nil)

func (c *Client) Connect(ctx context.Context)      {}
func (c *Client) Disconnect()                      {}
func (c *Client) IsLoggedIn() bool                 { return true }
func (c *Client) LogoutRemote(ctx context.Context) {}

func (c *Client) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) { // want HandleMatrixMessage:"raw .*callee=lib.Send network=true"
	text, err := conv.ToNetwork(ctx, c.net, msg)
	if err != nil {
		return nil, err
	}
	if _, err = lib.ConvertAudio(ctx, []byte(text)); err != nil {
		return nil, err
	}
	if err = c.lib.Send(ctx, text); err != nil {
		return nil, err // want `MSS001: HandleMatrixMessage returns raw error from lib.Send;`
	}
	return &bridgev2.MatrixMessageResponse{}, nil
}
