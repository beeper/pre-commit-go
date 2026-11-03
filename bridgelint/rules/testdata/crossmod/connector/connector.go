package connector

import (
	"context"

	"example.com/crossmod/conv"
	"example.com/crossmod/db"
	"example.com/crossmod/errs"
	"example.com/crossmod/lib"
	"example.com/jobq"
	"example.com/netlib"
	"example.com/netlib/memstore"
	"example.com/netlib/wstransport"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
)

// MessageStore is implemented by a package this one doesn't import, wired up in main.
type MessageStore interface {
	GetMessage(ctx context.Context, id string) (string, error)
}

type Client struct {
	lib   *lib.Client
	net   *netlib.Client
	db    *db.Store
	store MessageStore
	queue *jobq.Queue
}

var _ bridgev2.NetworkAPI = (*Client)(nil)

var (
	_ netlib.Transport = (*wstransport.Transport)(nil)
	_ netlib.Store     = (*memstore.Store)(nil)
)

func (c *Client) Connect(ctx context.Context)      {}
func (c *Client) Disconnect()                      {}
func (c *Client) IsLoggedIn() bool                 { return true }
func (c *Client) LogoutRemote(ctx context.Context) {}

func (c *Client) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) { // want HandleMatrixMessage:"raw .*callee=lib.Send"
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
	if _, err = conv.Upload(ctx, c.net, text); err != nil {
		return nil, err
	}
	if _, err = conv.Forward(ctx, c.net, text); err != nil {
		return nil, err // want `MSS001: HandleMatrixMessage returns raw error from conv.Forward;`
	}
	return &bridgev2.MatrixMessageResponse{}, nil
}

func (c *Client) HandleMatrixReactionRemove(ctx context.Context, msg *bridgev2.MatrixReaction) error { // want HandleMatrixReactionRemove:"raw .*callee=lib.Post"
	if err := c.db.Insert(ctx, "x"); err != nil {
		return err
	}
	if err := c.lib.Post(ctx); err != nil {
		return err // want `MSS001: HandleMatrixReactionRemove returns raw error from lib.Post;`
	}
	if err := c.lib.Notify(ctx); err != nil {
		return err // want `MSS001: HandleMatrixReactionRemove returns raw error from lib.Notify;`
	}
	return nil
}

func (c *Client) HandleMatrixEdit(ctx context.Context, msg *bridgev2.MatrixEdit) error { // want HandleMatrixEdit:"raw .*callee=netlib.Publish"
	if _, err := netlib.ParseID(ctx, "edit"); err != nil {
		return err
	}
	if _, err := c.net.Cached(ctx, "edit"); err != nil {
		return err
	}
	if err := c.net.Publish(ctx, []byte("edit")); err != nil {
		return err // want `MSS001: HandleMatrixEdit returns raw error from netlib.Publish;`
	}
	return nil
}

func (c *Client) HandleMatrixReaction(ctx context.Context, msg *bridgev2.MatrixReaction) error { // want HandleMatrixReaction:"raw .*callee=netlib.(Fetch|Ping|Stream)"
	if err := netlib.NewAuth(nil).Validate(); err != nil {
		return err
	}
	if err := c.net.Fetch(ctx); err != nil {
		return err // want `MSS001: HandleMatrixReaction returns raw error from netlib.Fetch;`
	}
	if err := c.net.StartReader(); err != nil {
		return err
	}
	if err := c.net.Ping(); err != nil {
		return err // want `MSS001: HandleMatrixReaction returns raw error from netlib.Ping;`
	}
	if err := c.net.Stream(ctx, nil); err != nil {
		return err // want `MSS001: HandleMatrixReaction returns raw error from netlib.Stream;`
	}
	return nil
}

func (c *Client) HandleMatrixMessageRemove(ctx context.Context, msg *bridgev2.MatrixMessageRemove) error { // want HandleMatrixMessageRemove:"^ msg=\"\" callee=. statuses=true"
	if _, err := c.store.GetMessage(ctx, "x"); err != nil {
		return err
	}
	if err := c.queue.Do(&jobq.Request{Name: "x"}); err != nil {
		return err
	}
	if err := c.net.Publish(ctx, nil); err != nil {
		return bridgev2.WrapErrorInStatus(err).WithMessage(errs.NoticeError{Notice: "x"}.Error()).WithErrorReason(event.MessageStatusNetworkError)
	}
	return nil
}
