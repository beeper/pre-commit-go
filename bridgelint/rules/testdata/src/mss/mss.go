package mss

import (
	"context"
	"errors"
	"fmt"
	"time"

	"example.com/netlib"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
)

type Client struct {
	client *netlib.Client
	events chan string
}

var _ bridgev2.EditHandlingNetworkAPI = (*Client)(nil)

func (c *Client) Connect(ctx context.Context)      {}
func (c *Client) Disconnect()                      { c.client.Disconnect() }
func (c *Client) IsLoggedIn() bool                 { return true }
func (c *Client) LogoutRemote(ctx context.Context) { c.Disconnect() }

var errLocalSentinel = errors.New("only your own messages can be edited")

func (c *Client) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	if msg.Content == "" {
		return nil, errors.New("no message to send")
	}
	if len(msg.Content) > 1000 {
		return nil, fmt.Errorf("message is too long (max %d characters)", 1000)
	}
	if msg.Content == "x" {
		return nil, bridgev2.ErrMediaTooLarge
	}
	if msg.Content == "y" {
		return nil, errLocalSentinel
	}
	_, err := c.client.Send(ctx, msg.Content)
	if err != nil {
		return nil, err // want `MSS001: HandleMatrixMessage returns raw error from netlib.Send` `MSS006: this package has codeOf`
	}
	c.events <- "sent" // want `GR007: HandleMatrixMessage does a channel send`
	return &bridgev2.MatrixMessageResponse{}, nil
}

func (c *Client) HandleMatrixEdit(ctx context.Context, msg *bridgev2.MatrixEdit) error {
	_, err := c.client.Send(ctx, "edit")
	if err != nil {
		return classifySendError(err)
	}
	if err := c.sendHelper(ctx); err != nil {
		return err // want `MSS001: HandleMatrixEdit returns plain error "failed to send: %w" wrapping a raw netlib error \(via sendHelper`
	}
	select {
	case c.events <- "edit":
	default:
	}
	select {
	case c.events <- "edit":
	case <-time.After(time.Second):
	}
	select {
	case c.events <- "edit": // want `GR007: HandleMatrixEdit does a channel send`
	case c.events <- "again": // want `GR007: HandleMatrixEdit does a channel send`
	}
	return mapped(err)
}

func (c *Client) sendHelper(ctx context.Context) error {
	_, err := c.client.Send(ctx, "x")
	if err != nil {
		err = fmt.Errorf("failed to send: %w", err)
		return err
	}
	return nil
}

func classifySendError(err error) error {
	code := codeOf(err)
	return bridgev2.WrapErrorInStatus(err).WithMessage(code).WithErrorReason(event.MessageStatusNetworkError)
}

func codeOf(err error) string {
	var re *codeErr
	if errors.As(err, &re) {
		return re.code
	}
	return ""
}

type codeErr struct{ code string }

func (c *codeErr) Error() string { return c.code }

func mapped(err error) error {
	if err == nil {
		return nil
	}
	return bridgev2.WrapErrorInStatus(err).WithErrorReason(event.MessageStatusNetworkError)
}

func statuses(err error) []error {
	return []error{
		bridgev2.WrapErrorInStatus(err).WithErrorReason(event.MessageStatusUnsupported), // want `MSS002: status has ErrorReason MessageStatusUnsupported but no WithStatus`
		bridgev2.WrapErrorInStatus(err).WithErrorReason(event.MessageStatusUnsupported).WithStatus(event.MessageStatusFail).WithIsCertain(true),
		bridgev2.WrapErrorInStatus(errors.New("stickers are not supported")),
		bridgev2.WrapErrorInStatus(err).WithErrorAsMessage().WithStatus(event.MessageStatusFail).WithErrorReason(event.MessageStatusUnsupported),
		bridgev2.WrapErrorInStatus(fmt.Errorf("server said %w", err)).WithErrorAsMessage().WithErrorReason(event.MessageStatusNetworkError), // want `MSS003: WithErrorAsMessage shows an error that formats another error`
		bridgev2.WrapErrorInStatus(err).WithMessage("failed: " + err.Error()).WithErrorReason(event.MessageStatusNetworkError),              // want `MSS003: status message is built from raw error text`
		bridgev2.WrapErrorInStatus(context.DeadlineExceeded).WithIsCertain(true).WithErrorReason(event.MessageStatusNetworkError),           // want `MSS004: WithIsCertain\(true\) on a timeout`
		bridgev2.WrapErrorInStatus(err).WithMessage("network is down").WithIsCertain(false),
		bridgev2.MessageStatus{Message: "network is down", IsCertain: true}, // want `MSS005: status sets a message and certainty but no ErrorReason`
		bridgev2.WrapErrorInStatus(errors.New("that emoji can't be used")).WithErrorAsMessage().WithStatus(event.MessageStatusFail).WithErrorReason(event.MessageStatusUnsupported),
	}
}

func suppressed(err error) error {
	//bridgelint:ignore MSS002 the framework treats this reason as permanent here
	return bridgev2.WrapErrorInStatus(err).WithErrorReason(event.MessageStatusUnsupported)
}

func bareIgnore(err error) error {
	//bridgelint:ignore because I said so
	return bridgev2.WrapErrorInStatus(err).WithErrorReason(event.MessageStatusUnsupported) // want `MSS002`
}

func (c *Client) HandleMatrixReadReceipt(ctx context.Context, msg *bridgev2.MatrixMessage) error {
	_, err := c.client.Send(ctx, "read")
	return err
}

var ErrNotLoggedIn = bridgev2.WrapErrorInStatus(fmt.Errorf("you're %w", errLocalSentinel)).WithErrorAsMessage()

type userNotice string

func (n userNotice) Error() string { return string(n) }

func localNotice(err error) error {
	notice := userNotice("remove it there first")
	return bridgev2.WrapErrorInStatus(err).WithMessage(notice.Error()).WithErrorReason(event.MessageStatusUnsupported).WithStatus(event.MessageStatusFail)
}
