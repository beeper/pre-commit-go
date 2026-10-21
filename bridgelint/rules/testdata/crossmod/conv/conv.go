// Package conv stands in for a bridge's message converter: it reaches the network to upload media, but
// wraps failures in statuses itself.
package conv

import (
	"context"
	"errors"
	"fmt"

	"example.com/netlib"
	"maunium.net/go/mautrix/bridgev2"
)

func ToNetwork(ctx context.Context, client *netlib.Client, msg *bridgev2.MatrixMessage) (string, error) { // want ToNetwork:"statuses=true"
	if msg.Content == "" {
		return "", bridgev2.ErrUnsupportedMessageType
	}
	id, err := client.Send(ctx, msg.Content)
	if err != nil {
		return "", fmt.Errorf("%w: %w", bridgev2.ErrMediaTooLarge, err)
	}
	return id, nil
}

var ErrUploadFailed = errors.New("failed to upload media")

// Upload turns the network error into a fixed one, so callers get an internal error rather than a raw
// network error.
func Upload(ctx context.Context, client *netlib.Client, data string) (string, error) { // want Upload:"constructed .*complete=true"
	id, err := client.Send(ctx, data)
	if err != nil {
		return "", ErrUploadFailed
	}
	return id, nil
}

func Forward(ctx context.Context, client *netlib.Client, data string) (string, error) { // want Forward:"raw .*callee=netlib.Send"
	if data == "" {
		return "", ErrUploadFailed
	}
	return client.Send(ctx, data)
}
