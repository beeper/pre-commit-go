// Package conv stands in for a bridge's message converter: it reaches the network to upload media, but
// wraps failures in statuses itself.
package conv

import (
	"context"
	"fmt"

	"example.com/netlib"
	"maunium.net/go/mautrix/bridgev2"
)

func ToNetwork(ctx context.Context, client *netlib.Client, msg *bridgev2.MatrixMessage) (string, error) { // want ToNetwork:"network=true opaque=false statuses=true"
	if msg.Content == "" {
		return "", bridgev2.ErrUnsupportedMessageType
	}
	id, err := client.Send(ctx, msg.Content)
	if err != nil {
		return "", fmt.Errorf("%w: %w", bridgev2.ErrMediaTooLarge, err)
	}
	return id, nil
}
