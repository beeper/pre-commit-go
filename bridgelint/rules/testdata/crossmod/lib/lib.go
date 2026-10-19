// Package lib stands in for a network library that lives in the bridge's own module.
package lib

import (
	"context"
	"fmt"

	"example.com/netlib"
)

type Client struct{ c *netlib.Client }

func (c *Client) Send(ctx context.Context, text string) error { // want Send:"constructed .*callee=netlib.Send"
	_, err := c.c.Send(ctx, text)
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}
	return nil
}

func ConvertAudio(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}
