// Package lib stands in for a network library that lives in the bridge's own module.
package lib

import (
	"context"
	"fmt"

	"example.com/netlib"
)

type Client struct {
	c    *netlib.Client
	hook func(ctx context.Context) error
}

func (c *Client) Send(ctx context.Context, text string) error { // want Send:"constructed .*callee=netlib.Send"
	_, err := c.c.Send(ctx, text)
	if err != nil {
		return fmt.Errorf("failed to send: %w", err)
	}
	return nil
}

// Post retries through a helper that calls its parameter, so the method passed by name is what reaches
// the network.
func (c *Client) Post(ctx context.Context) error {
	return retry(ctx, c.post)
}

func (c *Client) post(ctx context.Context) error { // want post:"raw .*callee=netlib.Send"
	_, err := c.c.Send(ctx, "post")
	return err
}

func retry(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

// Notify runs a hook stored on the client, which can't be followed.
func (c *Client) Notify(ctx context.Context) error {
	return retry(ctx, c.hook)
}

func ConvertAudio(ctx context.Context, data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	return data, nil
}
