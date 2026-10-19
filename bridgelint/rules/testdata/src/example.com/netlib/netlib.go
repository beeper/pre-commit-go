// Package netlib stands in for a network protocol library.
package netlib

import "context"

type Client struct{}

var ErrRateLimited error

func (c *Client) Send(ctx context.Context, text string) (string, error) { return "", nil }
func (c *Client) Connect(ctx context.Context) error                     { return nil }
func (c *Client) Disconnect()                                           {}
func (c *Client) Poll(ctx context.Context) ([]string, error)            { return nil, nil }
func (c *Client) Lookup(ctx context.Context, id string) (string, error) { return "", nil }

func ClassifyCode(err error) string { return "" }

type MessageEvent struct{}
type ReadyEvent struct{}
type DisconnectEvent struct{}
