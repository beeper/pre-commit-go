// Package netlib stands in for a network protocol library.
package netlib

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"strings"
)

// Doer is satisfied by *http.Client.
type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	bw        *bufio.Writer
	doer      Doer
	http      *http.Client
	conn      net.Conn
	transport Transport
	store     Store
}

var ErrRateLimited error

var ErrUnauthorized error

// APIError is a protocol error carrying the remote's own status code.
type APIError struct {
	Code int
	Msg  string
}

func (e *APIError) Error() string { return e.Msg }

// Transport is implemented outside this package (see wstransport), so calls through it are resolved by
// importers that can see the implementation.
type Transport interface {
	Write(ctx context.Context, data []byte) error
}

// Store is only implemented by memstore, which never touches the network.
type Store interface {
	Load(ctx context.Context, key string) (string, error)
}

func (c *Client) do(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *Client) Send(ctx context.Context, text string) (string, error) {
	resp, err := c.do(ctx, "https://example.com/send")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return resp.Header.Get("X-ID"), nil
}

func (c *Client) Fetch(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
	if err != nil {
		return err
	}
	resp, err := c.doer.Do(req)
	if err != nil {
		return err
	}
	return resp.Body.Close()
}

func (c *Client) Connect(ctx context.Context) error {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		return err
	}
	c.conn = conn
	return nil
}

func (c *Client) Disconnect() {}

func (c *Client) Poll(ctx context.Context) ([]string, error) {
	buf := make([]byte, 1024)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(buf[:n]), "\n"), nil
}

func (c *Client) Lookup(ctx context.Context, id string) (string, error) {
	resp, err := c.do(ctx, "https://example.com/lookup/"+id)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	return resp.Header.Get("X-Name"), nil
}

func (c *Client) Publish(ctx context.Context, data []byte) error {
	return c.transport.Write(ctx, data)
}

func (c *Client) Cached(ctx context.Context, key string) (string, error) {
	return c.store.Load(ctx, key)
}

// Stream writes through a bufio.Writer wrapped around the connection, which can't be followed.
func (c *Client) Stream(ctx context.Context, data []byte) error {
	if _, err := c.bw.Write(data); err != nil {
		return err
	}
	return c.bw.Flush()
}

// Ping writes from a goroutine and waits for the result.
func (c *Client) Ping() error {
	done := make(chan error, 1)
	go func() {
		_, err := c.conn.Write([]byte("ping"))
		done <- err
	}()
	return <-done
}

// StartReader reads from a goroutine nobody waits on.
func (c *Client) StartReader() error {
	go func() {
		_, _ = c.conn.Read(make([]byte, 1))
	}()
	return ParseErr
}

var ParseErr error

// Auth is only called when a connection is set up, so building one doesn't reach the network.
type Auth struct {
	Handshake func(ctx context.Context) error
}

func NewAuth(conn net.Conn) *Auth {
	return &Auth{Handshake: func(ctx context.Context) error {
		_, err := conn.Write([]byte("hello"))
		return err
	}}
}

func (a *Auth) Validate() error {
	if a.Handshake == nil {
		return ErrRateLimited
	}
	return nil
}

func ParseID(ctx context.Context, id string) (string, error) {
	if id == "" {
		return "", ErrRateLimited
	}
	return id, nil
}

func ClassifyCode(err error) string { return "" }

type MessageEvent struct{}
type ReadyEvent struct{}
type DisconnectEvent struct{}
