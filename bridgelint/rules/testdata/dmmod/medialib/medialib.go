// Package medialib stands in for a network library that lives in the bridge's own module.
package medialib

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

type Client struct{ http *http.Client }

type StatusError struct{ StatusCode int }

func (e *StatusError) Error() string { return fmt.Sprintf("HTTP %d", e.StatusCode) }

type ParseError struct{ Input string }

func (e *ParseError) Error() string { return "invalid media key " + e.Input }

func (c *Client) get(ctx context.Context, url string) (*http.Response, error) { // want get:"complete=true"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

func (c *Client) Download(ctx context.Context, url string) (io.ReadCloser, error) { // want Download:"raw .*callee=medialib.StatusError"
	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, &StatusError{StatusCode: resp.StatusCode}
	}
	return resp.Body, nil
}

func (c *Client) Thumbnail(ctx context.Context, url string) (io.ReadCloser, error) { // want Thumbnail:"constructed .*thumbnail status"
	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	} else if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected thumbnail status %d", resp.StatusCode)
	}
	return resp.Body, nil
}

func (c *Client) Stream(ctx context.Context, url string) (io.ReadCloser, error) { // want Stream:"complete=true"
	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

func ParseKey(key string) (string, error) { // want ParseKey:"raw .*callee=medialib.ParseError"
	if key == "" {
		return "", &ParseError{Input: key}
	}
	return key, nil
}
