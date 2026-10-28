// Package fhttp stands in for a fork of net/http.
package fhttp

import (
	"io"
	"net/url"
)

type Header map[string][]string

type Request struct {
	Method  string
	URL     *url.URL
	Header  Header
	Body    io.ReadCloser
	GetBody func() (io.ReadCloser, error)
}

type Response struct {
	Status     string
	StatusCode int
	Header     Header
	Body       io.ReadCloser
}

type Client struct{}

func (c *Client) Do(req *Request) (*Response, error) { return &Response{}, nil }
