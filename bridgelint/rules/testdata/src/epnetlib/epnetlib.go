// Package epnetlib is a protocol library (it doesn't import bridgev2).
package epnetlib

import (
	"fmt"
	"net/http"
)

func check(resp *http.Response) error {
	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode) // want `EP002: HTTP status formatted into a plain error`
	}
	return nil
}

// An API's own Response type isn't an HTTP response.
type Response struct {
	Status string
	Error  string
}

func checkAPI(r *Response) error {
	if r.Status != "ok" {
		return fmt.Errorf("api error: %s", r.Status)
	}
	return nil
}

type reply struct{ Status int }

func checkReply(r reply) error {
	if r.Status != 0 {
		return fmt.Errorf("server returned status %d", r.Status)
	}
	return nil
}
