// Package main is a command, not a library, so its errors aren't for callers to classify.
package main

import (
	"fmt"
	"net/http"
)

func check(resp *http.Response) error {
	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}
	return nil
}

func main() {}
