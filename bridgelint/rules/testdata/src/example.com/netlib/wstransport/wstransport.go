// Package wstransport implements netlib.Transport over a connection.
package wstransport

import (
	"context"
	"net"
)

type Transport struct{ conn net.Conn }

func (t *Transport) Write(ctx context.Context, data []byte) error {
	_, err := t.conn.Write(data)
	return err
}
