// Package jobq is a local work queue. Its Do takes a Request but never touches the network.
package jobq

import "errors"

type Request struct{ Name string }

type Queue struct{}

func (q *Queue) Do(r *Request) error { return errors.New("queue full") }
