// Package zerolog is a stub of github.com/rs/zerolog for GR004.
package zerolog

type Event struct{}

func (e *Event) Err(err error) *Event { return e }

func (e *Event) Msg(msg string) {}

type Logger struct{}

func (l Logger) Fatal() *Event { return &Event{} }

func (l Logger) Error() *Event { return &Event{} }
