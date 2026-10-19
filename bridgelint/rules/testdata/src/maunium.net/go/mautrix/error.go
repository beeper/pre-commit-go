// Package mautrix is a minimal stub of maunium.net/go/mautrix for bridgelint tests.
package mautrix

type RespError struct {
	ErrCode    string
	Err        string
	StatusCode int
}

func (e RespError) Error() string { return e.ErrCode + ": " + e.Err }

func (e RespError) WithMessage(msg string, args ...any) RespError { e.Err = msg; return e }

func (e RespError) WithStatus(status int) RespError { e.StatusCode = status; return e }

var (
	MUnknown       = RespError{ErrCode: "M_UNKNOWN", StatusCode: 500}
	MForbidden     = RespError{ErrCode: "M_FORBIDDEN", StatusCode: 403}
	MNotFound      = RespError{ErrCode: "M_NOT_FOUND", StatusCode: 404}
	MLimitExceeded = RespError{ErrCode: "M_LIMIT_EXCEEDED", StatusCode: 429}
	MBadState      = RespError{ErrCode: "M_BAD_STATE"}
	MInvalidParam  = RespError{ErrCode: "M_INVALID_PARAM", StatusCode: 400}
)
