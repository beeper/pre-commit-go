// Package errs holds the bridge's own error types, whose text is a fixed notice.
package errs

type NoticeError struct{ Notice string }

func (e NoticeError) Error() string { return e.Notice }
