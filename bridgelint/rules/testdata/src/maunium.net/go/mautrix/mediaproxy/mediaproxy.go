// Package mediaproxy is a minimal stub of maunium.net/go/mautrix/mediaproxy for bridgelint tests.
package mediaproxy

import (
	"errors"
	"io"
	"net/http"
	"os"
)

type GetMediaResponse interface {
	isGetMediaResponse()
}

type GetMediaResponseURL struct {
	URL string
}

type GetMediaResponseData struct {
	Reader        io.ReadCloser
	ContentType   string
	ContentLength int64
}

type FileMeta struct{}

type GetMediaResponseFile struct {
	Callback func(w *os.File) (*FileMeta, error)
}

func (*GetMediaResponseURL) isGetMediaResponse()  {}
func (*GetMediaResponseData) isGetMediaResponse() {}
func (*GetMediaResponseFile) isGetMediaResponse() {}

var ErrInvalidMediaIDSyntax = errors.New("invalid media ID syntax")

func Proxy(req *http.Request) (*http.Response, error) {
	return http.DefaultClient.Do(req)
}
