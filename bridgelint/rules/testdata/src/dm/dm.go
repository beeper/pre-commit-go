package dm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"

	"example.com/netlib"
	"example.com/netlib/fhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/mediaproxy"
)

type Connector struct {
	client *netlib.Client
	http   *http.Client
	fhttp  *fhttp.Client
}

var _ bridgev2.DirectMediableNetwork = (*Connector)(nil)

func (c *Connector) GetLoginFlows() []bridgev2.LoginFlow { return nil }
func (c *Connector) CreateLogin(ctx context.Context, user any, flowID string) (bridgev2.LoginProcess, error) {
	return nil, nil
}
func (c *Connector) SetUseDirectMedia() {}

func (c *Connector) Download(ctx context.Context, mediaID string, params map[string]string) (mediaproxy.GetMediaResponse, error) {
	switch mediaID {
	case "emoji":
		return &mediaproxy.GetMediaResponseURL{URL: "https://example.com/emoji.png"}, nil
	case "":
		return nil, mediaproxy.ErrInvalidMediaIDSyntax
	case "deleted":
		return nil, fmt.Errorf("message not found")
	case "gone":
		return nil, mautrix.MNotFound.WithMessage("Media is no longer available")
	case "phone":
		return nil, mautrix.MNotFound.WithMessage("Phone did not respond in time").WithStatus(http.StatusGatewayTimeout).WithCanRetry(true)
	case "limited":
		return nil, mautrix.MLimitExceeded.WithMessage("Too many media requests")
	case "file":
		return &mediaproxy.GetMediaResponseFile{
			Callback: func(w *os.File) (*mediaproxy.FileMeta, error) {
				_, err := c.client.Lookup(ctx, mediaID)
				return nil, err
			},
		}, nil
	case "mapped":
		_, err := c.client.Lookup(ctx, mediaID)
		if err != nil {
			return nil, mapMediaError(err)
		}
	case "as":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		if errors.As(err, &apiErr) {
			return nil, mautrix.MForbidden.WithMessage("Not allowed to download this media")
		} else if err != nil {
			return nil, err
		}
	case "astype":
		_, err := c.client.Lookup(ctx, mediaID)
		if apiErr, ok := errors.AsType[*netlib.APIError](err); ok {
			return nil, mautrix.MUnknown.WithMessage("Upstream returned %d", apiErr.Code).WithStatus(http.StatusBadGateway).WithCanRetry(true)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to look up media: %w", err)
		}
	case "not-as":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		if !errors.As(err, &apiErr) {
			return nil, err
		}
		if apiErr.Code == http.StatusNotFound {
			return nil, mautrix.MNotFound.WithMessage("Media was deleted")
		}
		return nil, err // want `DM001: Download returns raw error from netlib.Lookup, and the media proxy sends it as 404`
	case "sentinel":
		_, err := c.client.Lookup(ctx, mediaID)
		if errors.Is(err, netlib.ErrUnauthorized) {
			return nil, mautrix.MForbidden.WithMessage("Not logged in")
		}
		return nil, err // want `DM001: Download returns raw error from netlib.Lookup`
	case "raw":
		_, err := c.client.Lookup(ctx, mediaID)
		if err != nil {
			return nil, err // want `DM001: Download returns raw error from netlib.Lookup`
		}
	case "wrapped":
		if _, err := c.client.Lookup(ctx, mediaID); err != nil {
			return nil, fmt.Errorf("failed to look up media: %w", err) // want `DM001: Download returns plain error "failed to look up media: %w" wrapping a raw netlib error`
		}
	case "helper":
		return c.fetch(ctx, mediaID) // want `DM001: Download returns raw error from netlib.Lookup \(via fetch at dm.go:\d+\)`
	case "http":
		return c.downloadHTTP(ctx, mediaID) // want `DM002: Download returns plain error "unexpected status %d" \(via downloadHTTP at dm.go:\d+\) built from an upstream status`
	case "fhttp":
		resp, err := c.fhttp.Do(&fhttp.Request{Method: http.MethodGet})
		if err != nil {
			return nil, err
		}
		return &mediaproxy.GetMediaResponseData{Reader: resp.Body}, nil
	case "reassigned":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		if errors.As(err, &apiErr) {
			return nil, mautrix.MForbidden.WithMessage("Not allowed to download this media")
		}
		_, err = c.client.Lookup(ctx, mediaID+"?refreshed")
		if err != nil {
			return nil, err // want `DM001: Download returns raw error from netlib.Lookup`
		}
	case "reassigned-else":
		_, err := c.client.Lookup(ctx, mediaID)
		if apiErr, ok := errors.AsType[*netlib.APIError](err); !ok {
			_, err = c.client.Lookup(ctx, mediaID+"?refreshed")
			return nil, err // want `DM001: Download returns raw error from netlib.Lookup`
		} else if apiErr.Code == http.StatusNotFound {
			return nil, mautrix.MNotFound.WithMessage("Media was deleted")
		}
	case "switch":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		switch {
		case err == nil:
		case errors.As(err, &apiErr):
			return nil, mautrix.MForbidden.WithMessage("Not allowed to download this media")
		default:
			return nil, err
		}
	case "switch-default-first":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		switch {
		default:
			return nil, err
		case errors.As(err, &apiErr):
			return nil, mautrix.MForbidden.WithMessage("Not allowed to download this media")
		case err == nil:
		}
	case "switch-negated":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		switch {
		case !errors.As(err, &apiErr):
			return nil, err
		case apiErr.Code == http.StatusNotFound:
			return nil, mautrix.MNotFound.WithMessage("Media was deleted")
		}
	case "switch-after":
		_, err := c.client.Lookup(ctx, mediaID)
		switch apiErr, ok := errors.AsType[*netlib.APIError](err); {
		case ok && apiErr.Code == http.StatusNotFound:
			return nil, mautrix.MNotFound.WithMessage("Media was deleted")
		case ok:
			return nil, mautrix.MUnknown.WithMessage("Upstream returned %d", apiErr.Code).WithStatus(http.StatusBadGateway).WithCanRetry(true)
		}
		if err != nil {
			return nil, err
		}
	case "switch-earlier-case":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		switch {
		case err == nil:
		case errors.Is(err, netlib.ErrUnauthorized):
			return nil, err // want `DM001: Download returns raw error from netlib.Lookup`
		case errors.As(err, &apiErr):
			return nil, mautrix.MForbidden.WithMessage("Not allowed to download this media")
		}
	case "switch-fallthrough":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		switch {
		case errors.As(err, &apiErr):
			fallthrough
		default:
			return nil, err // want `DM001: Download returns raw error from netlib.Lookup`
		}
	case "switch-reassigned":
		_, err := c.client.Lookup(ctx, mediaID)
		var apiErr *netlib.APIError
		switch {
		case errors.As(err, &apiErr):
			return nil, mautrix.MForbidden.WithMessage("Not allowed to download this media")
		case err != nil:
			_, err = c.client.Lookup(ctx, mediaID+"?refreshed")
			return nil, err // want `DM001: Download returns raw error from netlib.Lookup`
		}
	case "pointer":
		return nil, &mautrix.RespError{ErrCode: "M_NOT_FOUND", Err: "Media was deleted", StatusCode: http.StatusNotFound} // want `DM001: Download returns a \*mautrix.RespError, which the media proxy doesn't recognise as a RespError, so it sends it as 404; return a mautrix.RespError value`
	case "pointer-helper":
		return nil, gone() // want `DM001: Download returns a \*mautrix.RespError \(via gone at dm.go:\d+\), which the media proxy doesn't recognise`
	case "bridgev2":
		return nil, bridgev2.RespError(mautrix.MNotFound.WithMessage("Media was deleted"))
	case "bridgev2-pointer":
		return nil, &bridgev2.RespError{ErrCode: "M_NOT_FOUND", Err: "Media was deleted", StatusCode: http.StatusNotFound}
	}
	return nil, fmt.Errorf("unknown media ID")
}

func gone() error {
	return &mautrix.RespError{ErrCode: "M_NOT_FOUND", Err: "Media was deleted", StatusCode: http.StatusNotFound}
}

func (c *Connector) fetch(ctx context.Context, mediaID string) (mediaproxy.GetMediaResponse, error) {
	if _, err := c.client.Lookup(ctx, mediaID); err != nil {
		return nil, err
	}
	return &mediaproxy.GetMediaResponseURL{URL: "https://example.com/" + mediaID}, nil
}

func (c *Connector) downloadHTTP(ctx context.Context, url string) (mediaproxy.GetMediaResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	} else if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return &mediaproxy.GetMediaResponseData{Reader: resp.Body, ContentLength: resp.ContentLength}, nil
}

func mapMediaError(err error) error {
	var apiErr *netlib.APIError
	if errors.As(err, &apiErr) && apiErr.Code == http.StatusNotFound {
		return mautrix.MNotFound.WithMessage("Media was deleted")
	}
	return err
}
