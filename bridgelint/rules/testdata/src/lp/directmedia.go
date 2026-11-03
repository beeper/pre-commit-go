package lp

import (
	"context"
	"net/http"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/mediaproxy"
)

type MediaConnector struct{ Connector }

var _ bridgev2.DirectMediableNetwork = (*MediaConnector)(nil)

func (m *MediaConnector) SetUseDirectMedia() {}

func (m *MediaConnector) Download(ctx context.Context, mediaID string, params map[string]string) (mediaproxy.GetMediaResponse, error) {
	switch mediaID {
	case "limited":
		return nil, mautrix.MLimitExceeded.WithMessage("Too many media requests")
	case "upstream":
		return nil, mautrix.MUnknown.WithMessage("Upstream failed").WithStatus(http.StatusBadGateway)
	case "not-ready":
		return nil, errMediaNotReady
	case "phone":
		return nil, errPhoneTimeout
	case "shared":
		return nil, errSharedTimeout
	}
	return nil, upstreamMediaError()
}

func upstreamMediaError() error {
	return mautrix.MUnknown.WithMessage("Upstream failed").WithStatus(http.StatusBadGateway) // want `LP002: RespError is sent as HTTP 502`
}

var errMediaNotReady = mautrix.RespError{ErrCode: "M_NOT_YET_UPLOADED", Err: "Not connected right now", StatusCode: http.StatusGatewayTimeout}

var errPhoneTimeout = mautrix.MUnknown.WithMessage("Phone did not respond").WithStatus(http.StatusGatewayTimeout)

var errSharedTimeout = mautrix.MUnknown.WithMessage("Phone did not respond").WithStatus(http.StatusGatewayTimeout) // want `LP002: RespError is sent as HTTP 504`

func (c *Connector) loginTimeout() error {
	return errSharedTimeout
}
