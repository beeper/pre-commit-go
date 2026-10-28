package dmold

import (
	"context"
	"net/http"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/mediaproxy"
)

type Connector struct{ http *http.Client }

var _ bridgev2.DirectMediableNetwork = (*Connector)(nil)

func (c *Connector) GetLoginFlows() []bridgev2.LoginFlow { return nil }
func (c *Connector) CreateLogin(ctx context.Context, user any, flowID string) (bridgev2.LoginProcess, error) {
	return nil, nil
}
func (c *Connector) SetUseDirectMedia() {}

func (c *Connector) Download(ctx context.Context, mediaID string, params map[string]string) (mediaproxy.GetMediaResponse, error) {
	switch mediaID {
	case "gone":
		return nil, mautrix.MNotFound.WithMessage("Media was deleted")
	case "bridgev2":
		return nil, bridgev2.RespError(mautrix.MNotFound.WithMessage("Media was deleted")) // want `DM001: Download returns a bridgev2.RespError, which the pinned mautrix \(before v0.32.0\) doesn't recognise as a RespError, so it sends it as 404`
	case "bridgev2-helper":
		return nil, notFound() // want `DM001: Download returns a bridgev2.RespError \(via notFound at dmold.go:\d+\), which the pinned mautrix \(before v0.32.0\) doesn't recognise`
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com/"+mediaID, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err // want `DM001: Download returns raw error from http.Do, and the pinned mautrix \(before v0.32.0\) sends every error that isn't a mautrix.RespError as 404, transport errors included`
	}
	return &mediaproxy.GetMediaResponseData{Reader: resp.Body}, nil
}

func notFound() error {
	return bridgev2.WrapRespErr(context.Canceled, mautrix.MNotFound)
}
