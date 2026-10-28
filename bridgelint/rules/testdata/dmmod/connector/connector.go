package connector

import (
	"context"

	"example.com/dmmod/medialib"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/mediaproxy"
)

type Connector struct{ lib *medialib.Client }

var _ bridgev2.DirectMediableNetwork = (*Connector)(nil)

func (c *Connector) GetLoginFlows() []bridgev2.LoginFlow { return nil }
func (c *Connector) CreateLogin(ctx context.Context, user any, flowID string) (bridgev2.LoginProcess, error) {
	return nil, nil
}
func (c *Connector) SetUseDirectMedia() {}

func (c *Connector) Download(ctx context.Context, mediaID string, params map[string]string) (mediaproxy.GetMediaResponse, error) { // want Download:"raw .*callee=medialib.Thumbnail"
	key, err := medialib.ParseKey(mediaID)
	if err != nil {
		return nil, err
	}
	switch params["size"] {
	case "thumbnail":
		body, err := c.lib.Thumbnail(ctx, key)
		if err != nil {
			return nil, err // want `DM001: Download returns raw error from medialib.Thumbnail`
		}
		return &mediaproxy.GetMediaResponseData{Reader: body}, nil
	case "stream":
		body, err := c.lib.Stream(ctx, key)
		if err != nil {
			return nil, err
		}
		return &mediaproxy.GetMediaResponseData{Reader: body}, nil
	case "missing":
		return nil, medialib.Missing(key) // want `DM001: Download returns a \*mautrix.RespError \(via medialib.Missing at connector.go:\d+\), which the media proxy doesn't recognise`
	}
	body, err := c.lib.Download(ctx, key)
	if err != nil {
		return nil, err // want `DM001: Download returns raw error from medialib.Download`
	}
	return &mediaproxy.GetMediaResponseData{Reader: body}, nil
}
