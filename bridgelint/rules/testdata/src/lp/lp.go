package lp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"

	"example.com/netlib"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/bridgev2"
)

type Client struct{ client *netlib.Client }

var _ bridgev2.IdentifierResolvingNetworkAPI = (*Client)(nil)

func (c *Client) Connect(ctx context.Context)      {}
func (c *Client) Disconnect()                      {}
func (c *Client) IsLoggedIn() bool                 { return true }
func (c *Client) LogoutRemote(ctx context.Context) { c.client.Disconnect() }
func (c *Client) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	return nil, bridgev2.ErrUnsupportedMessageType
}

func (c *Client) ResolveIdentifier(ctx context.Context, identifier string, createChat bool) (*bridgev2.ResolveIdentifierResponse, error) {
	if identifier == "" {
		return nil, fmt.Errorf("invalid identifier")
	}
	if identifier == "bad" {
		return nil, bridgev2.RespError(mautrix.MInvalidParam.WithMessage("invalid identifier"))
	}
	_, err := c.client.Lookup(ctx, identifier)
	if err != nil {
		zlog.Err(err).Msg("lookup failed")
	}
	_, err = c.client.Lookup(ctx, identifier)
	if err != nil {
		return nil, bridgev2.WrapRespErr(err, mautrix.MNotFound)
	}
	_, err = c.client.Lookup(ctx, identifier)
	if err != nil {
		return nil, err // want `LP001: ResolveIdentifier returns raw error from netlib.Lookup`
	}
	return &bridgev2.ResolveIdentifierResponse{}, nil
}

type Connector struct{}

var _ bridgev2.NetworkConnector = (*Connector)(nil)

func (c *Connector) GetLoginFlows() []bridgev2.LoginFlow { return nil }
func (c *Connector) CreateLogin(ctx context.Context, user any, flowID string) (bridgev2.LoginProcess, error) {
	switch flowID {
	case "nested":
		if c == nil {
			return nil, errors.New("connector is missing")
		}
		return &TokenLogin{}, nil
	case "token":
		return &TokenLogin{}, nil
	default:
		return nil, errors.New("this login isn't available") // want `LP001: CreateLogin returns plain error "this login isn't available"`
	}
}

type TokenLogin struct{}

var _ bridgev2.LoginProcessUserInput = (*TokenLogin)(nil)

var tokenRegex = regexp.MustCompile(`^xox[a-z]-.+$`)

var tokenField = bridgev2.LoginInputDataField{ID: "token", Name: "Token", Pattern: `^xox[a-z]-.+$`}

func (t *TokenLogin) Start(ctx context.Context) (*bridgev2.LoginStep, error) { return nil, nil }
func (t *TokenLogin) Cancel()                                                {}
func (t *TokenLogin) SubmitUserInput(ctx context.Context, input map[string]string) (*bridgev2.LoginStep, error) {
	if !tokenRegex.MatchString(input["token"]) { // want `LP008: this check duplicates the Pattern on the login field`
		return nil, ErrInvalidToken
	}
	return nil, nil
}

var (
	ErrInvalidToken  = bridgev2.RespError{ErrCode: "FI.MAU.EX.INVALID_TOKEN", Err: "Invalid token", StatusCode: http.StatusBadRequest}
	ErrRateLimited   = bridgev2.RespError{ErrCode: "FI.MAU.EX.RATE_LIMITED", Err: "Too many requests", StatusCode: http.StatusTooManyRequests} // want `LP002: RespError is sent as HTTP 429`
	ErrRateLimitedOK = bridgev2.RespError{ErrCode: "FI.MAU.EX.RATE_LIMITED", Err: "Too many requests", StatusCode: http.StatusBadRequest}
	ErrNoStatus      = bridgev2.RespError{ErrCode: "FI.MAU.EX.CAPTCHA", Err: "Captcha required"}                                                  // want `LP005: RespError literal without StatusCode`
	ErrOutage        = bridgev2.RespError{ErrCode: "FI.MAU.EX.TEMPORARY_FAILURE", Err: "Server error", StatusCode: http.StatusServiceUnavailable} // want `LP002: RespError is sent as HTTP 503`
	ErrUpstream      = bridgev2.RespError(mautrix.MUnknown.WithMessage("Upstream failed").WithStatus(502))                                        // want `LP002: RespError is sent as HTTP 502`
	ErrUpstreamOK    = bridgev2.RespError(mautrix.MUnknown.WithMessage("Upstream failed"))
	ErrPhoneTimeout  = mautrix.MNotFound.WithMessage("Phone did not respond").WithStatus(http.StatusGatewayTimeout).WithCanRetry(true)
	ErrLimit         = mautrix.RespError{ErrCode: "M_LIMIT_EXCEEDED", Err: "Slow down", StatusCode: http.StatusBadRequest} // want `LP007: RespError literal for M_LIMIT_EXCEEDED`
	ErrForbidden     = bridgev2.RespError{ErrCode: mautrix.MForbidden.ErrCode, Err: "Not allowed", StatusCode: 403}        // want `LP007: RespError literal for M_FORBIDDEN`
	ErrLockedOut     = bridgev2.RespError{ErrCode: "FI.MAU.EX.LOCKED", Err: "Too many incorrect attempts, temporarily locked", StatusCode: 403}
	ErrLimit2        = mautrix.MLimitExceeded.WithStatus(429)                              // want `LP002: RespError is sent as HTTP 429`
	ErrLimit3        = bridgev2.RespError(mautrix.MLimitExceeded.WithMessage("Slow down")) // want `LP002: mautrix.MLimitExceeded is sent as HTTP 429 by default`
	ErrLimit4        = mautrix.MLimitExceeded.WithMessage("Slow down").WithStatus(http.StatusBadRequest)
)

func isLimit(err error) bool { return errors.Is(err, mautrix.MLimitExceeded) }

func passthrough(code int, err error) error {
	te := struct{ Code int }{code}
	return bridgev2.RespError{ErrCode: "FI.MAU.EX.UPSTREAM", Err: "upstream", StatusCode: te.Code} // want `LP004: HTTP status copied from a network error code`
}

type logger struct{}
type logEvent struct{}

func (logger) Err(err error) *logEvent { return &logEvent{} }
func (*logEvent) Msg(msg string)       {}

var zlog logger
