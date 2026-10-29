package gr

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"example.com/netlib"
	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/bridgev2"
	"maunium.net/go/mautrix/event"
)

type Client struct {
	client  *netlib.Client
	br      *bridgev2.Bridge
	login   *bridgev2.UserLogin
	meta    *Meta
	cache   map[string]string
	pending map[string]bool

	reconnectAttempts int
}

type Meta struct {
	Cursor     string
	LastPts    int
	LastSeq    int
	Subsequent bool
}

var _ bridgev2.NetworkAPI = (*Client)(nil)

var sharedCaps = map[string]bool{}

// A map whose values synchronise themselves is still one map shared by every login.
var sharedCounts = map[string]*atomic.Int64{}

var (
	sharedState sync.Map
	sharedMu    sync.Mutex
)

var httpClient = &http.Client{Timeout: 10 * time.Second}

func (c *Client) Connect(ctx context.Context) {}
func (c *Client) Disconnect()                 { c.client.Disconnect() }
func (c *Client) IsLoggedIn() bool            { return true }
func (c *Client) LogoutRemote(ctx context.Context) { // want `GR013: LogoutRemote doesn't disconnect the client`
	c.meta = nil
}
func (c *Client) HandleMatrixMessage(ctx context.Context, msg *bridgev2.MatrixMessage) (*bridgev2.MatrixMessageResponse, error) {
	return nil, nil
}

func (c *Client) fetch(ctx context.Context) error {
	resp, err := http.Get("https://example.com") // want `GR002: http.Get uses DefaultClient` `GR001: resp.Body is never closed`
	if err != nil {
		return err
	}
	_ = resp.StatusCode
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
	resp2, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp2.Body.Close()
	_, _ = http.NewRequest(http.MethodGet, "https://example.com", nil) // want `GR002: http.NewRequest has no context`
	_ = http.DefaultClient
	_ = &http.Client{}
	return nil
}

func (c *Client) retry(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com", bytes.NewReader(body))
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		resp, err := httpClient.Do(req) // want `GR003: req is built once with a body and re-sent in a loop`
		if err == nil {
			resp.Body.Close()
			return nil
		}
	}
	return nil
}

func (c *Client) die(err error) {
	if err != nil {
		os.Exit(1) // want `GR004: os.Exit in connector or library code`
	}
	panic("unreachable")
}

func (c *Client) logAndDie(log zerolog.Logger, err error) {
	log.Fatal().Err(err).Msg("Giving up") // want `GR004: zerolog Fatal\(\) exits the process`
	log.Error().Err(err).Msg("Carrying on")
}

// retryReplayable sets GetBody, so the body survives a retry and GR003 stays quiet.
func (c *Client) retryReplayable(ctx context.Context, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://example.com", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	for i := 0; i < 3; i++ {
		resp, err := httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			return nil
		}
	}
	return nil
}

func MustParse(s string) string {
	if s == "" {
		panic("empty")
	}
	return s
}

func (c *Client) sync(ctx context.Context) {
	items, _ := c.client.Poll(ctx)
	for _, item := range items {
		c.br.QueueRemoteEvent(c.login, item)
	}
	c.meta.Cursor = "next" // want `GR008: Cursor is saved after queueing remote events`
	c.meta.LastPts = 5     // want `GR008: LastPts is saved after queueing remote events`
	c.reconnectAttempts = 0
	c.meta.LastSeq = 1 // want `GR008: LastSeq is saved after queueing remote events`
	c.meta.Subsequent = true
}

func (c *Client) remember(k string) {
	sharedCaps[k] = true              // want `GR009: package-level sharedCaps is written at runtime`
	sharedCounts[k] = &atomic.Int64{} // want `GR009: package-level sharedCounts is written at runtime`
	sharedState.Store(k, true)
	sharedMu.Lock()
	defer sharedMu.Unlock()
	c.cache[k] = "v"
	c.pending[k] = true
	delete(c.pending, k)
}

func (c *Client) GetCapabilities(ctx context.Context, isDM bool) *event.RoomFeatures {
	caps := &event.RoomFeatures{ID: "com.example.capabilities.v1", MaxTextSize: 4000}
	if isDM {
		caps.Edit = 1 // want `GR011: GetCapabilities changes Edit but keeps the same RoomFeatures.ID`
	}
	return caps
}

type apiRequest struct{ c *http.Client }

func (a *apiRequest) Do(ctx context.Context) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.com", nil)
	if err != nil {
		return nil, err
	}
	resp, err := a.c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return resp, nil
}

func headerFromWrapper(ctx context.Context, a *apiRequest) string {
	resp, err := a.Do(ctx)
	if err != nil {
		return ""
	}
	return resp.Header.Get("X-ID")
}
