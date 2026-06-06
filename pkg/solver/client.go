package solver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/L0ed0/datadome-solver/internal/builder"
	ddcrypto "github.com/L0ed0/datadome-solver/internal/crypto"
)

const (
	clientVersion = "5.7.0"
	defaultUA     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)

type Client struct {
	SiteURL  string
	ProxyURL string
	DDJSKey  string
	CID      string
	Profile  string
	TagsURL  string
	HTTP     *http.Client
}

type Result struct {
	Status int            `json:"status"`
	Cookie string         `json:"cookie"`
	Raw    map[string]any `json:"-"`
}

type Option func(*Client)

func WithProxy(proxyURL string) Option    { return func(c *Client) { c.ProxyURL = proxyURL } }
func WithDDJSKey(key string) Option       { return func(c *Client) { c.DDJSKey = key } }
func WithCID(cid string) Option           { return func(c *Client) { c.CID = cid } }
func WithProfile(profile string) Option   { return func(c *Client) { c.Profile = profile } }
func WithTagsURL(tagsURL string) Option   { return func(c *Client) { c.TagsURL = tagsURL } }
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.HTTP = h } }

func New(siteURL string, opts ...Option) (*Client, error) {
	if siteURL == "" {
		return nil, fmt.Errorf("solver: site URL is required")
	}
	if !strings.HasPrefix(siteURL, "http://") && !strings.HasPrefix(siteURL, "https://") {
		siteURL = "https://" + siteURL
	}
	u, err := url.Parse(siteURL)
	if err != nil {
		return nil, fmt.Errorf("solver: invalid site URL: %w", err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("solver: site URL must include a host")
	}

	c := &Client{
		SiteURL: strings.TrimSuffix(siteURL, "/") + "/",
		Profile: "chrome_win10",
	}
	for _, opt := range opts {
		opt(c)
	}
	if c.DDJSKey == "" {
		return nil, fmt.Errorf("solver: DDJSKey is required (use WithDDJSKey)")
	}
	if c.HTTP == nil {
		c.HTTP, err = newHTTPClient(c.ProxyURL)
		if err != nil {
			return nil, err
		}
	}
	return c, nil
}

func (c *Client) BuildPayload(serverHash *string, bpc int) []ddcrypto.Signal {
	return builder.BuildPayload(builder.Options{
		Profile:    c.Profile,
		URL:        c.SiteURL,
		ServerHash: serverHash,
		BPC:        bpc,
	})
}

func (c *Client) EncryptJSPL(signals []ddcrypto.Signal) (string, error) {
	return ddcrypto.Encrypt(signals, c.DDJSKey, c.CID, nil)
}

type SolveOptions struct {
	BPC           int
	JsType        string
	EventCounters string
}

func (c *Client) Solve(ctx context.Context) (*Result, error) {
	return c.SolveWith(ctx, SolveOptions{})
}

func (c *Client) SolveWith(ctx context.Context, opts SolveOptions) (*Result, error) {
	bpc := max(opts.BPC, 1)
	jsType := opts.JsType
	if jsType == "" {
		jsType = "ch"
	}
	eventCounters := opts.EventCounters
	if eventCounters == "" {
		eventCounters = "[]"
	}

	signals := c.BuildPayload(nil, bpc)
	jspl, err := c.EncryptJSPL(signals)
	if err != nil {
		return nil, fmt.Errorf("solver: encrypt: %w", err)
	}

	endpoint, origin, referer, err := c.endpoints()
	if err != nil {
		return nil, err
	}

	return c.postPayload(ctx, endpoint, origin, referer, jspl, jsType, eventCounters, c.CID)
}

func (c *Client) SolveTwoPhase(ctx context.Context, delay time.Duration, eventCounters string) (*Result, error) {
	signals := c.BuildPayload(nil, 1)

	endpoint, origin, referer, err := c.endpoints()
	if err != nil {
		return nil, err
	}

	jspl1, err := ddcrypto.Encrypt(signals, c.DDJSKey, c.CID, nil)
	if err != nil {
		return nil, fmt.Errorf("solver: encrypt phase1: %w", err)
	}

	result1, err := c.postPayload(ctx, endpoint, origin, referer, jspl1, "ch", "[]", c.CID)
	if err != nil {
		return nil, fmt.Errorf("solver: phase1: %w", err)
	}

	cid := extractCIDFromCookie(result1.Cookie)
	if cid == "" {
		return result1, fmt.Errorf("solver: could not extract CID from phase1 cookie")
	}
	fmt.Fprintf(os.Stderr, "phase1: status=%d cid=%s...\n", result1.Status, truncate(cid, 30))

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return result1, ctx.Err()
		}
	}

	for i := range signals {
		if signals[i].Key == "bpc" {
			signals[i].Value = 2
		}
		if signals[i].Key == "jset" {
			signals[i].Value = time.Now().UnixMilli() / 1000
		}
	}

	jspl2, err := ddcrypto.Encrypt(signals, c.DDJSKey, cid, nil)
	if err != nil {
		return nil, fmt.Errorf("solver: encrypt phase2: %w", err)
	}

	if eventCounters == "" {
		eventCounters = `{"mousemove":87,"pointermove":87,"click":4,"scroll":1,"touchstart":0,"touchend":0,"touchmove":0,"keydown":22,"keyup":21}`
	}

	result2, err := c.postPayload(ctx, endpoint, origin, referer, jspl2, "le", eventCounters, cid)
	if err != nil {
		return nil, fmt.Errorf("solver: phase2: %w", err)
	}
	fmt.Fprintf(os.Stderr, "phase2: status=%d\n", result2.Status)
	return result2, nil
}

func (c *Client) Verify(ctx context.Context, cookie string) (int, string, error) {
	return c.VerifyURL(ctx, cookie, c.SiteURL)
}

func (c *Client) VerifyURL(ctx context.Context, cookie, targetURL string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
	req.Header.Set("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("cache-control", "max-age=0")
	req.Header.Set("cookie", cookie)
	setChromeHeaders(req)
	req.Header.Set("sec-fetch-dest", "document")
	req.Header.Set("sec-fetch-mode", "navigate")
	req.Header.Set("sec-fetch-site", "none")
	req.Header.Set("sec-fetch-user", "?1")
	req.Header.Set("upgrade-insecure-requests", "1")
	req.Header.Set("user-agent", defaultUA)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("solver: verify failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), nil
}

func (c *Client) postPayload(ctx context.Context, endpoint, origin, referer, jspl, jsType, eventCounters, cid string) (*Result, error) {
	form := url.Values{}
	form.Set("jspl", jspl)
	form.Set("eventCounters", eventCounters)
	form.Set("jsType", jsType)
	form.Set("cid", cid)
	form.Set("ddk", c.DDJSKey)
	form.Set("Referer", url.QueryEscape(c.SiteURL))
	form.Set("request", "%2F")
	form.Set("responsePage", "origin")
	form.Set("ddv", clientVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("accept", "*/*")
	req.Header.Set("accept-language", "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("downlink", "10")
	req.Header.Set("ect", "4g")
	req.Header.Set("origin", origin)
	req.Header.Set("priority", "u=1, i")
	req.Header.Set("referer", referer)
	req.Header.Set("rtt", "0")
	setChromeHeaders(req)
	req.Header.Set("sec-fetch-dest", "empty")
	req.Header.Set("sec-fetch-mode", "cors")
	req.Header.Set("sec-fetch-site", "cross-site")
	req.Header.Set("user-agent", defaultUA)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("solver: request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("solver: invalid JSON (%d): %s", resp.StatusCode, truncate(string(body), 200))
	}

	result := &Result{Raw: raw}
	if st, ok := raw["status"].(float64); ok {
		result.Status = int(st)
	}
	if cookie, ok := raw["cookie"].(string); ok {
		result.Cookie = cookie
	}

	if result.Status != 200 {
		return result, fmt.Errorf("solver: solve failed (status %d)", result.Status)
	}
	return result, nil
}

func setChromeHeaders(req *http.Request) {
	req.Header.Set("dpr", "1")
	req.Header.Set("sec-ch-dpr", "1")
	req.Header.Set("sec-ch-ua", `"Google Chrome";v="149", "Chromium";v="149", "Not)A;Brand";v="24"`)
	req.Header.Set("sec-ch-ua-arch", `"x86"`)
	req.Header.Set("sec-ch-ua-bitness", `"64"`)
	req.Header.Set("sec-ch-ua-full-version-list", `"Google Chrome";v="149.0.7827.53", "Chromium";v="149.0.7827.53", "Not)A;Brand";v="24.0.0.0"`)
	req.Header.Set("sec-ch-ua-mobile", "?0")
	req.Header.Set("sec-ch-ua-platform", `"Windows"`)
	req.Header.Set("sec-ch-ua-platform-version", `"14.0.0"`)
}

func (c *Client) endpoints() (tagsEndpoint, origin, referer string, err error) {
	u, err := url.Parse(c.SiteURL)
	if err != nil {
		return "", "", "", err
	}
	origin = u.Scheme + "://" + u.Host
	referer = c.SiteURL
	if c.TagsURL != "" {
		tagsEndpoint = c.TagsURL
	} else {
		tagsEndpoint = "https://api-js.datadome.co/js/"
	}
	return tagsEndpoint, origin, referer, nil
}

func extractCIDFromCookie(cookieHeader string) string {
	parts := strings.SplitN(cookieHeader, "=", 2)
	if len(parts) < 2 {
		return cookieHeader
	}
	val := parts[1]
	if idx := strings.Index(val, ";"); idx >= 0 {
		val = val[:idx]
	}
	return val
}

func newHTTPClient(proxyURL string) (*http.Client, error) {
	ct, err := newChromeTransport(proxyURL)
	if err != nil {
		return nil, err
	}
	return &http.Client{
		Timeout:   30 * time.Second,
		Transport: ct,
	}, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
