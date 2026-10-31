// Package halosapi is a small typed client for the slice of the halo-server
// HTTP API (/api/v1) that the Terraform provider uses.
//
// It never logs or returns a credential: every error message and every log
// field passes through redaction first.
package halosapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// DefaultTimeout is the per-request timeout when Config.Timeout is zero.
	DefaultTimeout = 30 * time.Second
	// MaxTimeout bounds Config.Timeout.
	MaxTimeout = 10 * time.Minute

	maxResponseBytes = 32 << 20
	maxErrorBytes    = 4 << 10
	sessionCookie    = "halo_session"
)

// ErrSessionRequired is returned, before any request is made, by calls that
// halo-server only accepts from an interactive session (ADR-0036: a token
// cannot mint its successor).
var ErrSessionRequired = errors.New("this call needs an interactive admin session: set the provider's session argument (or HALO_SESSION); a service-account token cannot create service tokens")

// Config configures a Client. Endpoint and at least one of Token and Session
// are required.
type Config struct {
	// Endpoint is the halo-server base URL: https, or http for a loopback host.
	Endpoint string
	// Token is a service-account token ("halo_sat_..."), sent as a bearer.
	Token string
	// Session is a halo_session cookie value, sent as a cookie. Only needed
	// for CreateServiceToken.
	Session string
	// CABundlePEM, when set, replaces the system roots for TLS verification.
	CABundlePEM []byte
	// Timeout bounds each request; zero means DefaultTimeout.
	Timeout time.Duration
	// UserAgent is sent on every request.
	UserAgent string
	// Logger, when set, receives one debug line per request (method, path,
	// status, duration; never headers or bodies).
	Logger func(ctx context.Context, msg string, fields map[string]any)
	// HTTPClient replaces the transport, for tests. Its CheckRedirect is
	// overridden.
	HTTPClient *http.Client
}

// Client talks to one halo-server.
type Client struct {
	base    *url.URL
	token   string
	session string
	ua      string
	hc      *http.Client
	log     func(ctx context.Context, msg string, fields map[string]any)
}

// ValidateEndpoint parses raw and enforces the transport rule: https, or
// http only when the host is loopback (localhost, 127.0.0.0/8, ::1). Userinfo,
// query strings and fragments are refused (credentials never go in a URL).
func ValidateEndpoint(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("endpoint is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		// url.Error repeats the input, which could hold userinfo.
		return nil, errors.New("endpoint is not a valid URL")
	}
	switch {
	case u.Scheme != "https" && u.Scheme != "http":
		return nil, fmt.Errorf("endpoint scheme must be https (or http for a loopback host), got %q", u.Scheme)
	case u.Hostname() == "":
		return nil, errors.New("endpoint has no host")
	case u.User != nil:
		return nil, errors.New("endpoint must not contain credentials")
	case u.RawQuery != "" || u.Fragment != "":
		return nil, errors.New("endpoint must not contain a query or fragment")
	case u.Scheme == "http" && !isLoopback(u.Hostname()):
		return nil, fmt.Errorf("endpoint must use https unless the host is loopback, got http for host %q", u.Hostname())
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return u, nil
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// New validates cfg and returns a Client.
func New(cfg Config) (*Client, error) {
	base, err := ValidateEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if cfg.Token == "" && cfg.Session == "" {
		return nil, errors.New("a token (or a session) is required")
	}
	timeout := cfg.Timeout
	switch {
	case timeout == 0:
		timeout = DefaultTimeout
	case timeout < 0 || timeout > MaxTimeout:
		return nil, fmt.Errorf("timeout must be between 1ns and %s", MaxTimeout)
	}
	hc := cfg.HTTPClient
	if hc == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		if len(cfg.CABundlePEM) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(cfg.CABundlePEM) {
				return nil, errors.New("ca bundle contains no PEM certificate")
			}
			tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
		}
		hc = &http.Client{Transport: tr}
	} else {
		cp := *hc
		hc = &cp
	}
	hc.Timeout = timeout
	// A redirect would carry the credential to another host: never follow one.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	ua := cfg.UserAgent
	if ua == "" {
		ua = "terraform-provider-halos"
	}
	return &Client{base: base, token: cfg.Token, session: cfg.Session, ua: ua, hc: hc, log: cfg.Logger}, nil
}

type authKind int

const (
	authAny     authKind = iota // bearer token if set, else the session cookie
	authSession                 // the session cookie only
)

var secretShape = regexp.MustCompile(`halo_sat_[A-Za-z0-9._~+/=-]+`)

// redact removes the client's credentials, and anything shaped like a service
// token, from s.
func (c *Client) redact(s string) string {
	for _, secret := range []string{c.token, c.session} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	return secretShape.ReplaceAllString(s, "[redacted]")
}

// APIError is a non-2xx answer from halo-server.
type APIError struct {
	Method  string
	Path    string
	Status  int
	Message string // the server's "error" text, redacted and truncated
}

func (e *APIError) Error() string {
	return fmt.Sprintf("%s %s: HTTP %d: %s", e.Method, e.Path, e.Status, e.Message)
}

// IsStatus reports whether err is an APIError with the given HTTP status.
func IsStatus(err error, status int) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == status
}

func (c *Client) do(ctx context.Context, method, path string, auth authKind, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encode %s %s request: %w", method, path, err)
		}
		body = bytes.NewReader(b)
	}
	u := *c.base
	u.Path += path
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("build %s %s request: %w", method, path, err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.ua)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	switch {
	case auth == authSession:
		if c.session == "" {
			return ErrSessionRequired
		}
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.session}) //nolint:gosec // a request cookie, not a Set-Cookie: Secure/HttpOnly/SameSite do not apply
	case c.token != "":
		req.Header.Set("Authorization", "Bearer "+c.token)
	default:
		req.AddCookie(&http.Cookie{Name: sessionCookie, Value: c.session}) //nolint:gosec // a request cookie, not a Set-Cookie: Secure/HttpOnly/SameSite do not apply
	}

	start := time.Now()
	resp, err := c.hc.Do(req)
	if err != nil {
		// Do the redaction on the text only: *url.Error carries the URL, never headers.
		return fmt.Errorf("%s %s: %s", method, path, c.redact(transportReason(err)))
	}
	defer func() { _ = resp.Body.Close() }()
	if c.log != nil {
		c.log(ctx, "halos request", map[string]any{
			"method": method, "path": path, "status": resp.StatusCode, "duration_ms": time.Since(start).Milliseconds(),
		})
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBytes))
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Message: c.redact(errorText(raw, resp))}
	}
	if out == nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return nil
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := dec.Decode(out); err != nil {
		// The body may hold a secret (the create response): never quote it.
		return fmt.Errorf("%s %s: decode response (HTTP %d): %s", method, path, resp.StatusCode, jsonErrKind(err))
	}
	return nil
}

func transportReason(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	return err.Error()
}

func jsonErrKind(err error) string {
	var se *json.SyntaxError
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &se):
		return "invalid JSON"
	case errors.As(err, &te):
		return fmt.Sprintf("field %q has the wrong type", te.Field)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "empty or truncated body"
	}
	return "unexpected body"
}

func errorText(raw []byte, resp *http.Response) string {
	var e struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		if len(e.Error) > 512 {
			return e.Error[:512] + "..."
		}
		return e.Error
	}
	return http.StatusText(resp.StatusCode)
}
