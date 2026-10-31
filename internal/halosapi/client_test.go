package halosapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testToken   = "halo_sat_0123456789abcdef.SECRETSECRETSECRET"
	testSession = "sealed-session-cookie-value-xyz"
)

func TestValidateEndpoint(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr string // substring; "" means valid
	}{
		{"https", "https://halos.example.com", ""},
		{"https with port and path", "https://halos.example.com:8443/prefix/", ""},
		{"http localhost", "http://localhost:8080", ""},
		{"http Localhost mixed case", "http://LocalHost:8080", ""},
		{"http 127.0.0.1", "http://127.0.0.1:8080", ""},
		{"http 127.0.0.2", "http://127.0.0.2", ""},
		{"http ipv6 loopback", "http://[::1]:8080", ""},
		{"https loopback", "https://127.0.0.1:8443", ""},
		{"http remote host", "http://halos.example.com", "must use https unless the host is loopback"},
		{"http remote ip", "http://10.0.0.5:8080", "must use https unless the host is loopback"},
		{"http lookalike", "http://localhost.evil.example", "must use https unless the host is loopback"},
		{"http 127 lookalike", "http://127.0.0.1.evil.example", "must use https unless the host is loopback"},
		{"ftp", "ftp://halos.example.com", "scheme must be https"},
		{"no scheme", "halos.example.com", "scheme must be https"},
		{"empty", "  ", "endpoint is empty"},
		{"no host", "https://", "no host"},
		{"userinfo", "https://user:" + testToken + "@halos.example.com", "must not contain credentials"},
		{"query", "https://halos.example.com?x=1", "query or fragment"},
		{"fragment", "https://halos.example.com#x", "query or fragment"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := ValidateEndpoint(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if strings.HasSuffix(u.Path, "/") {
					t.Fatalf("trailing slash kept: %q", u.Path)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("error echoes the credential: %v", err)
			}
		})
	}
}

func TestNewValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr string
	}{
		{"ok token", Config{Endpoint: "https://h.example", Token: testToken}, ""},
		{"ok session", Config{Endpoint: "https://h.example", Session: testSession}, ""},
		{"no credential", Config{Endpoint: "https://h.example"}, "token"},
		{"http remote", Config{Endpoint: "http://h.example", Token: testToken}, "https"},
		{"negative timeout", Config{Endpoint: "https://h.example", Token: testToken, Timeout: -1}, "timeout"},
		{"huge timeout", Config{Endpoint: "https://h.example", Token: testToken, Timeout: time.Hour}, "timeout"},
		{"bad ca", Config{Endpoint: "https://h.example", Token: testToken, CABundlePEM: []byte("not pem")}, "no PEM"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}

// recorder is a fake halo-server handler that records requests.
type recorder struct {
	mu   sync.Mutex
	reqs []recorded
	h    http.HandlerFunc
}

type recorded struct {
	Method, Path, Auth, Cookie, ContentType string
	Body                                    []byte
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	b, _ := io.ReadAll(req.Body)
	c := ""
	if ck, err := req.Cookie("halo_session"); err == nil {
		c = ck.Value
	}
	r.mu.Lock()
	r.reqs = append(r.reqs, recorded{req.Method, req.URL.Path, req.Header.Get("Authorization"), c, req.Header.Get("Content-Type"), b})
	r.mu.Unlock()
	req.Body = io.NopCloser(bytes.NewReader(b))
	r.h(w, req)
}

func (r *recorder) all() []recorded {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]recorded(nil), r.reqs...)
}

func newTestClient(t *testing.T, h http.HandlerFunc, mod func(*Config)) (*Client, *recorder) {
	t.Helper()
	rec := &recorder{h: h}
	srv := httptest.NewServer(rec)
	t.Cleanup(srv.Close)
	cfg := Config{Endpoint: srv.URL, Token: testToken, Session: testSession}
	if mod != nil {
		mod(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return c, rec
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func TestAuthSelection(t *testing.T) {
	ok := func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]any{"tokens": []any{}}) }
	t.Run("token wins for reads", func(t *testing.T) {
		c, rec := newTestClient(t, ok, nil)
		if _, err := c.ListServiceTokens(context.Background()); err != nil {
			t.Fatal(err)
		}
		got := rec.all()[0]
		if got.Auth != "Bearer "+testToken || got.Cookie != "" {
			t.Fatalf("auth = %q cookie = %q", got.Auth, got.Cookie)
		}
	})
	t.Run("session only falls back to the cookie", func(t *testing.T) {
		c, rec := newTestClient(t, ok, func(c *Config) { c.Token = "" })
		if _, err := c.ListServiceTokens(context.Background()); err != nil {
			t.Fatal(err)
		}
		got := rec.all()[0]
		if got.Auth != "" || got.Cookie != testSession {
			t.Fatalf("auth = %q cookie = %q", got.Auth, got.Cookie)
		}
	})
	t.Run("create sends the cookie and no bearer", func(t *testing.T) {
		c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, 201, CreateServiceTokenResponse{Token: "halo_sat_new.secret", ServiceToken: ServiceToken{ID: "abc"}})
		}, nil)
		if _, err := c.CreateServiceToken(context.Background(), CreateServiceTokenRequest{Name: "a", Role: "viewer"}); err != nil {
			t.Fatal(err)
		}
		got := rec.all()[0]
		if got.Auth != "" || got.Cookie != testSession {
			t.Fatalf("auth = %q cookie = %q", got.Auth, got.Cookie)
		}
	})
	t.Run("create without a session fails before any request", func(t *testing.T) {
		c, rec := newTestClient(t, ok, func(c *Config) { c.Session = "" })
		_, err := c.CreateServiceToken(context.Background(), CreateServiceTokenRequest{Name: "a", Role: "viewer"})
		if !errors.Is(err, ErrSessionRequired) {
			t.Fatalf("err = %v, want ErrSessionRequired", err)
		}
		if n := len(rec.all()); n != 0 {
			t.Fatalf("%d requests were made", n)
		}
	})
}

// serverKeys mirrors halo-server's exactKeys: only these keys, each once.
var serverKeys = []string{"name", "role", "scope", "description", "owner", "ttl"}

func topLevelKeys(t *testing.T, raw []byte) []string {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		t.Fatalf("body is not an object: %s", raw)
	}
	var keys []string
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, k.(string))
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(keys)
	return keys
}

func TestCreateRequestIsStrict(t *testing.T) {
	tests := []struct {
		name     string
		in       CreateServiceTokenRequest
		wantKeys []string
		wantBody string
	}{
		{
			name:     "minimal omits every optional key",
			in:       CreateServiceTokenRequest{Name: "ci", Role: "viewer"},
			wantKeys: []string{"name", "role"},
			wantBody: `{"name":"ci","role":"viewer"}`,
		},
		{
			name:     "rings only scope omits units",
			in:       CreateServiceTokenRequest{Name: "ci", Role: "operator", TTL: "720h", Scope: &RoleScope{Rings: []string{"ring1-canary"}}},
			wantKeys: []string{"name", "role", "scope", "ttl"},
			wantBody: `{"name":"ci","role":"operator","ttl":"720h","scope":{"rings":["ring1-canary"]}}`,
		},
		{
			name:     "everything",
			in:       CreateServiceTokenRequest{Name: "ci", Role: "admin", TTL: "2h", Owner: "platform", Description: "d", Scope: &RoleScope{Rings: []string{"r"}, Units: []string{"u"}}},
			wantKeys: []string{"description", "name", "owner", "role", "scope", "ttl"},
			wantBody: `{"name":"ci","role":"admin","ttl":"2h","owner":"platform","description":"d","scope":{"rings":["r"],"units":["u"]}}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, 201, CreateServiceTokenResponse{Token: "halo_sat_x.y", ServiceToken: ServiceToken{ID: "id1"}})
			}, nil)
			if _, err := c.CreateServiceToken(context.Background(), tc.in); err != nil {
				t.Fatal(err)
			}
			got := rec.all()[0]
			if got.Method != "POST" || got.Path != "/api/v1/service-tokens" || got.ContentType != "application/json" {
				t.Fatalf("request = %+v", got)
			}
			if string(got.Body) != tc.wantBody {
				t.Fatalf("body = %s\nwant   %s", got.Body, tc.wantBody)
			}
			keys := topLevelKeys(t, got.Body)
			if strings.Join(keys, ",") != strings.Join(tc.wantKeys, ",") {
				t.Fatalf("keys = %v, want %v", keys, tc.wantKeys)
			}
			for _, k := range keys {
				found := false
				for _, a := range serverKeys {
					found = found || a == k
				}
				if !found {
					t.Fatalf("key %q is not one halo-server accepts", k)
				}
			}
		})
	}
}

func TestStatusMapping(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 409, 422, 429, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, status, map[string]string{"error": "server says no"})
			}, nil)
			_, err := c.ListServiceTokens(context.Background())
			var ae *APIError
			if !errors.As(err, &ae) {
				t.Fatalf("err = %v, want *APIError", err)
			}
			if ae.Status != status || ae.Message != "server says no" || ae.Method != "GET" || ae.Path != "/api/v1/service-tokens" {
				t.Fatalf("APIError = %+v", ae)
			}
			if !IsStatus(err, status) || IsStatus(err, status+1) {
				t.Fatalf("IsStatus wrong for %d", status)
			}
		})
	}
	t.Run("non-JSON body falls back to the status text", func(t *testing.T) {
		c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "<html>proxy page</html>", http.StatusBadGateway)
		}, nil)
		_, err := c.GetMe(context.Background())
		var ae *APIError
		if !errors.As(err, &ae) || ae.Message != "Bad Gateway" {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestCredentialsNeverInErrorsOrLogs(t *testing.T) {
	var logs []string
	var logMu sync.Mutex
	logger := func(_ context.Context, msg string, f map[string]any) {
		logMu.Lock()
		defer logMu.Unlock()
		b, _ := json.Marshal(f)
		logs = append(logs, msg+" "+string(b))
	}
	secrets := []string{testToken, testSession, "halo_sat_deadbeef.otherSECRET"}
	hostile := func(w http.ResponseWriter, _ *http.Request) {
		// A misbehaving server or proxy that reflects the credentials.
		writeJSON(w, 401, map[string]string{"error": "bad credential " + testToken + " / " + testSession + " / " + secrets[2]})
	}
	c, _ := newTestClient(t, hostile, func(c *Config) { c.Logger = logger })
	_, listErr := c.ListServiceTokens(context.Background())
	_, createErr := c.CreateServiceToken(context.Background(), CreateServiceTokenRequest{Name: "a", Role: "viewer"})
	revokeErr := c.RevokeServiceToken(context.Background(), "abc", "r")

	// A transport error: connection refused to a closed server.
	dead := httptest.NewServer(http.NotFoundHandler())
	endpoint := dead.URL
	dead.Close()
	dc, err := New(Config{Endpoint: endpoint, Token: testToken, Session: testSession, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	_, transportErr := dc.GetMe(context.Background())

	// A success body that is not JSON but holds the secret.
	bad, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"token": "`+testToken+`", "serviceToken": "oops"`)
	}, nil)
	_, decodeErr := bad.CreateServiceToken(context.Background(), CreateServiceTokenRequest{Name: "a", Role: "viewer"})

	for name, err := range map[string]error{"list": listErr, "create": createErr, "revoke": revokeErr, "transport": transportErr, "decode": decodeErr} {
		if err == nil {
			t.Fatalf("%s: expected an error", name)
		}
		for _, s := range secrets {
			if strings.Contains(err.Error(), s) || strings.Contains(err.Error(), "SECRET") {
				t.Errorf("%s error leaks a credential: %v", name, err)
			}
		}
	}
	if !strings.Contains(listErr.Error(), "[redacted]") {
		t.Errorf("reflected credential was not marked redacted: %v", listErr)
	}
	logMu.Lock()
	defer logMu.Unlock()
	if len(logs) == 0 {
		t.Fatal("expected request log lines")
	}
	for _, l := range logs {
		for _, s := range secrets {
			if strings.Contains(l, s) || strings.Contains(l, "Bearer") {
				t.Errorf("log line leaks a credential: %s", l)
			}
		}
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	var otherHit bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHit = true
		w.WriteHeader(200)
	}))
	defer other.Close()
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/steal", http.StatusTemporaryRedirect)
	}, nil)
	_, err := c.ListServiceTokens(context.Background())
	if !IsStatus(err, http.StatusTemporaryRedirect) {
		t.Fatalf("err = %v, want the 307 surfaced", err)
	}
	if otherHit {
		t.Fatal("the client followed a redirect and would have sent the credential on")
	}
}

func TestContextCancellationAndTimeout(t *testing.T) {
	block := make(chan struct{})
	c, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) { <-block }, func(c *Config) { c.Timeout = 50 * time.Millisecond })
	t.Cleanup(func() { close(block) }) // runs before the server's Close, which waits for handlers
	start := time.Now()
	if _, err := c.GetMe(context.Background()); err == nil {
		t.Fatal("expected a timeout")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("timeout not honored")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c2, _ := newTestClient(t, func(http.ResponseWriter, *http.Request) {}, nil)
	if _, err := c2.GetMe(ctx); err == nil {
		t.Fatal("expected a canceled context to fail")
	}
}

func TestGetServiceTokenMatchesByID(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"tokens": []ServiceToken{{ID: "aaa", Name: "a"}, {ID: "bbb", Name: "b", Revoked: true}}})
	}, nil)
	got, err := c.GetServiceToken(context.Background(), "bbb")
	if err != nil || got == nil || got.Name != "b" || !got.Revoked {
		t.Fatalf("got %+v, %v", got, err)
	}
	got, err = c.GetServiceToken(context.Background(), "zzz")
	if err != nil || got != nil {
		t.Fatalf("missing id: got %+v, %v", got, err)
	}
}

func TestRevokeRequest(t *testing.T) {
	c, rec := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, ServiceToken{ID: "a/b", Revoked: true})
	}, nil)
	if err := c.RevokeServiceToken(context.Background(), "a/b", "rotated"); err != nil {
		t.Fatal(err)
	}
	got := rec.all()[0]
	if got.Method != "POST" || got.Path != "/api/v1/service-tokens/a/b/revoke" && got.Path != "/api/v1/service-tokens/a%2Fb/revoke" {
		t.Fatalf("path = %q", got.Path)
	}
	if string(got.Body) != `{"reason":"rotated"}` {
		t.Fatalf("body = %s", got.Body)
	}
	if err := c.RevokeServiceToken(context.Background(), "", "r"); err == nil {
		t.Fatal("empty id must fail")
	}
}
