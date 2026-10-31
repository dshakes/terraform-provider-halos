package provider

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	fakeToken   = "halo_sat_feedfacefeedface.TOKENSECRETVALUE"
	fakeSession = "SESSIONSECRETVALUE"
)

// fakeHalo is a small stand-in for halo-server's service-token API. It
// enforces what the real one does that matters here: strict create bodies, a
// session (not a token) to create, and revoke by id.
type fakeHalo struct {
	mu      sync.Mutex
	srv     *httptest.Server
	tokens  []fakeTok
	nextID  int
	failure map[string]int // "METHOD /path" -> status to answer instead
	calls   []string
	bodies  [][]byte
}

type fakeTok struct {
	ID, Name, Role, Owner, Description string
	Rings, Units                       []string
	Created, Expires                   time.Time
	Revoked                            bool
}

func newFakeHalo(t *testing.T) *fakeHalo {
	t.Helper()
	f := &fakeHalo{failure: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHalo) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeHalo) setFailure(route string, status int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failure[route] = status
}

func (f *fakeHalo) revokeOutOfBand(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.tokens {
		if f.tokens[i].ID == id {
			f.tokens[i].Revoked = true
		}
	}
}

func (f *fakeHalo) removeOutOfBand(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.tokens {
		if f.tokens[i].ID == id {
			f.tokens = append(f.tokens[:i], f.tokens[i+1:]...)
			return
		}
	}
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeHalo) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	route := r.Method + " " + r.URL.Path
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, route)
	f.bodies = append(f.bodies, body)
	if st, ok := f.failure[route]; ok {
		// Reflect the credentials, as a hostile proxy might.
		reply(w, st, map[string]string{"error": fmt.Sprintf("injected %d (%s %s)", st, fakeToken, fakeSession)})
		return
	}
	authed := r.Header.Get("Authorization") == "Bearer "+fakeToken
	session := false
	if c, err := r.Cookie("halo_session"); err == nil && c.Value == fakeSession {
		session = true
	}
	if !authed && !session {
		reply(w, 401, map[string]string{"error": "login required"})
		return
	}
	switch {
	case route == "POST /api/v1/service-tokens":
		if authed { // ADR-0036: a token cannot mint its successor
			reply(w, 403, map[string]string{"error": "service tokens are created from an interactive admin session, not a service-account"})
			return
		}
		f.create(w, body)
	case route == "GET /api/v1/service-tokens":
		out := []map[string]any{}
		for _, t := range f.tokens {
			out = append(out, tokJSON(t))
		}
		reply(w, 200, map[string]any{"tokens": out})
	case r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/api/v1/service-tokens/") && strings.HasSuffix(r.URL.Path, "/revoke"):
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/service-tokens/"), "/revoke")
		var in struct {
			Reason string `json:"reason"`
		}
		if json.Unmarshal(body, &in) != nil || strings.TrimSpace(in.Reason) == "" {
			reply(w, 400, map[string]string{"error": "reason required"})
			return
		}
		for i := range f.tokens {
			if f.tokens[i].ID == id {
				f.tokens[i].Revoked = true
				reply(w, 200, tokJSON(f.tokens[i]))
				return
			}
		}
		reply(w, 404, map[string]string{"error": "service token not found"})
	case route == "GET /api/v1/me":
		reply(w, 200, map[string]any{"id": "service-account:ci:1", "kind": "service-account", "admin": false, "groups": []string{}, "roles": []string{"viewer"}, "permissions": []string{"read"}, "ring": "ring3-ga"})
	default:
		reply(w, 404, map[string]string{"error": "no such route"})
	}
}

func (f *fakeHalo) create(w http.ResponseWriter, body []byte) {
	// Strict decode, as the real server: exact keys, each once.
	dec := json.NewDecoder(bytes.NewReader(body))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		reply(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	seen := map[string]bool{}
	for dec.More() {
		kt, _ := dec.Token()
		k := kt.(string)
		switch k {
		case "name", "role", "scope", "description", "owner", "ttl":
		default:
			reply(w, 400, map[string]string{"error": fmt.Sprintf("invalid request: unknown field %q", k)})
			return
		}
		if seen[k] {
			reply(w, 400, map[string]string{"error": "invalid request: field given twice"})
			return
		}
		seen[k] = true
		var v json.RawMessage
		_ = dec.Decode(&v)
	}
	var in struct {
		Name, Role, TTL, Owner, Description string
		Scope                               *struct{ Rings, Units []string }
	}
	if err := json.Unmarshal(body, &in); err != nil {
		reply(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	if in.Scope != nil && len(in.Scope.Rings) == 0 && len(in.Scope.Units) == 0 {
		reply(w, 400, map[string]string{"error": "scope names no ring or unit: omit it for a global token"})
		return
	}
	ttl := 90 * 24 * time.Hour
	if in.TTL != "" {
		d, err := time.ParseDuration(in.TTL)
		if err != nil {
			reply(w, 400, map[string]string{"error": "ttl must be a duration such as 720h"})
			return
		}
		ttl = d
	}
	if ttl < time.Hour {
		reply(w, 400, map[string]string{"error": "ttl must be between 1h0m0s and 2160h0m0s"})
		return
	}
	if in.Name == "dup-limit" {
		reply(w, 409, map[string]string{"error": "1000 service tokens are active (the limit): revoke unused ones first"})
		return
	}
	if in.Name == "unprocessable" {
		reply(w, 422, map[string]string{"error": "cannot process"})
		return
	}
	f.nextID++
	now := time.Now().UTC().Truncate(time.Second)
	t := fakeTok{ID: fmt.Sprintf("%016x", f.nextID), Name: in.Name, Role: in.Role, Owner: strings.TrimSpace(in.Owner), Description: strings.TrimSpace(in.Description), Created: now, Expires: now.Add(ttl)}
	if in.Scope != nil {
		t.Rings, t.Units = in.Scope.Rings, in.Scope.Units
	}
	f.tokens = append(f.tokens, t)
	reply(w, 201, map[string]any{"token": "halo_sat_" + t.ID + ".NEWSECRET" + t.ID, "serviceToken": tokJSON(t)})
}

func tokJSON(t fakeTok) map[string]any {
	scope := map[string]any{}
	if len(t.Rings) > 0 {
		scope["rings"] = t.Rings
	}
	if len(t.Units) > 0 {
		scope["units"] = t.Units
	}
	m := map[string]any{
		"id": t.ID, "principal": "service-account:" + t.Name + ":" + t.ID, "name": t.Name, "role": t.Role, "scope": scope,
		"createdBy": "boss@acme.example", "createdAt": t.Created.Format(time.RFC3339Nano), "expiresAt": t.Expires.Format(time.RFC3339Nano),
		"expired": false, "revoked": t.Revoked,
	}
	if t.Owner != "" {
		m["owner"] = t.Owner
	}
	if t.Description != "" {
		m["description"] = t.Description
	}
	return m
}
