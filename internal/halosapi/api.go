package halosapi

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"
)

// RoleScope bounds a role to rings and units (ADR-0037). The zero value is
// global.
type RoleScope struct {
	Rings []string `json:"rings,omitempty"`
	Units []string `json:"units,omitempty"`
}

// Global reports whether the scope names nothing.
func (s RoleScope) Global() bool { return len(s.Rings) == 0 && len(s.Units) == 0 }

// CreateServiceTokenRequest is the POST /api/v1/service-tokens body. The
// server decodes it strictly (exact keys, each once), so this struct is the
// whole wire shape: optional keys are omitted, never sent empty, and Scope is
// a pointer so an absent scope is absent rather than "{}" (which the server
// refuses).
type CreateServiceTokenRequest struct {
	Name        string     `json:"name"`
	Role        string     `json:"role"`
	TTL         string     `json:"ttl,omitempty"`
	Owner       string     `json:"owner,omitempty"`
	Description string     `json:"description,omitempty"`
	Scope       *RoleScope `json:"scope,omitempty"`
}

// ServiceToken is a service-account token as listed: never the secret.
type ServiceToken struct {
	ID           string    `json:"id"`
	Principal    string    `json:"principal"`
	Name         string    `json:"name"`
	Description  string    `json:"description,omitempty"`
	Owner        string    `json:"owner,omitempty"`
	Role         string    `json:"role"`
	Scope        RoleScope `json:"scope"`
	CreatedBy    string    `json:"createdBy"`
	CreatedAt    time.Time `json:"createdAt"`
	ExpiresAt    time.Time `json:"expiresAt"`
	Expired      bool      `json:"expired"`
	Revoked      bool      `json:"revoked"`
	RevokedAt    time.Time `json:"revokedAt,omitempty"`
	RevokedBy    string    `json:"revokedBy,omitempty"`
	RevokeReason string    `json:"revokeReason,omitempty"`
}

// CreateServiceTokenResponse carries the secret, which is shown once.
type CreateServiceTokenResponse struct {
	Token        string       `json:"token"`
	ServiceToken ServiceToken `json:"serviceToken"`
}

// CreateServiceToken mints a token. It needs an interactive session (see
// ErrSessionRequired) and is not retried: a retry could mint a second token.
func (c *Client) CreateServiceToken(ctx context.Context, in CreateServiceTokenRequest) (*CreateServiceTokenResponse, error) {
	var out CreateServiceTokenResponse
	if err := c.do(ctx, http.MethodPost, "/api/v1/service-tokens", authSession, in, &out); err != nil {
		return nil, err
	}
	if out.Token == "" || out.ServiceToken.ID == "" {
		return nil, errors.New("POST /api/v1/service-tokens: response has no token or id")
	}
	return &out, nil
}

// ListServiceTokens returns every token, revoked ones included.
func (c *Client) ListServiceTokens(ctx context.Context) ([]ServiceToken, error) {
	var out struct {
		Tokens []ServiceToken `json:"tokens"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/service-tokens", authAny, nil, &out); err != nil {
		return nil, err
	}
	return out.Tokens, nil
}

// GetServiceToken finds one token by id in the list (the API has no
// get-by-id). It returns (nil, nil) when no such token is listed.
func (c *Client) GetServiceToken(ctx context.Context, id string) (*ServiceToken, error) {
	all, err := c.ListServiceTokens(ctx)
	if err != nil {
		return nil, err
	}
	for i := range all {
		if all[i].ID == id {
			return &all[i], nil
		}
	}
	return nil, nil
}

// RevokeServiceToken revokes a token; reason is required by the server.
func (c *Client) RevokeServiceToken(ctx context.Context, id, reason string) error {
	if id == "" {
		return errors.New("revoke service token: empty id")
	}
	body := struct {
		Reason string `json:"reason"`
	}{reason}
	return c.do(ctx, http.MethodPost, "/api/v1/service-tokens/"+url.PathEscape(id)+"/revoke", authAny, body, nil)
}

// Grant is one role binding of the caller.
type Grant struct {
	Role   string    `json:"role"`
	Scope  RoleScope `json:"scope"`
	Source string    `json:"source"`
}

// Me is GET /api/v1/me.
type Me struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Admin       bool     `json:"admin"`
	Groups      []string `json:"groups"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Bindings    []Grant  `json:"bindings"`
	Ring        string   `json:"ring"`
}

// GetMe returns the caller.
func (c *Client) GetMe(ctx context.Context) (*Me, error) {
	var out Me
	if err := c.do(ctx, http.MethodGet, "/api/v1/me", authAny, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Capabilities is GET /api/v1/capabilities.
type Capabilities struct {
	KillSwitch  bool     `json:"killSwitch"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
	Bindings    []Grant  `json:"bindings"`
}

// GetCapabilities returns the optional features and the caller's permissions.
func (c *Client) GetCapabilities(ctx context.Context) (*Capabilities, error) {
	var out Capabilities
	if err := c.do(ctx, http.MethodGet, "/api/v1/capabilities", authAny, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Convergence is how many reporting devices are on a ring's digest.
type Convergence struct {
	Total    int `json:"total"`
	OnDigest int `json:"onDigest"`
	Other    int `json:"other"`
}

// RingRelease is one ring's pointer, convergence and drift.
type RingRelease struct {
	Ring        string      `json:"ring"`
	Published   bool        `json:"published"`
	Digest      string      `json:"digest"`
	Seq         int64       `json:"seq"`
	Expired     bool        `json:"expired"`
	ExpiresAt   *time.Time  `json:"expiresAt"`
	Stale       bool        `json:"stale"`
	Suspicious  bool        `json:"suspicious"`
	Error       string      `json:"error"`
	DriftHosts  int         `json:"driftHosts"`
	Convergence Convergence `json:"convergence"`
}

// Releases is GET /api/v1/releases.
type Releases struct {
	Registry string        `json:"registry"`
	Stale    bool          `json:"stale"`
	Rings    []RingRelease `json:"rings"`
}

// GetReleases returns the ring pointers.
func (c *Client) GetReleases(ctx context.Context) (*Releases, error) {
	var out Releases
	if err := c.do(ctx, http.MethodGet, "/api/v1/releases", authAny, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Experiment is the summary of one experiment.
type Experiment struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Axis   string   `json:"axis"`
	Status string   `json:"status"`
	Rings  []string `json:"rings"`
}

// ListExperiments returns every experiment.
func (c *Client) ListExperiments(ctx context.Context) ([]Experiment, error) {
	var out []Experiment
	if err := c.do(ctx, http.MethodGet, "/api/v1/experiments", authAny, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Rollout is the summary of one rollout: its timeline header and, when the
// controller has started it, its state.
type Rollout struct {
	Timeline struct {
		Rollout    string `json:"rollout"`
		Axis       string `json:"axis"`
		Status     string `json:"status"`
		Experiment string `json:"experiment"`
	} `json:"timeline"`
	State *struct {
		Step       int    `json:"step"`
		StepName   string `json:"stepName"`
		Halted     string `json:"halted"`
		HaltReason string `json:"haltReason"`
	} `json:"state"`
}

// ListRollouts returns every rollout.
func (c *Client) ListRollouts(ctx context.Context) ([]Rollout, error) {
	var out []Rollout
	if err := c.do(ctx, http.MethodGet, "/api/v1/rollouts", authAny, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// KillRecord is one entry of the kill list.
type KillRecord struct {
	Experiment string    `json:"experiment"`
	Killed     bool      `json:"killed"`
	By         string    `json:"by"`
	At         time.Time `json:"at"`
	Reason     string    `json:"reason"`
}

// Kills is GET /api/v1/killswitch.
type Kills struct {
	Version int64        `json:"version"`
	Killed  []KillRecord `json:"killed"`
}

// GetKills returns the kill list. Read only: this client never kills.
func (c *Client) GetKills(ctx context.Context) (*Kills, error) {
	var out Kills
	if err := c.do(ctx, http.MethodGet, "/api/v1/killswitch", authAny, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// RingStats is per-ring fleet statistics.
type RingStats struct {
	Ring       string  `json:"ring"`
	Hosts      int     `json:"hosts"`
	Percent    float64 `json:"percent"`
	DriftHosts int     `json:"driftHosts"`
}

// Fleet is GET /api/v1/fleet without the per-host rows.
type Fleet struct {
	Total      int         `json:"total"`
	DriftHosts int         `json:"driftHosts"`
	Rings      []RingStats `json:"rings"`
}

// GetFleet returns per-ring statistics. The per-host rows are not decoded.
func (c *Client) GetFleet(ctx context.Context) (*Fleet, error) {
	var out Fleet
	if err := c.do(ctx, http.MethodGet, "/api/v1/fleet", authAny, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
