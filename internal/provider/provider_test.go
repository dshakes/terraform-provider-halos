package provider

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/dshakes/terraform-provider-halos/internal/halosapi"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func noFile(string) ([]byte, error) { return nil, errors.New("no files in this test") }

func diagText(d diag.Diagnostics) string {
	var sb strings.Builder
	for _, x := range d {
		sb.WriteString(x.Summary() + "\n" + x.Detail() + "\n")
	}
	return sb.String()
}

func TestResolveConfig(t *testing.T) {
	str := types.StringValue
	null := types.StringNull()
	tests := []struct {
		name     string
		model    providerModel
		env      map[string]string
		wantErr  []string // substrings across all diagnostics; none means success
		wantSess bool
	}{
		{
			name:  "arguments only",
			model: providerModel{Endpoint: str("https://halos.example.com"), Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: null},
		},
		{
			name:  "environment only",
			model: providerModel{Endpoint: null, Token: null, Session: null, CABundleFile: null, Timeout: null},
			env:   map[string]string{"HALO_SERVER": "https://halos.example.com", "HALO_TOKEN": fakeToken},
		},
		{
			name:  "argument beats environment",
			model: providerModel{Endpoint: str("https://a.example.com"), Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: null},
			env:   map[string]string{"HALO_SERVER": "http://insecure.example.com", "HALO_TOKEN": "other"},
		},
		{
			name:     "session satisfies the credential rule",
			model:    providerModel{Endpoint: str("https://halos.example.com"), Token: null, Session: null, CABundleFile: null, Timeout: null},
			env:      map[string]string{"HALO_SESSION": fakeSession},
			wantSess: true,
		},
		{
			name:  "http loopback is allowed",
			model: providerModel{Endpoint: str("http://127.0.0.1:8080"), Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: str("5s")},
		},
		{
			name:    "http remote is refused",
			model:   providerModel{Endpoint: str("http://halos.example.com"), Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: null},
			wantErr: []string{"Invalid halo-server endpoint", "must use https unless the host is loopback"},
		},
		{
			name:    "http remote from the environment is refused",
			model:   providerModel{Endpoint: null, Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: null},
			env:     map[string]string{"HALO_SERVER": "http://halos.example.com"},
			wantErr: []string{"must use https"},
		},
		{
			name:    "missing endpoint",
			model:   providerModel{Endpoint: null, Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: null},
			wantErr: []string{"Missing halo-server endpoint", "HALO_SERVER"},
		},
		{
			name:    "missing token",
			model:   providerModel{Endpoint: str("https://halos.example.com"), Token: null, Session: null, CABundleFile: null, Timeout: null},
			wantErr: []string{"Missing halo-server token", "HALO_TOKEN"},
		},
		{
			name:    "empty token argument is missing",
			model:   providerModel{Endpoint: str("https://halos.example.com"), Token: str(""), Session: null, CABundleFile: null, Timeout: null},
			wantErr: []string{"Missing halo-server token"},
		},
		{
			name:    "credentials in the endpoint are refused and not echoed",
			model:   providerModel{Endpoint: str("https://u:" + fakeToken + "@halos.example.com"), Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: null},
			wantErr: []string{"must not contain credentials"},
		},
		{
			name:    "bad timeout",
			model:   providerModel{Endpoint: str("https://halos.example.com"), Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: str("soon")},
			wantErr: []string{"Invalid timeout"},
		},
		{
			name:    "zero timeout",
			model:   providerModel{Endpoint: str("https://halos.example.com"), Token: str(fakeToken), Session: null, CABundleFile: null, Timeout: str("0s")},
			wantErr: []string{"Invalid timeout"},
		},
		{
			name:    "unreadable CA bundle",
			model:   providerModel{Endpoint: str("https://halos.example.com"), Token: str(fakeToken), Session: null, CABundleFile: str("/nope/ca.pem"), Timeout: null},
			wantErr: []string{"Cannot read CA bundle"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, diags := resolveConfig(tc.model, env(tc.env), noFile)
			text := diagText(diags)
			for _, secret := range []string{"TOKENSECRETVALUE", "SESSIONSECRETVALUE"} {
				if strings.Contains(text, secret) {
					t.Fatalf("diagnostics echo a credential: %s", text)
				}
			}
			if len(tc.wantErr) == 0 {
				if diags.HasError() {
					t.Fatalf("unexpected diagnostics: %s", text)
				}
				if tc.wantSess && cfg.Session == "" {
					t.Fatal("session not picked up from the environment")
				}
				return
			}
			if !diags.HasError() {
				t.Fatalf("expected an error containing %v", tc.wantErr)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(text, want) {
					t.Errorf("diagnostics %q lack %q", text, want)
				}
			}
		})
	}
}

func TestResolveConfigReadsCABundle(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(p, []byte("PEM"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, diags := resolveConfig(providerModel{Endpoint: types.StringValue("https://h.example"), Token: types.StringValue(fakeToken), Session: types.StringNull(), CABundleFile: types.StringNull(), Timeout: types.StringNull()},
		env(map[string]string{"HALO_CA_BUNDLE_FILE": p}), os.ReadFile)
	if diags.HasError() || string(cfg.CABundlePEM) != "PEM" {
		t.Fatalf("cfg.CABundlePEM = %q, diags = %s", cfg.CABundlePEM, diagText(diags))
	}
}

func TestAPIDiagMapping(t *testing.T) {
	mk := func(status int) error {
		return &halosapi.APIError{Method: "POST", Path: "/api/v1/service-tokens", Status: status, Message: "boom [redacted]"}
	}
	tests := []struct {
		name        string
		err         error
		wantSummary string
		wantDetail  string
	}{
		{"400", mk(400), "Invalid request while creating", "rejected the arguments"},
		{"401", mk(401), "Authentication failed while creating", "HALO_TOKEN"},
		{"403", mk(403), "Permission denied while creating", "admin"},
		{"404", mk(404), "Not found while creating", "no such resource"},
		{"409", mk(409), "Conflict while creating", "1,000 active token limit"},
		{"422", mk(422), "Invalid request while creating", "boom"},
		{"429", mk(429), "Rate limited while creating", "wait and retry"},
		{"500", mk(500), "halo-server error while creating", "HTTP 500"},
		{"503", mk(503), "unavailable while creating", "retry"},
		{"session required", halosapi.ErrSessionRequired, "Error creating", "interactive admin session"},
		{"plain error", errors.New("dial tcp: refused"), "Error creating", "refused"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := apiDiag("creating the service token", tc.err)
			if d.Severity() != diag.SeverityError {
				t.Fatalf("severity = %v", d.Severity())
			}
			if !strings.Contains(d.Summary(), tc.wantSummary) {
				t.Errorf("summary %q lacks %q", d.Summary(), tc.wantSummary)
			}
			if !strings.Contains(d.Detail(), tc.wantDetail) {
				t.Errorf("detail %q lacks %q", d.Detail(), tc.wantDetail)
			}
		})
	}
}
