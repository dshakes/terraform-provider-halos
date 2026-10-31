package provider

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/dshakes/terraform-provider-halos/internal/halosapi"
)

func testResource(t *testing.T, f *fakeHalo, token, session string) *serviceTokenResource {
	t.Helper()
	c, err := halosapi.New(halosapi.Config{Endpoint: f.srv.URL, Token: token, Session: session})
	if err != nil {
		t.Fatal(err)
	}
	return &serviceTokenResource{client: c}
}

func resourceSchema(t *testing.T) resource.SchemaResponse {
	t.Helper()
	var resp resource.SchemaResponse
	NewServiceTokenResource().Schema(context.Background(), resource.SchemaRequest{}, &resp)
	if d := resp.Schema.ValidateImplementation(context.Background()); d.HasError() {
		t.Fatalf("schema invalid: %s", diagText(d))
	}
	return resp
}

func nullScope() types.Object { return types.ObjectNull(scopeAttrTypes) }

func ringScope(t *testing.T, rings ...string) types.Object {
	t.Helper()
	elems := make([]attr.Value, len(rings))
	for i, r := range rings {
		elems[i] = types.StringValue(r)
	}
	set, d := types.SetValue(types.StringType, elems)
	if d.HasError() {
		t.Fatal(diagText(d))
	}
	o, d := types.ObjectValue(scopeAttrTypes, map[string]attr.Value{"rings": set, "units": types.SetNull(types.StringType)})
	if d.HasError() {
		t.Fatal(diagText(d))
	}
	return o
}

func plannedModel(name, role string) serviceTokenModel {
	return serviceTokenModel{
		ID: types.StringUnknown(), Name: types.StringValue(name), Role: types.StringValue(role), TTL: types.StringUnknown(),
		Owner: types.StringNull(), Description: types.StringNull(), Scope: nullScope(), Token: types.StringUnknown(),
		Principal: types.StringUnknown(), CreatedBy: types.StringUnknown(), CreatedAt: types.StringUnknown(), ExpiresAt: types.StringUnknown(),
	}
}

func create(t *testing.T, r *serviceTokenResource, m serviceTokenModel) (serviceTokenModel, diag.Diagnostics) {
	t.Helper()
	ctx := context.Background()
	s := resourceSchema(t).Schema
	raw := tftypes.NewValue(s.Type().TerraformType(ctx), nil)
	plan := tfsdk.Plan{Schema: s, Raw: raw}
	if d := plan.Set(ctx, &m); d.HasError() {
		t.Fatal(diagText(d))
	}
	resp := resource.CreateResponse{State: tfsdk.State{Schema: s, Raw: raw}}
	r.Create(ctx, resource.CreateRequest{Plan: plan}, &resp)
	var out serviceTokenModel
	if !resp.Diagnostics.HasError() {
		if d := resp.State.Get(ctx, &out); d.HasError() {
			t.Fatal(diagText(d))
		}
	}
	return out, resp.Diagnostics
}

func stateOf(t *testing.T, m serviceTokenModel) tfsdk.State {
	t.Helper()
	ctx := context.Background()
	s := resourceSchema(t).Schema
	st := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	if d := st.Set(ctx, &m); d.HasError() {
		t.Fatal(diagText(d))
	}
	return st
}

func read(t *testing.T, r *serviceTokenResource, m serviceTokenModel) (*serviceTokenModel, diag.Diagnostics) {
	t.Helper()
	ctx := context.Background()
	resp := resource.ReadResponse{State: stateOf(t, m)}
	r.Read(ctx, resource.ReadRequest{State: stateOf(t, m)}, &resp)
	if resp.State.Raw.IsNull() {
		return nil, resp.Diagnostics
	}
	var out serviceTokenModel
	if d := resp.State.Get(ctx, &out); d.HasError() {
		t.Fatal(diagText(d))
	}
	return &out, resp.Diagnostics
}

func TestCreateStoresSecretAndComputedFields(t *testing.T) {
	f := newFakeHalo(t)
	r := testResource(t, f, fakeToken, fakeSession)
	m := plannedModel("ci-reporter", "viewer")
	m.TTL = types.StringValue("720h")
	m.Owner = types.StringValue("platform")
	m.Scope = ringScope(t, "ring1-canary")
	got, diags := create(t, r, m)
	if diags.HasError() {
		t.Fatal(diagText(diags))
	}
	if !strings.HasPrefix(got.Token.ValueString(), "halo_sat_") || got.ID.ValueString() == "" {
		t.Fatalf("token/id not stored: %+v", got)
	}
	if got.Principal.ValueString() != "service-account:ci-reporter:"+got.ID.ValueString() {
		t.Errorf("principal = %q", got.Principal.ValueString())
	}
	if got.TTL.ValueString() != "720h" || got.Owner.ValueString() != "platform" {
		t.Errorf("ttl = %q owner = %q", got.TTL.ValueString(), got.Owner.ValueString())
	}
	if got.Scope.IsNull() {
		t.Error("scope lost")
	}
	// The wire body had exactly the keys set in the plan.
	body := string(f.bodies[0])
	if body != `{"name":"ci-reporter","role":"viewer","ttl":"720h","owner":"platform","scope":{"rings":["ring1-canary"]}}` {
		t.Errorf("body = %s", body)
	}
}

func TestCreateDefaultTTLIsReadBack(t *testing.T) {
	f := newFakeHalo(t)
	got, diags := create(t, testResource(t, f, fakeToken, fakeSession), plannedModel("a", "viewer"))
	if diags.HasError() {
		t.Fatal(diagText(diags))
	}
	if got.TTL.ValueString() != "2160h" {
		t.Errorf("ttl = %q, want the server default 2160h", got.TTL.ValueString())
	}
	if strings.Contains(string(f.bodies[0]), "ttl") || strings.Contains(string(f.bodies[0]), "scope") {
		t.Errorf("unset optional keys were sent: %s", f.bodies[0])
	}
}

func TestCreateErrorMapping(t *testing.T) {
	tests := []struct {
		name        string
		model       func() serviceTokenModel
		token       string
		session     string
		failure     int
		wantSummary string
	}{
		{"token only cannot create", func() serviceTokenModel { return plannedModel("a", "viewer") }, fakeToken, "", 0, "Error creating"},
		{"401 bad session", func() serviceTokenModel { return plannedModel("a", "viewer") }, "", "wrong-session", 0, "Authentication failed"},
		{"403", func() serviceTokenModel { return plannedModel("a", "viewer") }, "", fakeSession, 403, "Permission denied"},
		{"404", func() serviceTokenModel { return plannedModel("a", "viewer") }, "", fakeSession, 404, "Not found"},
		{"409 limit", func() serviceTokenModel { return plannedModel("dup-limit", "viewer") }, "", fakeSession, 0, "Conflict"},
		{"422", func() serviceTokenModel { return plannedModel("unprocessable", "viewer") }, "", fakeSession, 0, "Invalid request"},
		{"400 ttl", func() serviceTokenModel { m := plannedModel("a", "viewer"); m.TTL = types.StringValue("1m"); return m }, "", fakeSession, 0, "Invalid request"},
		{"500", func() serviceTokenModel { return plannedModel("a", "viewer") }, "", fakeSession, 500, "halo-server error"},
		{"503", func() serviceTokenModel { return plannedModel("a", "viewer") }, "", fakeSession, 503, "unavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeHalo(t)
			if tc.failure != 0 {
				f.setFailure("POST /api/v1/service-tokens", tc.failure)
			}
			_, diags := create(t, testResource(t, f, tc.token, tc.session), tc.model())
			if !diags.HasError() {
				t.Fatal("expected an error")
			}
			text := diagText(diags)
			if !strings.Contains(text, tc.wantSummary) {
				t.Errorf("diagnostics %q lack %q", text, tc.wantSummary)
			}
			for _, secret := range []string{"TOKENSECRETVALUE", "SESSIONSECRETVALUE", "wrong-session"} {
				if strings.Contains(text, secret) {
					t.Errorf("diagnostics leak %q: %s", secret, text)
				}
			}
			if tc.token != "" && tc.session == "" && len(f.callList()) != 0 {
				t.Errorf("a token-only create reached the server: %v", f.callList())
			}
		})
	}
}

func TestReadRefreshBehaviour(t *testing.T) {
	f := newFakeHalo(t)
	r := testResource(t, f, fakeToken, "")
	cr := testResource(t, f, "", fakeSession)
	created, diags := create(t, cr, plannedModel("a", "operator"))
	if diags.HasError() {
		t.Fatal(diagText(diags))
	}

	t.Run("live token is kept and the secret survives", func(t *testing.T) {
		got, diags := read(t, r, created)
		if diags.HasError() || got == nil {
			t.Fatalf("got %v, %s", got, diagText(diags))
		}
		if got.Token != created.Token {
			t.Error("refresh lost the secret")
		}
		if got.TTL != created.TTL {
			t.Errorf("ttl changed on refresh: %q -> %q", created.TTL.ValueString(), got.TTL.ValueString())
		}
	})
	t.Run("revoked out of band is removed from state", func(t *testing.T) {
		f.revokeOutOfBand(created.ID.ValueString())
		got, diags := read(t, r, created)
		if diags.HasError() {
			t.Fatal(diagText(diags))
		}
		if got != nil {
			t.Fatalf("revoked token stayed in state: %+v", got)
		}
	})
	t.Run("missing from the list is removed from state", func(t *testing.T) {
		g := newFakeHalo(t)
		c2, _ := create(t, testResource(t, g, "", fakeSession), plannedModel("b", "viewer"))
		g.removeOutOfBand(c2.ID.ValueString())
		got, diags := read(t, testResource(t, g, fakeToken, ""), c2)
		if diags.HasError() || got != nil {
			t.Fatalf("got %v, %s", got, diagText(diags))
		}
	})
	t.Run("list failure is an error, not a removal", func(t *testing.T) {
		g := newFakeHalo(t)
		c3, _ := create(t, testResource(t, g, "", fakeSession), plannedModel("c", "viewer"))
		g.setFailure("GET /api/v1/service-tokens", 503)
		got, diags := read(t, testResource(t, g, fakeToken, ""), c3)
		if !diags.HasError() || got != nil && got.ID.IsNull() {
			t.Fatalf("a transient failure must not drop state: got %v diags %s", got, diagText(diags))
		}
		if !strings.Contains(diagText(diags), "unavailable") {
			t.Errorf("diags = %s", diagText(diags))
		}
	})
	t.Run("import shape: only the id is known", func(t *testing.T) {
		g := newFakeHalo(t)
		c4, _ := create(t, testResource(t, g, "", fakeSession), func() serviceTokenModel {
			m := plannedModel("d", "viewer")
			m.Scope = ringScope(t, "ring1-canary")
			m.Owner = types.StringValue("platform")
			return m
		}())
		imp := serviceTokenModel{
			ID: c4.ID, Name: types.StringNull(), Role: types.StringNull(), TTL: types.StringNull(), Owner: types.StringNull(),
			Description: types.StringNull(), Scope: nullScope(), Token: types.StringNull(), Principal: types.StringNull(),
			CreatedBy: types.StringNull(), CreatedAt: types.StringNull(), ExpiresAt: types.StringNull(),
		}
		got, diags := read(t, testResource(t, g, fakeToken, ""), imp)
		if diags.HasError() || got == nil {
			t.Fatalf("got %v, %s", got, diagText(diags))
		}
		if !got.Token.IsNull() {
			t.Error("an imported token must have no secret")
		}
		if got.Name.ValueString() != "d" || got.Role.ValueString() != "viewer" || got.Owner.ValueString() != "platform" ||
			got.TTL.ValueString() != "2160h" || got.Scope.IsNull() {
			t.Errorf("import did not fill the attributes: %+v", got)
		}
	})
}

func TestDeleteRevokes(t *testing.T) {
	tests := []struct {
		name      string
		prep      func(f *fakeHalo, id string)
		wantError string
	}{
		{"revokes", func(*fakeHalo, string) {}, ""},
		{"already gone is success", func(f *fakeHalo, id string) { f.removeOutOfBand(id) }, ""},
		{"403 is an error", func(f *fakeHalo, _ string) { f.setFailure("POST /api/v1/service-tokens/0000000000000001/revoke", 403) }, "Permission denied"},
		{"503 is an error", func(f *fakeHalo, _ string) { f.setFailure("POST /api/v1/service-tokens/0000000000000001/revoke", 503) }, "unavailable"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeHalo(t)
			created, diags := create(t, testResource(t, f, "", fakeSession), plannedModel("a", "viewer"))
			if diags.HasError() {
				t.Fatal(diagText(diags))
			}
			tc.prep(f, created.ID.ValueString())
			r := testResource(t, f, fakeToken, "")
			resp := resource.DeleteResponse{State: stateOf(t, created)}
			r.Delete(context.Background(), resource.DeleteRequest{State: stateOf(t, created)}, &resp)
			text := diagText(resp.Diagnostics)
			if tc.wantError == "" {
				if resp.Diagnostics.HasError() {
					t.Fatal(text)
				}
			} else if !strings.Contains(text, tc.wantError) {
				t.Fatalf("diagnostics %q lack %q", text, tc.wantError)
			}
			wantCall := "POST /api/v1/service-tokens/" + created.ID.ValueString() + "/revoke"
			if !contains(f.callList(), wantCall) {
				t.Fatalf("revoke endpoint not called: %v", f.callList())
			}
			if tc.name == "revokes" {
				got, _ := f.revoked(created.ID.ValueString())
				if !got {
					t.Fatal("token still active on the server after Delete")
				}
			}
		})
	}
}

func (f *fakeHalo) revoked(id string) (bool, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tokens {
		if t.ID == id {
			return t.Revoked, true
		}
	}
	return false, false
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestCanonicalTTL(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{720 * time.Hour, "720h"}, {time.Hour, "1h"}, {90 * time.Minute, "90m"}, {90 * time.Second, "90s"}, {2160 * time.Hour, "2160h"},
	}
	for _, tc := range tests {
		if got := canonicalTTL(tc.d); got != tc.want {
			t.Errorf("canonicalTTL(%s) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestOptionalTextKeepsConfiguredWhitespace(t *testing.T) {
	if got := optionalText(types.StringValue("  platform "), "platform"); got.ValueString() != "  platform " {
		t.Errorf("got %q: a refresh would show a diff the server cannot satisfy", got.ValueString())
	}
	if got := optionalText(types.StringNull(), ""); !got.IsNull() {
		t.Error("empty server value must read back as null")
	}
	if got := optionalText(types.StringValue("a"), "b"); got.ValueString() != "b" {
		t.Error("real drift must be reported")
	}
}
