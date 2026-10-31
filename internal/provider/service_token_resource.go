package provider

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"

	"github.com/dshakes/terraform-provider-halos/internal/halosapi"
)

var (
	_ resource.Resource                = (*serviceTokenResource)(nil)
	_ resource.ResourceWithConfigure   = (*serviceTokenResource)(nil)
	_ resource.ResourceWithImportState = (*serviceTokenResource)(nil)
)

// serviceTokenRoles are halo-server's roles (internal/server.Roles).
var serviceTokenRoles = []string{"viewer", "operator", "approver", "auditor", "admin"}

// minTokenTTL is halo-server's floor; the ceiling is --service-token-max-ttl
// (server side), so it is not checked here.
const minTokenTTL = time.Hour

// NewServiceTokenResource returns the halos_service_token resource.
func NewServiceTokenResource() resource.Resource { return &serviceTokenResource{} }

type serviceTokenResource struct{ client *halosapi.Client }

type scopeModel struct {
	Rings types.Set `tfsdk:"rings"`
	Units types.Set `tfsdk:"units"`
}

var scopeAttrTypes = map[string]attr.Type{
	"rings": types.SetType{ElemType: types.StringType},
	"units": types.SetType{ElemType: types.StringType},
}

type serviceTokenModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Role        types.String `tfsdk:"role"`
	TTL         types.String `tfsdk:"ttl"`
	Owner       types.String `tfsdk:"owner"`
	Description types.String `tfsdk:"description"`
	Scope       types.Object `tfsdk:"scope"`
	Token       types.String `tfsdk:"token"`
	Principal   types.String `tfsdk:"principal"`
	CreatedBy   types.String `tfsdk:"created_by"`
	CreatedAt   types.String `tfsdk:"created_at"`
	ExpiresAt   types.String `tfsdk:"expires_at"`
}

func (r *serviceTokenResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service_token"
}

func (r *serviceTokenResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "A halo-server service-account token (ADR-0036): one role, optionally bounded to rings and units (ADR-0037), for automation. " +
			"Every argument forces a new token, because a token cannot be edited; destroying the resource revokes it.",
		MarkdownDescription: "A halo-server service-account token (ADR-0036): one role, optionally bounded to rings and units (ADR-0037), for automation.\n\n" +
			"Every argument forces a new token, because a token cannot be edited; destroying the resource revokes it.\n\n" +
			"~> **The secret is stored in Terraform state.** `token` is returned by halo-server exactly once, at create, and Terraform has to keep it to be useful. " +
			"Use an encrypted remote backend (or OpenTofu state encryption) and restrict who can read state. Marking it sensitive only hides it from CLI output. " +
			"An imported token has no `token` value: the secret cannot be read back.\n\n" +
			"~> **Creating needs an interactive session.** halo-server only lets a signed-in human create tokens (a token cannot mint its successor), so the provider needs `session` (or `HALO_SESSION`) for create. Refresh, import and destroy work with a service token.\n\n" +
			"~> **Orphan recovery.** If the connection drops after halo-server stored the token but before the response arrived, Terraform has no id in state and the next apply creates a second token. " +
			"To recover: list tokens (`halo service-token list`, or `GET /api/v1/service-tokens`), find the one with your `name` and no matching state entry, then either revoke it (`halo service-token revoke <id>`) or adopt it with `terraform import halos_service_token.<name> <id>` (its secret is lost either way, so revoke and recreate if you need the secret). Re-run the apply.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "The token id (16 hex characters). Also the import id.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Lowercase name (a-z, 0-9, `.`, `_`, `-`; at most 63 characters). Shown in the audit log as `service-account:<name>:<id>`. Changing it forces a new token.",
				PlanModifiers: replace,
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 63),
					stringvalidator.RegexMatches(regexp.MustCompile(`^[a-z0-9._-]+$`), "must use only a-z, 0-9, '.', '_' and '-'"),
				},
			},
			"role": schema.StringAttribute{
				Required:      true,
				Description:   "One of " + strings.Join(serviceTokenRoles, ", ") + ". May not exceed the creator's own permissions. Changing it forces a new token.",
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.OneOf(serviceTokenRoles...)},
			},
			"ttl": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Lifetime as a duration such as `720h`: at least `1h`, at most halo-server's `--service-token-max-ttl` (default and maximum 90 days). " +
					"Omit for the server default. Changing it forces a new token. After import the value is derived from the token's dates and is whole hours, minutes or seconds (`720h`, `90m`).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown(), stringplanmodifier.RequiresReplace()},
				Validators:    []validator.String{ttlValidator{}},
			},
			"owner": schema.StringAttribute{
				Optional:      true,
				Description:   "Free-text owner, for example a team name. Changing it forces a new token.",
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.LengthAtMost(256)},
			},
			"description": schema.StringAttribute{
				Optional:      true,
				Description:   "Free-text description. Changing it forces a new token.",
				PlanModifiers: replace,
				Validators:    []validator.String{stringvalidator.LengthAtMost(256)},
			},
			"scope": schema.SingleNestedAttribute{
				Optional: true,
				Description: "Bounds the role to rings and units that exist in policy and lie within the creator's admin grants. " +
					"Omit for a global token. Must name at least one ring or unit. Changing it forces a new token.",
				PlanModifiers: []planmodifier.Object{objectplanmodifier.RequiresReplace()},
				Validators:    []validator.Object{scopeValidator{}},
				Attributes: map[string]schema.Attribute{
					"rings": schema.SetAttribute{
						Optional: true, ElementType: types.StringType,
						Description: "Ring names.",
						Validators:  []validator.Set{setvalidator.SizeAtLeast(1)},
					},
					"units": schema.SetAttribute{
						Optional: true, ElementType: types.StringType,
						Description: "Unit names.",
						Validators:  []validator.Set{setvalidator.SizeAtLeast(1)},
					},
				},
			},
			"token": schema.StringAttribute{
				Computed:  true,
				Sensitive: true,
				Description: "The secret (`halo_sat_...`), for use as `Authorization: Bearer`. Available only at create and stored in state, so use encrypted state; " +
					"null after import.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"principal":  schema.StringAttribute{Computed: true, Description: "The audit identity, `service-account:<name>:<id>`.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"created_by": schema.StringAttribute{Computed: true, Description: "The admin who created the token.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"created_at": schema.StringAttribute{Computed: true, Description: "Creation time, RFC 3339.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
			"expires_at": schema.StringAttribute{Computed: true, Description: "Expiry time, RFC 3339. An expired token stays in state until it is destroyed or revoked.", PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()}},
		},
	}
}

func (r *serviceTokenResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*halosapi.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *halosapi.Client, got %T", req.ProviderData))
		return
	}
	r.client = c
}

func (r *serviceTokenResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceTokenModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in := halosapi.CreateServiceTokenRequest{
		Name:        plan.Name.ValueString(),
		Role:        plan.Role.ValueString(),
		TTL:         plan.TTL.ValueString(),
		Owner:       plan.Owner.ValueString(),
		Description: plan.Description.ValueString(),
	}
	if !plan.Scope.IsNull() {
		var sc scopeModel
		resp.Diagnostics.Append(plan.Scope.As(ctx, &sc, basicObjectOptions)...)
		in.Scope = &halosapi.RoleScope{}
		resp.Diagnostics.Append(sc.Rings.ElementsAs(ctx, &in.Scope.Rings, false)...)
		resp.Diagnostics.Append(sc.Units.ElementsAs(ctx, &in.Scope.Units, false)...)
		sort.Strings(in.Scope.Rings)
		sort.Strings(in.Scope.Units)
	}
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.client.CreateServiceToken(ctx, in)
	if err != nil {
		resp.Diagnostics.Append(apiDiag("creating the service token", err))
		return
	}
	state := plan
	state.Token = types.StringValue(out.Token)
	// Save the secret first: nothing after this may lose it.
	resp.Diagnostics.Append(applyToken(ctx, &state, out.ServiceToken)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceTokenResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	tok, err := r.client.GetServiceToken(ctx, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.Append(apiDiag("reading the service token", err))
		return
	}
	if tok == nil || tok.Revoked {
		// Gone or revoked out of band: plan a new one.
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(applyToken(ctx, &state, *tok)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is never reached: every argument forces replacement and the rest is
// computed. It exists to satisfy the interface and fails loudly.
func (r *serviceTokenResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Service tokens cannot be updated", "Every argument forces a new token; this is a provider bug.")
}

func (r *serviceTokenResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceTokenModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	reason := "revoked by Terraform: destroy of halos_service_token " + state.Name.ValueString()
	err := r.client.RevokeServiceToken(ctx, state.ID.ValueString(), reason)
	switch {
	case err == nil, halosapi.IsStatus(err, 404):
		// Revoked now, or already gone: either way the goal state holds.
	default:
		resp.Diagnostics.Append(apiDiag("revoking the service token", err))
	}
}

func (r *serviceTokenResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

var basicObjectOptions = basetypes.ObjectAsOptions{}

// applyToken copies what the server knows into m. It leaves Token alone, and
// keeps a user-written ttl, owner or description that means the same as the
// server's value so a refresh never shows a spurious diff.
func applyToken(ctx context.Context, m *serviceTokenModel, t halosapi.ServiceToken) diag.Diagnostics {
	var diags diag.Diagnostics
	m.ID = types.StringValue(t.ID)
	m.Name = types.StringValue(t.Name)
	m.Role = types.StringValue(t.Role)
	m.Principal = types.StringValue(t.Principal)
	m.CreatedBy = types.StringValue(t.CreatedBy)
	m.CreatedAt = types.StringValue(t.CreatedAt.UTC().Format(time.RFC3339))
	m.ExpiresAt = types.StringValue(t.ExpiresAt.UTC().Format(time.RFC3339))
	m.Owner = optionalText(m.Owner, t.Owner)
	m.Description = optionalText(m.Description, t.Description)

	got := t.ExpiresAt.Sub(t.CreatedAt).Round(time.Second)
	if want, err := time.ParseDuration(m.TTL.ValueString()); m.TTL.IsNull() || m.TTL.IsUnknown() || err != nil || want != got {
		m.TTL = types.StringValue(canonicalTTL(got))
	}

	if t.Scope.Global() {
		m.Scope = types.ObjectNull(scopeAttrTypes)
		return diags
	}
	rings, d := stringSetOrNull(ctx, t.Scope.Rings)
	diags.Append(d...)
	units, d := stringSetOrNull(ctx, t.Scope.Units)
	diags.Append(d...)
	obj, d := types.ObjectValue(scopeAttrTypes, map[string]attr.Value{"rings": rings, "units": units})
	diags.Append(d...)
	m.Scope = obj
	return diags
}

func stringSetOrNull(ctx context.Context, s []string) (types.Set, diag.Diagnostics) {
	if len(s) == 0 {
		return types.SetNull(types.StringType), nil
	}
	return types.SetValueFrom(ctx, types.StringType, s)
}

// optionalText maps the server's omitted-or-empty text to null, and keeps the
// configured value when only whitespace differs (the server trims it).
func optionalText(prior types.String, got string) types.String {
	if got == "" {
		return types.StringNull()
	}
	if !prior.IsNull() && !prior.IsUnknown() && strings.TrimSpace(prior.ValueString()) == got {
		return prior
	}
	return types.StringValue(got)
}

// canonicalTTL renders d as whole hours, else whole minutes, else seconds.
func canonicalTTL(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}
