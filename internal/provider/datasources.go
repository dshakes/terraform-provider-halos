package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/dshakes/terraform-provider-halos/internal/halosapi"
)

// dsBase holds what every data source shares: the client.
type dsBase struct{ client *halosapi.Client }

func (b *dsBase) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*halosapi.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("expected *halosapi.Client, got %T", req.ProviderData))
		return
	}
	b.client = c
}

func strList(ctx context.Context, s []string, diags *diag.Diagnostics) types.List {
	if s == nil {
		s = []string{}
	}
	l, d := types.ListValueFrom(ctx, types.StringType, s)
	diags.Append(d...)
	return l
}

func listOf(ctx context.Context, elem attr.Type, v any, diags *diag.Diagnostics) types.List {
	l, d := types.ListValueFrom(ctx, elem, v)
	diags.Append(d...)
	return l
}

func listAttr(desc string) schema.ListAttribute {
	return schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: desc}
}

// ---- halos_me ----

type meDataSource struct{ dsBase }

// NewMeDataSource returns the halos_me data source.
func NewMeDataSource() datasource.DataSource { return &meDataSource{} }

type meModel struct {
	ID          types.String `tfsdk:"id"`
	Kind        types.String `tfsdk:"kind"`
	Admin       types.Bool   `tfsdk:"admin"`
	Groups      types.List   `tfsdk:"groups"`
	Roles       types.List   `tfsdk:"roles"`
	Permissions types.List   `tfsdk:"permissions"`
	Ring        types.String `tfsdk:"ring"`
}

func (d *meDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_me"
}

func (d *meDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The identity the provider authenticates as (GET /api/v1/me): use it to assert that the credential has the roles a configuration needs.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, Description: "The caller's id, for a service token `service-account:<name>:<id>`."},
			"kind":        schema.StringAttribute{Computed: true, Description: "Empty for a signed-in user, `service-account` for a token."},
			"admin":       schema.BoolAttribute{Computed: true, Description: "Whether the caller holds the admin permission globally."},
			"groups":      listAttr("Directory groups."),
			"roles":       listAttr("Role names granted to the caller."),
			"permissions": listAttr("Permissions the roles grant: read, operate, approve, audit, admin."),
			"ring":        schema.StringAttribute{Computed: true, Description: "The ring policy assigns the caller to."},
		},
	}
}

func (d *meDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	me, err := d.client.GetMe(ctx)
	if err != nil {
		resp.Diagnostics.Append(apiDiag("reading /api/v1/me", err))
		return
	}
	m := meModel{
		ID: types.StringValue(me.ID), Kind: types.StringValue(me.Kind), Admin: types.BoolValue(me.Admin), Ring: types.StringValue(me.Ring),
		Groups: strList(ctx, me.Groups, &resp.Diagnostics), Roles: strList(ctx, me.Roles, &resp.Diagnostics),
		Permissions: strList(ctx, me.Permissions, &resp.Diagnostics),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---- halos_capabilities ----

type capabilitiesDataSource struct{ dsBase }

// NewCapabilitiesDataSource returns the halos_capabilities data source.
func NewCapabilitiesDataSource() datasource.DataSource { return &capabilitiesDataSource{} }

type bindingModel struct {
	Role   types.String `tfsdk:"role"`
	Source types.String `tfsdk:"source"`
	Rings  types.List   `tfsdk:"rings"`
	Units  types.List   `tfsdk:"units"`
}

var bindingType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"role": types.StringType, "source": types.StringType,
	"rings": types.ListType{ElemType: types.StringType}, "units": types.ListType{ElemType: types.StringType},
}}

type capabilitiesModel struct {
	ID          types.String `tfsdk:"id"`
	KillSwitch  types.Bool   `tfsdk:"kill_switch"`
	Roles       types.List   `tfsdk:"roles"`
	Permissions types.List   `tfsdk:"permissions"`
	Bindings    types.List   `tfsdk:"bindings"`
}

func (d *capabilitiesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_capabilities"
}

func (d *capabilitiesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Optional server features and the caller's permissions and scoped role bindings (GET /api/v1/capabilities).",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, Description: "Always `capabilities`."},
			"kill_switch": schema.BoolAttribute{Computed: true, Description: "Whether the server has a kill-switch signing key configured."},
			"roles":       listAttr("Role names granted to the caller."),
			"permissions": listAttr("Permissions the roles grant."),
			"bindings": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The caller's role bindings; an empty rings and units means global.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"role":   schema.StringAttribute{Computed: true, Description: "Role name."},
					"source": schema.StringAttribute{Computed: true, Description: "Where the binding comes from, for example `identity.roleBindings[0]`."},
					"rings":  listAttr("Rings the binding is limited to."),
					"units":  listAttr("Units the binding is limited to."),
				}},
			},
		},
	}
}

func (d *capabilitiesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	c, err := d.client.GetCapabilities(ctx)
	if err != nil {
		resp.Diagnostics.Append(apiDiag("reading /api/v1/capabilities", err))
		return
	}
	bs := make([]bindingModel, 0, len(c.Bindings))
	for _, b := range c.Bindings {
		bs = append(bs, bindingModel{
			Role: types.StringValue(b.Role), Source: types.StringValue(b.Source),
			Rings: strList(ctx, b.Scope.Rings, &resp.Diagnostics), Units: strList(ctx, b.Scope.Units, &resp.Diagnostics),
		})
	}
	m := capabilitiesModel{
		ID: types.StringValue("capabilities"), KillSwitch: types.BoolValue(c.KillSwitch),
		Roles: strList(ctx, c.Roles, &resp.Diagnostics), Permissions: strList(ctx, c.Permissions, &resp.Diagnostics),
		Bindings: listOf(ctx, bindingType, bs, &resp.Diagnostics),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---- halos_releases ----

type releasesDataSource struct{ dsBase }

// NewReleasesDataSource returns the halos_releases data source.
func NewReleasesDataSource() datasource.DataSource { return &releasesDataSource{} }

type ringReleaseModel struct {
	Ring           types.String `tfsdk:"ring"`
	Published      types.Bool   `tfsdk:"published"`
	Digest         types.String `tfsdk:"digest"`
	Seq            types.Int64  `tfsdk:"seq"`
	ExpiresAt      types.String `tfsdk:"expires_at"`
	Expired        types.Bool   `tfsdk:"expired"`
	Stale          types.Bool   `tfsdk:"stale"`
	Suspicious     types.Bool   `tfsdk:"suspicious"`
	Error          types.String `tfsdk:"error"`
	DriftHosts     types.Int64  `tfsdk:"drift_hosts"`
	TotalHosts     types.Int64  `tfsdk:"total_hosts"`
	HostsOnDigest  types.Int64  `tfsdk:"hosts_on_digest"`
	HostsOnOtherID types.Int64  `tfsdk:"hosts_on_other_digest"`
}

var ringReleaseType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"ring": types.StringType, "published": types.BoolType, "digest": types.StringType, "seq": types.Int64Type,
	"expires_at": types.StringType, "expired": types.BoolType, "stale": types.BoolType, "suspicious": types.BoolType,
	"error": types.StringType, "drift_hosts": types.Int64Type, "total_hosts": types.Int64Type,
	"hosts_on_digest": types.Int64Type, "hosts_on_other_digest": types.Int64Type,
}}

type releasesModel struct {
	ID       types.String `tfsdk:"id"`
	Registry types.String `tfsdk:"registry"`
	Stale    types.Bool   `tfsdk:"stale"`
	Rings    types.List   `tfsdk:"rings"`
}

func (d *releasesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_releases"
}

func (d *releasesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	i, b, s := func(desc string) schema.Attribute { return schema.Int64Attribute{Computed: true, Description: desc} },
		func(desc string) schema.Attribute { return schema.BoolAttribute{Computed: true, Description: desc} },
		func(desc string) schema.Attribute { return schema.StringAttribute{Computed: true, Description: desc} }
	resp.Schema = schema.Schema{
		Description: "Per-ring release pointers as verified by halo-server, with fleet convergence and drift (GET /api/v1/releases). " +
			"Releases are published by CI and promoted by a human merging a PR; this data source only reads them, for example to feed monitoring or a precondition.",
		Attributes: map[string]schema.Attribute{
			"id":       s("Always `releases`."),
			"registry": s("The OCI registry the pointers are read from; empty when portal config sets none."),
			"stale":    b("True when the registry was unreachable and the last verified state is shown."),
			"rings": schema.ListNestedAttribute{
				Computed: true, Description: "One entry per ring, in policy order.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"ring":                  s("Ring name."),
					"published":             b("Whether a signed pointer exists."),
					"digest":                s("The release digest the ring points at."),
					"seq":                   i("Pointer sequence number."),
					"expires_at":            s("Pointer expiry, RFC 3339; empty if unpublished."),
					"expired":               b("Whether the pointer has expired."),
					"stale":                 b("Whether this ring's state is the last verified one."),
					"suspicious":            b("Whether the pointer failed a consistency check."),
					"error":                 s("Why the pointer could not be read, if it could not."),
					"drift_hosts":           i("Hosts reporting a digest other than the ring's."),
					"total_hosts":           i("Reporting hosts."),
					"hosts_on_digest":       i("Hosts on the ring's digest."),
					"hosts_on_other_digest": i("Hosts on another digest."),
				}},
			},
		},
	}
}

func (d *releasesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	rel, err := d.client.GetReleases(ctx)
	if err != nil {
		resp.Diagnostics.Append(apiDiag("reading /api/v1/releases", err))
		return
	}
	rows := make([]ringReleaseModel, 0, len(rel.Rings))
	for _, r := range rel.Rings {
		exp := ""
		if r.ExpiresAt != nil && !r.ExpiresAt.IsZero() {
			exp = r.ExpiresAt.UTC().Format(time.RFC3339)
		}
		rows = append(rows, ringReleaseModel{
			Ring: types.StringValue(r.Ring), Published: types.BoolValue(r.Published), Digest: types.StringValue(r.Digest),
			Seq: types.Int64Value(r.Seq), ExpiresAt: types.StringValue(exp), Expired: types.BoolValue(r.Expired),
			Stale: types.BoolValue(r.Stale), Suspicious: types.BoolValue(r.Suspicious), Error: types.StringValue(r.Error),
			DriftHosts: types.Int64Value(int64(r.DriftHosts)), TotalHosts: types.Int64Value(int64(r.Convergence.Total)),
			HostsOnDigest: types.Int64Value(int64(r.Convergence.OnDigest)), HostsOnOtherID: types.Int64Value(int64(r.Convergence.Other)),
		})
	}
	m := releasesModel{
		ID: types.StringValue("releases"), Registry: types.StringValue(rel.Registry), Stale: types.BoolValue(rel.Stale),
		Rings: listOf(ctx, ringReleaseType, rows, &resp.Diagnostics),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---- halos_experiments ----

type experimentsDataSource struct{ dsBase }

// NewExperimentsDataSource returns the halos_experiments data source.
func NewExperimentsDataSource() datasource.DataSource { return &experimentsDataSource{} }

type experimentModel struct {
	Name   types.String `tfsdk:"name"`
	Type   types.String `tfsdk:"type"`
	Axis   types.String `tfsdk:"axis"`
	Status types.String `tfsdk:"status"`
	Rings  types.List   `tfsdk:"rings"`
}

var experimentType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"name": types.StringType, "type": types.StringType, "axis": types.StringType, "status": types.StringType,
	"rings": types.ListType{ElemType: types.StringType},
}}

type experimentsModel struct {
	ID          types.String `tfsdk:"id"`
	Experiments types.List   `tfsdk:"experiments"`
}

func (d *experimentsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_experiments"
}

func (d *experimentsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Experiments defined in policy with their status (GET /api/v1/experiments). Read only: experiments are started, paused and concluded by a human, not by Terraform.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{Computed: true, Description: "Always `experiments`."},
			"experiments": schema.ListNestedAttribute{
				Computed: true, Description: "Experiments in policy order.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":   schema.StringAttribute{Computed: true, Description: "Experiment name."},
					"type":   schema.StringAttribute{Computed: true, Description: "Experiment type, for example `ab` or `shadow`."},
					"axis":   schema.StringAttribute{Computed: true, Description: "`client` or `gateway`."},
					"status": schema.StringAttribute{Computed: true, Description: "`draft`, `running`, `paused` or `concluded`."},
					"rings":  listAttr("Rings the experiment runs in."),
				}},
			},
		},
	}
}

func (d *experimentsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	exps, err := d.client.ListExperiments(ctx)
	if err != nil {
		resp.Diagnostics.Append(apiDiag("reading /api/v1/experiments", err))
		return
	}
	rows := make([]experimentModel, 0, len(exps))
	for _, e := range exps {
		rows = append(rows, experimentModel{
			Name: types.StringValue(e.Name), Type: types.StringValue(e.Type), Axis: types.StringValue(e.Axis),
			Status: types.StringValue(e.Status), Rings: strList(ctx, e.Rings, &resp.Diagnostics),
		})
	}
	m := experimentsModel{ID: types.StringValue("experiments"), Experiments: listOf(ctx, experimentType, rows, &resp.Diagnostics)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---- halos_rollouts ----

type rolloutsDataSource struct{ dsBase }

// NewRolloutsDataSource returns the halos_rollouts data source.
func NewRolloutsDataSource() datasource.DataSource { return &rolloutsDataSource{} }

type rolloutModel struct {
	Name       types.String `tfsdk:"name"`
	Axis       types.String `tfsdk:"axis"`
	Status     types.String `tfsdk:"status"`
	Experiment types.String `tfsdk:"experiment"`
	Step       types.Int64  `tfsdk:"step"`
	StepName   types.String `tfsdk:"step_name"`
	Halted     types.String `tfsdk:"halted"`
	HaltReason types.String `tfsdk:"halt_reason"`
}

var rolloutType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"name": types.StringType, "axis": types.StringType, "status": types.StringType, "experiment": types.StringType,
	"step": types.Int64Type, "step_name": types.StringType, "halted": types.StringType, "halt_reason": types.StringType,
}}

type rolloutsModel struct {
	ID       types.String `tfsdk:"id"`
	Rollouts types.List   `tfsdk:"rollouts"`
}

func (d *rolloutsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_rollouts"
}

func (d *rolloutsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	s := func(desc string) schema.Attribute { return schema.StringAttribute{Computed: true, Description: desc} }
	resp.Schema = schema.Schema{
		Description: "Rollouts defined in policy with the controller's current step (GET /api/v1/rollouts). Read only: advancing or rolling back a rollout is a human decision.",
		Attributes: map[string]schema.Attribute{
			"id": s("Always `rollouts`."),
			"rollouts": schema.ListNestedAttribute{
				Computed: true, Description: "Rollouts in policy order.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"name":        s("Rollout name."),
					"axis":        s("`client` or `gateway`."),
					"status":      s("Rollout status, for example `draft` or `running`."),
					"experiment":  s("The experiment the rollout drives."),
					"step":        schema.Int64Attribute{Computed: true, Description: "Index of the current step; 0 when the controller has not started it."},
					"step_name":   s("Name of the current step; empty when not started."),
					"halted":      s("Non-empty when the controller halted the rollout."),
					"halt_reason": s("Why it halted."),
				}},
			},
		},
	}
}

func (d *rolloutsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	rs, err := d.client.ListRollouts(ctx)
	if err != nil {
		resp.Diagnostics.Append(apiDiag("reading /api/v1/rollouts", err))
		return
	}
	rows := make([]rolloutModel, 0, len(rs))
	for _, r := range rs {
		row := rolloutModel{
			Name: types.StringValue(r.Timeline.Rollout), Axis: types.StringValue(r.Timeline.Axis),
			Status: types.StringValue(r.Timeline.Status), Experiment: types.StringValue(r.Timeline.Experiment),
			Step: types.Int64Value(0), StepName: types.StringValue(""), Halted: types.StringValue(""), HaltReason: types.StringValue(""),
		}
		if r.State != nil {
			row.Step, row.StepName = types.Int64Value(int64(r.State.Step)), types.StringValue(r.State.StepName)
			row.Halted, row.HaltReason = types.StringValue(r.State.Halted), types.StringValue(r.State.HaltReason)
		}
		rows = append(rows, row)
	}
	m := rolloutsModel{ID: types.StringValue("rollouts"), Rollouts: listOf(ctx, rolloutType, rows, &resp.Diagnostics)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---- halos_kill_switch ----

type killSwitchDataSource struct{ dsBase }

// NewKillSwitchDataSource returns the halos_kill_switch data source.
func NewKillSwitchDataSource() datasource.DataSource { return &killSwitchDataSource{} }

type killModel struct {
	Experiment types.String `tfsdk:"experiment"`
	Killed     types.Bool   `tfsdk:"killed"`
	By         types.String `tfsdk:"by"`
	At         types.String `tfsdk:"at"`
	Reason     types.String `tfsdk:"reason"`
}

var killType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"experiment": types.StringType, "killed": types.BoolType, "by": types.StringType, "at": types.StringType, "reason": types.StringType,
}}

type killSwitchModel struct {
	ID      types.String `tfsdk:"id"`
	Version types.Int64  `tfsdk:"version"`
	Killed  types.List   `tfsdk:"killed"`
	Active  types.Bool   `tfsdk:"any_active"`
}

func (d *killSwitchDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_kill_switch"
}

func (d *killSwitchDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The kill list (GET /api/v1/killswitch). Read only: killing and unkilling are incident actions a human takes with `halo kill`, never Terraform. " +
			"Use `any_active` in a `check` block to alert when something is killed.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Computed: true, Description: "Always `kill-switch`."},
			"version":    schema.Int64Attribute{Computed: true, Description: "Monotonic version of the signed kill list."},
			"any_active": schema.BoolAttribute{Computed: true, Description: "True when at least one entry has `killed = true`."},
			"killed": schema.ListNestedAttribute{
				Computed: true, Description: "Kill records.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"experiment": schema.StringAttribute{Computed: true, Description: "The experiment."},
					"killed":     schema.BoolAttribute{Computed: true, Description: "Whether it is currently killed."},
					"by":         schema.StringAttribute{Computed: true, Description: "Who set it."},
					"at":         schema.StringAttribute{Computed: true, Description: "When, RFC 3339."},
					"reason":     schema.StringAttribute{Computed: true, Description: "The recorded reason."},
				}},
			},
		},
	}
}

func (d *killSwitchDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	k, err := d.client.GetKills(ctx)
	if err != nil {
		resp.Diagnostics.Append(apiDiag("reading /api/v1/killswitch", err))
		return
	}
	rows := make([]killModel, 0, len(k.Killed))
	active := false
	for _, r := range k.Killed {
		active = active || r.Killed
		rows = append(rows, killModel{
			Experiment: types.StringValue(r.Experiment), Killed: types.BoolValue(r.Killed), By: types.StringValue(r.By),
			At: types.StringValue(r.At.UTC().Format(time.RFC3339)), Reason: types.StringValue(r.Reason),
		})
	}
	m := killSwitchModel{ID: types.StringValue("kill-switch"), Version: types.Int64Value(k.Version), Active: types.BoolValue(active), Killed: listOf(ctx, killType, rows, &resp.Diagnostics)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}

// ---- halos_fleet ----

type fleetDataSource struct{ dsBase }

// NewFleetDataSource returns the halos_fleet data source.
func NewFleetDataSource() datasource.DataSource { return &fleetDataSource{} }

type fleetRingModel struct {
	Ring       types.String  `tfsdk:"ring"`
	Hosts      types.Int64   `tfsdk:"hosts"`
	Percent    types.Float64 `tfsdk:"percent"`
	DriftHosts types.Int64   `tfsdk:"drift_hosts"`
}

var fleetRingType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"ring": types.StringType, "hosts": types.Int64Type, "percent": types.Float64Type, "drift_hosts": types.Int64Type,
}}

type fleetModel struct {
	ID         types.String `tfsdk:"id"`
	Total      types.Int64  `tfsdk:"total"`
	DriftHosts types.Int64  `tfsdk:"drift_hosts"`
	Rings      types.List   `tfsdk:"rings"`
}

func (d *fleetDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_fleet"
}

func (d *fleetDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Fleet size and per-ring host counts and drift (GET /api/v1/fleet). Per-host rows are deliberately not exposed, so no device or user data lands in state.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Computed: true, Description: "Always `fleet`."},
			"total":       schema.Int64Attribute{Computed: true, Description: "Enrolled hosts."},
			"drift_hosts": schema.Int64Attribute{Computed: true, Description: "Hosts not on their ring's release."},
			"rings": schema.ListNestedAttribute{
				Computed: true, Description: "Per-ring statistics.",
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"ring":        schema.StringAttribute{Computed: true, Description: "Ring name."},
					"hosts":       schema.Int64Attribute{Computed: true, Description: "Hosts in the ring."},
					"percent":     schema.Float64Attribute{Computed: true, Description: "Share of the fleet, in percent."},
					"drift_hosts": schema.Int64Attribute{Computed: true, Description: "Hosts in the ring that drifted."},
				}},
			},
		},
	}
}

func (d *fleetDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	f, err := d.client.GetFleet(ctx)
	if err != nil {
		resp.Diagnostics.Append(apiDiag("reading /api/v1/fleet", err))
		return
	}
	rows := make([]fleetRingModel, 0, len(f.Rings))
	for _, r := range f.Rings {
		rows = append(rows, fleetRingModel{Ring: types.StringValue(r.Ring), Hosts: types.Int64Value(int64(r.Hosts)), Percent: types.Float64Value(r.Percent), DriftHosts: types.Int64Value(int64(r.DriftHosts))})
	}
	m := fleetModel{ID: types.StringValue("fleet"), Total: types.Int64Value(int64(f.Total)), DriftHosts: types.Int64Value(int64(f.DriftHosts)), Rings: listOf(ctx, fleetRingType, rows, &resp.Diagnostics)}
	resp.Diagnostics.Append(resp.State.Set(ctx, &m)...)
}
