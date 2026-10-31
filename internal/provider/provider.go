// Package provider implements the Halos Terraform provider.
package provider

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/dshakes/terraform-provider-halos/internal/halosapi"
)

const (
	envServer  = "HALO_SERVER"
	envToken   = "HALO_TOKEN"
	envSession = "HALO_SESSION"
	envCA      = "HALO_CA_BUNDLE_FILE"
)

var _ provider.Provider = (*haloProvider)(nil)

type haloProvider struct{ version string }

// New returns a provider factory.
func New(version string) func() provider.Provider {
	return func() provider.Provider { return &haloProvider{version: version} }
}

type providerModel struct {
	Endpoint     types.String `tfsdk:"endpoint"`
	Token        types.String `tfsdk:"token"`
	Session      types.String `tfsdk:"session"`
	CABundleFile types.String `tfsdk:"ca_bundle_file"`
	Timeout      types.String `tfsdk:"timeout"`
}

func (p *haloProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "halos"
	resp.Version = p.version
}

func (p *haloProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages Halos server-side state that is not policy-as-code (service-account tokens) and reads halo-server status. " +
			"Policy files, kill/unkill, approvals, promotions, rollout advances and release publishing are deliberately not exposed.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional: true,
				Description: "halo-server base URL, for example `https://halos.example.com`. Must be https unless the host is loopback " +
					"(`localhost`, `127.0.0.0/8`, `::1`). May also be set with the `" + envServer + "` environment variable.",
			},
			"token": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Service-account token (`halo_sat_...`, ADR-0036) used for every call. May also be set with `" + envToken + "`. " +
					"A token cannot create service tokens; see `session`.",
			},
			"session": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Value of an admin's `halo_session` cookie. halo-server only lets an interactive session create service tokens " +
					"(a token cannot mint its successor), so `halos_service_token` needs this; data sources, refresh and destroy work with `token` alone. " +
					"May also be set with `" + envSession + "`. Sessions are short-lived: prefer minting tokens from a human-run apply.",
			},
			"ca_bundle_file": schema.StringAttribute{
				Optional: true,
				Description: "Path to a PEM file of CA certificates that replaces the system roots when verifying halo-server's certificate. " +
					"May also be set with `" + envCA + "`.",
			},
			"timeout": schema.StringAttribute{
				Optional:    true,
				Description: "Per-request timeout as a Go duration. Default `30s`, maximum `10m`.",
			},
		},
	}
}

// resolveConfig merges the provider block with the environment and validates
// the result. It never includes a credential in a diagnostic.
func resolveConfig(m providerModel, getenv func(string) string, readFile func(string) ([]byte, error)) (halosapi.Config, diag.Diagnostics) {
	var diags diag.Diagnostics
	pick := func(v types.String, env string) string {
		if !v.IsNull() && v.ValueString() != "" {
			return v.ValueString()
		}
		return strings.TrimSpace(getenv(env))
	}
	cfg := halosapi.Config{
		Endpoint: pick(m.Endpoint, envServer),
		Token:    pick(m.Token, envToken),
		Session:  pick(m.Session, envSession),
	}
	if cfg.Endpoint == "" {
		diags.AddAttributeError(path.Root("endpoint"), "Missing halo-server endpoint",
			"Set the endpoint argument or the "+envServer+" environment variable to the halo-server base URL.")
	} else if _, err := halosapi.ValidateEndpoint(cfg.Endpoint); err != nil {
		diags.AddAttributeError(path.Root("endpoint"), "Invalid halo-server endpoint", err.Error())
	}
	if cfg.Token == "" && cfg.Session == "" {
		diags.AddAttributeError(path.Root("token"), "Missing halo-server token",
			"Set the token argument or the "+envToken+" environment variable to a service-account token "+
				"(a session is accepted instead, for creating tokens).")
	}
	if ca := pick(m.CABundleFile, envCA); ca != "" {
		pem, err := readFile(ca)
		if err != nil {
			diags.AddAttributeError(path.Root("ca_bundle_file"), "Cannot read CA bundle", fmt.Sprintf("reading %q: %s", ca, err))
		}
		cfg.CABundlePEM = pem
	}
	if !m.Timeout.IsNull() && m.Timeout.ValueString() != "" {
		d, err := time.ParseDuration(m.Timeout.ValueString())
		switch {
		case err != nil:
			diags.AddAttributeError(path.Root("timeout"), "Invalid timeout", "timeout must be a duration such as 30s.")
		case d <= 0 || d > halosapi.MaxTimeout:
			diags.AddAttributeError(path.Root("timeout"), "Invalid timeout", fmt.Sprintf("timeout must be greater than 0 and at most %s.", halosapi.MaxTimeout))
		default:
			cfg.Timeout = d
		}
	}
	return cfg, diags
}

func (p *haloProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var m providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)
	if resp.Diagnostics.HasError() {
		return
	}
	for name, v := range map[string]types.String{"endpoint": m.Endpoint, "token": m.Token, "session": m.Session, "ca_bundle_file": m.CABundleFile, "timeout": m.Timeout} {
		if v.IsUnknown() {
			resp.Diagnostics.AddAttributeError(path.Root(name), "Unknown provider argument",
				fmt.Sprintf("The %s argument is not known until apply. Set it from a value that is known at plan time, or use the environment variable.", name))
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}
	cfg, diags := resolveConfig(m, os.Getenv, os.ReadFile)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	cfg.UserAgent = "terraform-provider-halos/" + p.version
	cfg.Logger = func(ctx context.Context, msg string, fields map[string]any) { tflog.Debug(ctx, msg, fields) }
	client, err := halosapi.New(cfg)
	if err != nil {
		resp.Diagnostics.AddError("Cannot configure the Halos client", err.Error())
		return
	}
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *haloProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{NewServiceTokenResource}
}

func (p *haloProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewMeDataSource,
		NewCapabilitiesDataSource,
		NewReleasesDataSource,
		NewExperimentsDataSource,
		NewRolloutsDataSource,
		NewKillSwitchDataSource,
		NewFleetDataSource,
	}
}
