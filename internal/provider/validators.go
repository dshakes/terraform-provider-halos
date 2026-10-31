package provider

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// ttlValidator accepts a Go duration of at least one hour.
type ttlValidator struct{}

func (ttlValidator) Description(context.Context) string {
	return "a duration such as 720h, at least 1h"
}
func (v ttlValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (ttlValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	d, err := time.ParseDuration(req.ConfigValue.ValueString())
	switch {
	case err != nil:
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid ttl", fmt.Sprintf("%q is not a duration such as 720h.", req.ConfigValue.ValueString()))
	case d < minTokenTTL:
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid ttl", fmt.Sprintf("ttl must be at least %s, got %s.", minTokenTTL, d))
	}
}

// scopeValidator requires a present scope to name at least one ring or unit:
// halo-server refuses an empty scope (it must never read as global).
type scopeValidator struct{}

func (scopeValidator) Description(context.Context) string {
	return "must name at least one ring or unit; omit scope for a global token"
}
func (v scopeValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }

func (scopeValidator) ValidateObject(ctx context.Context, req validator.ObjectRequest, resp *validator.ObjectResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	attrs := req.ConfigValue.Attributes()
	for _, k := range []string{"rings", "units"} {
		// Unknown counts as "maybe set": it is checked again at apply.
		if v, ok := attrs[k]; ok && !v.IsNull() {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Empty scope", "scope must set rings or units (omit scope entirely for a global token).")
}
