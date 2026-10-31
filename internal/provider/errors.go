package provider

import (
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/dshakes/terraform-provider-halos/internal/halosapi"
)

// apiDiag maps an error from the client to a diagnostic. action reads as
// "creating the service token". The text never holds a credential: the client
// redacts before it builds an error.
func apiDiag(action string, err error) diag.Diagnostic {
	summary := "Error " + action
	var ae *halosapi.APIError
	if errors.Is(err, halosapi.ErrSessionRequired) {
		return diag.NewErrorDiagnostic(summary, err.Error())
	}
	if !errors.As(err, &ae) {
		return diag.NewErrorDiagnostic(summary, err.Error())
	}
	var hint string
	switch ae.Status {
	case 400, 422:
		summary = "Invalid request while " + action
		hint = "halo-server rejected the arguments."
	case 401:
		summary = "Authentication failed while " + action
		hint = "The token or session is missing, malformed, expired or revoked. Check the provider's token/session (HALO_TOKEN / HALO_SESSION)."
	case 403:
		summary = "Permission denied while " + action
		hint = "The credential lacks the required permission (service tokens need `admin`; a token's role and scope may not exceed its creator's)."
	case 404:
		summary = "Not found while " + action
		hint = "halo-server has no such resource, or the endpoint is not the halo-server API (is the version too old?)."
	case 409:
		summary = "Conflict while " + action
		hint = "halo-server refused because of its current state (for service tokens: the 1,000 active token limit)."
	case 429:
		summary = "Rate limited while " + action
		hint = "Too many failed authentications or requests from this address; wait and retry."
	case 503:
		summary = "halo-server unavailable while " + action
		hint = "The server's state store or policy is not available; retry."
	}
	if ae.Status >= 500 && ae.Status != 503 {
		summary = "halo-server error while " + action
	}
	detail := fmt.Sprintf("%s %s answered HTTP %d: %s", ae.Method, ae.Path, ae.Status, ae.Message)
	if hint != "" {
		detail += "\n\n" + hint
	}
	return diag.NewErrorDiagnostic(summary, detail)
}
