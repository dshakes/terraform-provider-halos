# terraform-provider-halos

Terraform / OpenTofu provider for [Halos](https://github.com/dshakes/halos), the control plane for AI coding CLIs.

It manages the **server-side state of halo-server that is not policy-as-code**: service-account API tokens
([ADR-0036](https://github.com/dshakes/halos), scoped by ADR-0037). It also exposes read-only data sources for status.

> Status: unreleased, not published to any registry.

## Scope, and what is left out on purpose

Halos policy is GitOps: it lives in a git policy repository and changes through pull requests that a human merges.
Halos' invariant is that a human owns every irreversible step. So this provider does **not**:

- manage policy files. Manage the policy repository with the GitHub or GitLab provider and PR review.
- kill or unkill, approve, promote, advance or roll back a rollout, merge, or publish a release.
  Those have no resource, no data source write path, and no client method.

## Usage

```hcl
terraform {
  required_providers {
    halos = { source = "dshakes/halos" }
  }
}

provider "halos" {
  endpoint = "https://halos.example.com" # or HALO_SERVER
  # token   = ...                        # or HALO_TOKEN   (service-account token)
  # session = ...                        # or HALO_SESSION (admin halo_session cookie; creating tokens only)
}

resource "halos_service_token" "dashboard" {
  name  = "fleet-dashboard"
  role  = "viewer"
  ttl   = "720h"
  scope = { rings = ["ring1-canary"] }
}
```

Provider arguments: `endpoint`, `token` (sensitive), `session` (sensitive), `ca_bundle_file`, `timeout` (default `30s`, max `10m`).
`endpoint` must be https unless the host is loopback. Credentials never appear in diagnostics or logs, and HTTP redirects are never followed.

### Creating tokens needs a session, not a token

halo-server only lets an interactive, signed-in admin create a service token: "a token cannot mint its successor" (ADR-0036).
A `halo_sat_` token therefore can **list, revoke, read data sources, refresh and destroy**, but a `POST /service-tokens`
made with one answers 403. To `apply` a new `halos_service_token`, set `session` (or `HALO_SESSION`) to an admin's
`halo_session` cookie value, as the `halo` CLI does. Without it the provider fails the create before sending anything and says why.

### The secret lives in state

`halos_service_token.token` is returned once, at create, and has to be kept in state to be useful.
Use an encrypted remote backend (or OpenTofu state encryption) and restrict who can read state.
`sensitive` only hides the value from CLI output. An imported token has no secret (`token` is null).

## Resource

| Resource | Why |
| --- | --- |
| `halos_service_token` | The one piece of halo-server state that is neither policy nor an irreversible human decision. Create mints (POST), read lists and matches by id (a missing or revoked token leaves state), destroy revokes. Every argument forces replacement, since a token cannot be edited. Import by id. |

## Data sources

All read-only `GET /api/v1/...`. Chosen because each answers a question a Terraform configuration or `check` block can act on,
without moving a human decision into Terraform.

| Data source | Endpoint | Why |
| --- | --- | --- |
| `halos_me` | `/me` | Assert the credential's roles before a plan depends on them. |
| `halos_capabilities` | `/capabilities` | Whether the kill switch is configured, plus the caller's scoped role bindings. |
| `halos_releases` | `/releases` | Ring pointers, convergence and drift: wire release health into monitoring or a `check`. |
| `halos_experiments` | `/experiments` | Names and status, for dashboards and naming alerts. |
| `halos_rollouts` | `/rollouts` | Current step and halted state. |
| `halos_kill_switch` | `/killswitch` | `any_active` for alerting. Read only; killing stays with a human. |
| `halos_fleet` | `/fleet` | Fleet size and per-ring drift. Per-host rows are dropped on purpose so no device data lands in state. |

Not included: `/fleet/ring` and `/fleet/killswitch` (device-token auth, for halod, not for an admin credential), `/whoami`
(needs a user id per call; `halos_me` covers the credential), `/experiments/{name}` and `/rollouts/{name}` (the list calls already carry what is exposed), `/audit` and the session ledger (large, sensitive and unbounded for state).

## Development

```sh
make build lint test           # unit tests need no external binary
make testacc                   # acceptance, see below
make docs                      # regenerate docs/ with tfplugindocs (pinned in main.go)
```

Acceptance tests (`TF_ACC=1`) drive the provider through OpenTofu or Terraform against a real `halo-server` built from
`github.com/dshakes/halos`:

```sh
export TF_ACC=1 TF_ACC_TERRAFORM_PATH=$(command -v tofu)
export TF_ACC_PROVIDER_HOST=registry.opentofu.org TF_ACC_PROVIDER_NAMESPACE=hashicorp   # OpenTofu only
export HALOS_SERVER_BIN=/path/to/halo-server
export HALOS_POLICY_DIR=/path/to/halos/examples/acme-corp
go test -race -count=1 -v ./internal/provider/
```

The test server runs with `--dev-insecure-user`: authentication is off and every request acts as an admin. That is the only
way to get an interactive admin without an OIDC provider, so the acceptance run does not exercise the server's bearer-token
and session checks. The unit tests (httptest fake) cover what the provider sends on the wire.

Break-glass (ADR-0036) gives a real admin session without an IdP, but halo-server refuses to create a token for it
(`403 ... not a break-glass`), so no real `halo_sat_` token can be minted in a test without a fake OIDC provider.
Real-auth acceptance of bearer tokens is therefore not covered.

## Known API gaps (Halos side)

- No `GET /api/v1/service-tokens/{id}`: read lists every token and matches by id.
- No way for a token to mint a token, so unattended creation is impossible by design (ADR-0036).
- Revoke is idempotent (200 twice) but an unknown id is 404; destroy treats 404 as done.
- `ttl` is not returned; the provider derives it from `expiresAt - createdAt`.

## License

Apache-2.0. See [LICENSE](LICENSE).
