package provider

// Acceptance tests (TF_ACC=1) run the provider through a real Terraform or
// OpenTofu binary against a real halo-server.
//
// Required environment:
//
//	TF_ACC=1
//	TF_ACC_TERRAFORM_PATH   the tofu or terraform binary
//	HALOS_SERVER_BIN        a halo-server binary built from github.com/dshakes/halos
//	HALOS_POLICY_DIR        a policy directory with rings ring1-canary and ring2-early
//	                        (halos' examples/acme-corp)
//
// For OpenTofu also set TF_ACC_PROVIDER_HOST=registry.opentofu.org and
// TF_ACC_PROVIDER_NAMESPACE=hashicorp.
//
// halo-server runs with --dev-insecure-user: authentication is off and every
// request acts as an admin user. That is the only way to obtain an interactive
// (non-token) admin without an OIDC provider, so the bearer-token and session
// checks of a real server are NOT exercised here; the unit tests cover what
// the provider sends.

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/compare"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/dshakes/terraform-provider-halos/internal/halosapi"
)

var protoV6Factories = map[string]func() (tfprotov6.ProviderServer, error){
	"halos": providerserver.NewProtocol6WithError(New("test")()),
}

// accServer is the halo-server shared by the acceptance tests.
var accServer struct {
	url    string
	client *halosapi.Client
	cmd    *exec.Cmd
}

const devAdmin = "boss@acme.example"

func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC") == "" {
		os.Exit(m.Run())
	}
	stop, err := startHalosServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "acceptance setup:", err)
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

func startHalosServer() (func(), error) {
	bin, policy := os.Getenv("HALOS_SERVER_BIN"), os.Getenv("HALOS_POLICY_DIR")
	if bin == "" || policy == "" {
		return nil, fmt.Errorf("TF_ACC needs HALOS_SERVER_BIN and HALOS_POLICY_DIR")
	}
	dir, err := os.MkdirTemp("", "halos-acc-")
	if err != nil {
		return nil, err
	}
	pol := filepath.Join(dir, "policy")
	if err := copyDir(policy, pol); err != nil {
		return nil, fmt.Errorf("copy policy: %w", err)
	}
	agentTok := filepath.Join(dir, "agent-token")
	if err := os.WriteFile(agentTok, []byte("acceptance-agent-token-not-a-secret-0123456789"), 0o600); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cmd := exec.Command(bin, "--policy-dir", pol, "--token-file", agentTok, "--data-dir", filepath.Join(dir, "data"),
		"--listen", addr, "--dev-insecure-user", devAdmin, "--dev-insecure-roles", "admin")
	logf, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		return nil, err
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start halo-server: %w", err)
	}
	stop := func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		_ = logf.Close()
		_ = os.RemoveAll(dir)
	}
	accServer.url, accServer.cmd = "http://"+addr, cmd
	deadline := time.Now().Add(30 * time.Second)
	for {
		resp, err := http.Get(accServer.url + "/api/v1/me")
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == 200 {
				break
			}
			err = fmt.Errorf("HTTP %d: %s", resp.StatusCode, body)
		}
		if time.Now().After(deadline) {
			stop()
			return nil, fmt.Errorf("halo-server did not become ready: %v (log in %s)", err, dir)
		}
		time.Sleep(100 * time.Millisecond)
	}
	// In dev-insecure mode credentials are ignored; the client just needs some.
	accServer.client, err = halosapi.New(halosapi.Config{Endpoint: accServer.url, Token: "halo_sat_dev-insecure-ignored.x", Session: "dev-insecure-ignored"})
	if err != nil {
		stop()
		return nil, err
	}
	return stop, nil
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
}

func accPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC=1 (see the comment at the top of this file)")
	}
	if accServer.client == nil {
		t.Fatal("halo-server is not running: set TF_ACC=1, HALOS_SERVER_BIN and HALOS_POLICY_DIR")
	}
}

func providerBlock() string {
	return fmt.Sprintf(`
provider "halos" {
  endpoint = %q
  token    = "halo_sat_dev-insecure-ignored.x"
  session  = "dev-insecure-ignored"
}
`, accServer.url)
}

func serverToken(t *testing.T, id string) *halosapi.ServiceToken {
	t.Helper()
	tok, err := accServer.client.GetServiceToken(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// stateAttr reads an attribute of a resource in the state under test.
func stateAttr(s *terraform.State, addr, key string) (string, error) {
	rs, ok := s.RootModule().Resources[addr]
	if !ok {
		return "", fmt.Errorf("%s not in state", addr)
	}
	return rs.Primary.Attributes[key], nil
}

const tokenAddr = "halos_service_token.ci"

func tokenConfig(rings string) string {
	return providerBlock() + fmt.Sprintf(`
resource "halos_service_token" "ci" {
  name        = "acc-ci-reporter"
  role        = "viewer"
  ttl         = "720h"
  owner       = "platform"
  description = "acceptance test token"
  scope = {
    rings = [%s]
  }
}
`, rings)
}

func TestAccServiceToken_Lifecycle(t *testing.T) {
	accPreCheck(t)
	var firstID, secondID string
	idsDiffer := statecheck.CompareValue(compare.ValuesDiffer())

	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		// Destroy must have revoked every token it created.
		CheckDestroy: func(s *terraform.State) error {
			for _, id := range []string{firstID, secondID} {
				if id == "" {
					continue
				}
				tok := serverToken(t, id)
				if tok == nil || !tok.Revoked {
					return fmt.Errorf("token %s was not revoked on destroy: %+v", id, tok)
				}
			}
			return nil
		},
		Steps: []resource.TestStep{
			{
				// Create; the plan after apply must be empty.
				Config: tokenConfig(`"ring1-canary"`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PostApplyPreRefresh:  []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
					PostApplyPostRefresh: []plancheck.PlanCheck{plancheck.ExpectEmptyPlan()},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("name"), knownvalue.StringExact("acc-ci-reporter")),
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("role"), knownvalue.StringExact("viewer")),
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("ttl"), knownvalue.StringExact("720h")),
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("token"), knownvalue.StringRegexp(regexp.MustCompile(`^halo_sat_`))),
					statecheck.ExpectSensitiveValue(tokenAddr, tfjsonpath.New("token")),
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("principal"), knownvalue.StringRegexp(regexp.MustCompile(`^.+:acc-ci-reporter:[0-9a-f]{16}$`))),
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("created_by"), knownvalue.StringExact(devAdmin)),
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("scope").AtMapKey("rings"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("ring1-canary")})),
					idsDiffer.AddStateValue(tokenAddr, tfjsonpath.New("id")),
				},
				Check: resource.ComposeAggregateTestCheckFunc(
					func(s *terraform.State) error {
						id, _ := stateAttr(s, tokenAddr, "id")
						firstID = id
						tok := serverToken(t, id)
						switch {
						case tok == nil:
							return fmt.Errorf("token %s does not exist on the server", id)
						case tok.Revoked || tok.Name != "acc-ci-reporter" || tok.Role != "viewer" || tok.Owner != "platform" || tok.Description != "acceptance test token":
							return fmt.Errorf("server record differs: %+v", tok)
						case len(tok.Scope.Rings) != 1 || tok.Scope.Rings[0] != "ring1-canary" || len(tok.Scope.Units) != 0:
							return fmt.Errorf("server scope = %+v", tok.Scope)
						case time.Until(tok.ExpiresAt) < 719*time.Hour:
							return fmt.Errorf("ttl not applied: expires %s", tok.ExpiresAt)
						}
						return nil
					},
				),
			},
			{
				// Import by id: everything is read back except the secret.
				ResourceName:            tokenAddr,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"token"},
				ImportStateCheck: func(states []*terraform.InstanceState) error {
					if len(states) != 1 {
						return fmt.Errorf("imported %d resources", len(states))
					}
					if v, ok := states[0].Attributes["token"]; ok && v != "" {
						return fmt.Errorf("an imported token must have no secret, got %q", v)
					}
					return nil
				},
			},
			{
				// Changing the scope forces a replacement: new id, old token revoked.
				Config: tokenConfig(`"ring2-early"`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(tokenAddr, plancheck.ResourceActionReplace)},
				},
				ConfigStateChecks: []statecheck.StateCheck{
					idsDiffer.AddStateValue(tokenAddr, tfjsonpath.New("id")),
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("scope").AtMapKey("rings"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("ring2-early")})),
				},
				Check: func(s *terraform.State) error {
					id, _ := stateAttr(s, tokenAddr, "id")
					secondID = id
					if old := serverToken(t, firstID); old == nil || !old.Revoked {
						return fmt.Errorf("replaced token %s was not revoked: %+v", firstID, old)
					}
					if cur := serverToken(t, id); cur == nil || cur.Revoked || len(cur.Scope.Rings) != 1 || cur.Scope.Rings[0] != "ring2-early" {
						return fmt.Errorf("replacement token wrong: %+v", cur)
					}
					return nil
				},
			},
			{
				// Revoked behind Terraform's back: refresh drops it from state and the plan creates a new one.
				PreConfig: func() {
					if err := accServer.client.RevokeServiceToken(context.Background(), secondID, "acceptance: out-of-band revoke"); err != nil {
						t.Fatalf("out-of-band revoke: %v", err)
					}
				},
				RefreshState:       true,
				ExpectNonEmptyPlan: true,
			},
			{
				// Apply recreates it; destroy at the end revokes this one (CheckDestroy).
				Config: tokenConfig(`"ring2-early"`),
				Check: func(s *terraform.State) error {
					id, _ := stateAttr(s, tokenAddr, "id")
					if id == secondID {
						return fmt.Errorf("the revoked token %s was kept", id)
					}
					if cur := serverToken(t, id); cur == nil || cur.Revoked {
						return fmt.Errorf("recreated token not active: %+v", cur)
					}
					secondID = id
					return nil
				},
			},
		},
	})
}

func TestAccServiceToken_ServerRejections(t *testing.T) {
	accPreCheck(t)
	bad := func(body string) string {
		return providerBlock() + fmt.Sprintf(`
resource "halos_service_token" "bad" {
  name = "acc-bad"
  role = "viewer"
%s
}
`, body)
	}
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{
			{
				// Validated at plan, before any request.
				Config:      bad(`ttl = "5m"`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`ttl must be at least 1h`),
			},
			{
				Config:      bad(`scope = {}`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`(?s)Empty scope.*rings or units`),
			},
			{
				// A ring that is not in policy: the server's 400 surfaces as a diagnostic.
				Config:      bad(`scope = { rings = ["no-such-ring"] }`),
				ExpectError: regexp.MustCompile(`(?s)Invalid request while creating.*not a ring in policy`),
			},
			{
				// A ttl above the server's maximum.
				Config:      bad(`ttl = "99999h"`),
				ExpectError: regexp.MustCompile(`(?s)Invalid request while creating.*ttl must be between`),
			},
		},
	})
}

func TestAccDataSources(t *testing.T) {
	accPreCheck(t)
	cfg := providerBlock() + `
data "halos_me" "this" {}
data "halos_capabilities" "this" {}
data "halos_releases" "this" {}
data "halos_experiments" "this" {}
data "halos_rollouts" "this" {}
data "halos_kill_switch" "this" {}
data "halos_fleet" "this" {}
`
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{{
			Config: cfg,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.halos_me.this", tfjsonpath.New("id"), knownvalue.StringExact(devAdmin)),
				statecheck.ExpectKnownValue("data.halos_me.this", tfjsonpath.New("admin"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue("data.halos_me.this", tfjsonpath.New("roles"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("admin")})),
				statecheck.ExpectKnownValue("data.halos_capabilities.this", tfjsonpath.New("permissions"), knownvalue.ListPartial(map[int]knownvalue.Check{0: knownvalue.StringExact("read")})),
				statecheck.ExpectKnownValue("data.halos_capabilities.this", tfjsonpath.New("bindings").AtSliceIndex(0).AtMapKey("role"), knownvalue.StringExact("admin")),
				statecheck.ExpectKnownValue("data.halos_releases.this", tfjsonpath.New("rings").AtSliceIndex(1).AtMapKey("ring"), knownvalue.StringExact("ring1-canary")),
				statecheck.ExpectKnownValue("data.halos_experiments.this", tfjsonpath.New("experiments").AtSliceIndex(0).AtMapKey("name"), knownvalue.NotNull()),
				statecheck.ExpectKnownValue("data.halos_rollouts.this", tfjsonpath.New("rollouts").AtSliceIndex(0).AtMapKey("name"), knownvalue.StringExact("claude-code-2.1.300")),
				statecheck.ExpectKnownValue("data.halos_kill_switch.this", tfjsonpath.New("any_active"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue("data.halos_fleet.this", tfjsonpath.New("total"), knownvalue.Int64Exact(0)),
			},
		}},
	})
}
