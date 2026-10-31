package provider

// Acceptance tests (TF_ACC=1) run the provider through a real Terraform or
// OpenTofu binary against a real halo-server with real authentication.
//
// Required environment:
//
//	TF_ACC=1
//	TF_ACC_TERRAFORM_PATH   the tofu or terraform binary
//	HALOS_SRC               a checkout of github.com/dshakes/halos (read-only; default
//	                        /Users/shakes/workspace/halos). halo-server and the demo
//	                        mock IdP are built from it with `go build`.
//	GO                      optional: the go binary (default: go from PATH)
//
// For OpenTofu also set TF_ACC_PROVIDER_HOST=registry.opentofu.org and
// TF_ACC_PROVIDER_NAMESPACE=hashicorp.
//
// The stack: halo-server WITHOUT --dev-insecure-user, pointed at the mock IdP
// (deploy/compose/mockidp, which auto-approves the authorization-code flow) as
// its OIDC issuer. The test logs in as alice@acme.com (admin through
// adminGroups) with a cookie jar, which yields a real interactive halo_session.
// That session mints a real admin and a real viewer halo_sat_ token. The
// provider then runs with token + session, as documented. (Break-glass cannot
// stand in: the server refuses to create tokens for it.)
//
// mockidp listens on a hard-coded :8080; it is built with `go build -overlay`
// replacing only that address with $LISTEN, so the Halos tree is not modified.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
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

// acc is the real stack shared by the acceptance tests.
var acc struct {
	url      string
	session  string // a real halo_session cookie value (alice, admin)
	adminTok string // a real halo_sat_ admin token
	viewTok  string // a real halo_sat_ viewer token
	adminID  string
	viewID   string
	// admin is the provider's own client: admin token for reads, session for create.
	admin *halosapi.Client
}

const (
	adminUser       = "alice@acme.com"
	garbageToken    = "halo_sat_0123456789abcdef.GARBAGEGARBAGEGARBAGE"
	defaultHalosSrc = "/Users/shakes/workspace/halos"
)

func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC") == "" {
		os.Exit(m.Run())
	}
	stop, err := startStack()
	if err != nil {
		fmt.Fprintln(os.Stderr, "acceptance setup:", err)
		if stop != nil {
			stop()
		}
		os.Exit(1)
	}
	code := m.Run()
	stop()
	os.Exit(code)
}

func freeAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer func() { _ = ln.Close() }()
	return ln.Addr().String(), nil
}

func goBin() string {
	if g := os.Getenv("GO"); g != "" {
		return g
	}
	return "go"
}

func build(src, out, pkg string, extra ...string) error {
	args := append([]string{"build"}, extra...)
	args = append(args, "-o", out, pkg)
	cmd := exec.Command(goBin(), args...) //nolint:gosec // test helper building a pinned package
	cmd.Dir = src
	if b, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("go build %s: %w\n%s", pkg, err, b)
	}
	return nil
}

func startProc(dir, name string, env []string, bin string, args ...string) (*exec.Cmd, error) {
	logf, err := os.Create(filepath.Join(dir, name+".log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, args...) //nolint:gosec // test helper running binaries it just built
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", name, err)
	}
	return cmd, nil
}

func waitHTTP(u string, ok func(*http.Response) bool) error {
	hc := &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		resp, err := hc.Get(u)
		if err == nil {
			_ = resp.Body.Close()
			if ok(resp) {
				return nil
			}
			err = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("%s not ready: %v", u, last)
}

func startStack() (func(), error) {
	src := os.Getenv("HALOS_SRC")
	if src == "" {
		src = defaultHalosSrc
	}
	dir, err := os.MkdirTemp("", "halos-acc-")
	if err != nil {
		return nil, err
	}
	var procs []*exec.Cmd
	stop := func() {
		for _, c := range procs {
			_ = c.Process.Kill()
			_, _ = c.Process.Wait()
		}
		_ = os.RemoveAll(dir)
	}

	serverBin, idpBin := filepath.Join(dir, "halo-server"), filepath.Join(dir, "mockidp")
	if err := build(src, serverBin, "./cmd/halo-server"); err != nil {
		return stop, err
	}
	// mockidp, with its fixed :8080 replaced by $LISTEN via an overlay (the tree is untouched).
	idpSrc := filepath.Join(src, "deploy/compose/mockidp/main.go")
	orig, err := os.ReadFile(idpSrc) //nolint:gosec // path under the configured Halos checkout
	if err != nil {
		return stop, err
	}
	if !strings.Contains(string(orig), `Addr: ":8080"`) {
		return stop, fmt.Errorf("mockidp no longer hard-codes :8080; drop the overlay in acc_test.go")
	}
	patched := filepath.Join(dir, "mockidp-main.go")
	if err := os.WriteFile(patched, []byte(strings.Replace(string(orig), `Addr: ":8080"`, `Addr: os.Getenv("LISTEN")`, 1)), 0o600); err != nil {
		return stop, err
	}
	overlay := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlay, []byte(fmt.Sprintf(`{"Replace":{%q:%q}}`, idpSrc, patched)), 0o600); err != nil {
		return stop, err
	}
	if err := build(src, idpBin, "./deploy/compose/mockidp", "-overlay", overlay); err != nil {
		return stop, err
	}

	idpAddr, err := freeAddr()
	if err != nil {
		return stop, err
	}
	srvAddr, err := freeAddr()
	if err != nil {
		return stop, err
	}
	idpURL, srvURL := "http://"+idpAddr, "http://"+srvAddr

	// Policy: the acme example with its issuer pointed at the mock IdP.
	pol := filepath.Join(dir, "policy")
	if err := copyDir(filepath.Join(src, "examples/acme-corp"), pol); err != nil {
		return stop, fmt.Errorf("copy policy: %w", err)
	}
	halosYAML := filepath.Join(pol, "halos.yaml")
	b, err := os.ReadFile(halosYAML) //nolint:gosec // our own copy
	if err != nil {
		return stop, err
	}
	const oldIssuer = "issuer: https://acme.okta.com/oauth2/default"
	if !strings.Contains(string(b), oldIssuer) {
		return stop, fmt.Errorf("examples/acme-corp/halos.yaml no longer has %q; update acc_test.go", oldIssuer)
	}
	if err := os.WriteFile(halosYAML, []byte(strings.Replace(string(b), oldIssuer, "issuer: "+idpURL, 1)), 0o600); err != nil {
		return stop, err
	}

	// Secrets are random per run and live only in the temp dir.
	keyRaw := make([]byte, 48)
	if _, err := io.ReadFull(rand.Reader, keyRaw); err != nil {
		return stop, err
	}
	sessKey, agentTok, portal := filepath.Join(dir, "session.key"), filepath.Join(dir, "agent-token"), filepath.Join(dir, "portal.json")
	if err := os.WriteFile(sessKey, []byte(base64.StdEncoding.EncodeToString(keyRaw)), 0o600); err != nil {
		return stop, err
	}
	if err := os.WriteFile(agentTok, []byte(base64.StdEncoding.EncodeToString(keyRaw[:24])), 0o600); err != nil {
		return stop, err
	}
	if err := os.WriteFile(portal, []byte(fmt.Sprintf(`{"baseURL":%q,"sessionKeyFile":%q}`, srvURL, sessKey)), 0o600); err != nil {
		return stop, err
	}

	idp, err := startProc(dir, "mockidp", []string{"ISSUER=" + idpURL, "AUDIENCE=halos-gateway", "LISTEN=" + idpAddr}, idpBin)
	if err != nil {
		return stop, err
	}
	procs = append(procs, idp)
	if err := waitHTTP(idpURL+"/.well-known/openid-configuration", func(r *http.Response) bool { return r.StatusCode == 200 }); err != nil {
		return stop, err
	}
	srv, err := startProc(dir, "halo-server", nil, serverBin, "--policy-dir", pol, "--token-file", agentTok,
		"--data-dir", filepath.Join(dir, "data"), "--listen", srvAddr, "--portal-config", portal)
	if err != nil {
		return stop, err
	}
	procs = append(procs, srv)
	// No credentials: a real server answers 401, a dead one does not answer.
	if err := waitHTTP(srvURL+"/api/v1/me", func(r *http.Response) bool { return r.StatusCode == 401 }); err != nil {
		return stop, fmt.Errorf("%w (logs in %s)", err, dir)
	}

	acc.url = srvURL
	if acc.session, err = oidcLogin(srvURL, adminUser); err != nil {
		return stop, fmt.Errorf("oidc login: %w (logs in %s)", err, dir)
	}
	sess, err := halosapi.New(halosapi.Config{Endpoint: srvURL, Session: acc.session})
	if err != nil {
		return stop, err
	}
	for _, t := range []struct {
		name, role string
		tok, id    *string
	}{{"acc-admin", "admin", &acc.adminTok, &acc.adminID}, {"acc-viewer", "viewer", &acc.viewTok, &acc.viewID}} {
		out, err := sess.CreateServiceToken(context.Background(), halosapi.CreateServiceTokenRequest{Name: t.name, Role: t.role, TTL: "2h"})
		if err != nil {
			return stop, fmt.Errorf("mint %s token with the real session: %w", t.role, err)
		}
		*t.tok, *t.id = out.Token, out.ServiceToken.ID
	}
	acc.admin, err = halosapi.New(halosapi.Config{Endpoint: srvURL, Token: acc.adminTok, Session: acc.session})
	return stop, err
}

// oidcLogin drives the authorization-code flow like a browser: /auth/login,
// the mock IdP's auto-approving /authorize (user= picks the account), then
// /auth/callback. It returns the halo_session cookie value.
func oidcLogin(server, user string) (string, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return "", err
	}
	noFollow := &http.Client{Jar: jar, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := noFollow.Get(server + "/auth/login")
	if err != nil {
		return "", err
	}
	_ = resp.Body.Close()
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || loc == "" {
		return "", fmt.Errorf("/auth/login answered %d without a redirect", resp.StatusCode)
	}
	follow := &http.Client{Jar: jar, Timeout: 10 * time.Second}
	resp, err = follow.Get(loc + "&user=" + url.QueryEscape(user)) // the IdP approves and redirects to /auth/callback
	if err != nil {
		return "", err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	u, _ := url.Parse(server)
	for _, c := range jar.Cookies(u) {
		if c.Name == "halo_session" {
			return c.Value, nil
		}
	}
	return "", fmt.Errorf("no halo_session cookie after the callback (last status %d)", resp.StatusCode)
}

func accPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("acceptance test: set TF_ACC=1 (see the comment at the top of this file)")
	}
	if acc.admin == nil {
		t.Fatal("the halo-server stack is not running: set TF_ACC=1 and HALOS_SRC")
	}
	accEnv(t, acc.adminTok, acc.session)
}

// accEnv gives the provider its credentials through the environment, as a user would.
func accEnv(t *testing.T, token, session string) {
	t.Helper()
	t.Setenv("HALO_SERVER", acc.url)
	t.Setenv("HALO_TOKEN", token)
	t.Setenv("HALO_SESSION", session)
}

func providerBlock() string { return "provider \"halos\" {}\n" }

func serverToken(t *testing.T, id string) *halosapi.ServiceToken {
	t.Helper()
	tok, err := acc.admin.GetServiceToken(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o750)
		}
		b, err := os.ReadFile(p) //nolint:gosec // walking the configured Halos checkout
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
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
					statecheck.ExpectKnownValue(tokenAddr, tfjsonpath.New("created_by"), knownvalue.StringExact(adminUser)),
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
					if err := acc.admin.RevokeServiceToken(context.Background(), secondID, "acceptance: out-of-band revoke"); err != nil {
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
				statecheck.ExpectKnownValue("data.halos_me.this", tfjsonpath.New("id"), knownvalue.StringExact("service-account:acc-admin:"+acc.adminID)),
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

// ---- real-auth cases ----

// realClient builds a client against the real server.
func realClient(t *testing.T, token, session string) *halosapi.Client {
	t.Helper()
	c, err := halosapi.New(halosapi.Config{Endpoint: acc.url, Token: token, Session: session})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// noSecrets fails if text holds any credential the stack knows about.
func noSecrets(t *testing.T, what, text string) {
	t.Helper()
	for _, s := range []string{acc.session, acc.adminTok, acc.viewTok, garbageToken, "GARBAGE"} {
		if strings.Contains(text, s) {
			t.Errorf("%s leaks a credential: %s", what, text)
		}
	}
}

// diagFor maps err the way the provider does and returns the diagnostic text.
func diagFor(t *testing.T, action string, err error) string {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected an error", action)
	}
	d := apiDiag(action, err)
	text := d.Summary() + "\n" + d.Detail()
	noSecrets(t, action, text)
	return text
}

// rawCreate POSTs a create with exactly the headers given, bypassing the client's own auth choice.
func rawCreate(t *testing.T, bearer, cookie string) int {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, acc.url+"/api/v1/service-tokens", strings.NewReader(`{"name":"acc-raw","role":"viewer","ttl":"2h"}`))
	if err != nil {
		t.Fatal(err)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "halo_session", Value: cookie}) //nolint:gosec // request cookie
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

func TestAccRealAuth_GarbageAndRevokedTokensGet401(t *testing.T) {
	accPreCheck(t)
	ctx := context.Background()

	_, err := realClient(t, garbageToken, "").GetMe(ctx)
	if !halosapi.IsStatus(err, 401) {
		t.Fatalf("garbage token: err = %v, want the server's 401", err)
	}
	text := diagFor(t, "reading /api/v1/me", err)
	if !strings.Contains(text, "Authentication failed") || !strings.Contains(text, "invalid service token") {
		t.Errorf("garbage token diagnostic is unclear: %s", text)
	}

	// A real token, revoked: the same 401, from the server's own revocation check.
	out, err := acc.admin.CreateServiceToken(ctx, halosapi.CreateServiceTokenRequest{Name: "acc-soon-revoked", Role: "viewer", TTL: "2h"})
	if err != nil {
		t.Fatal(err)
	}
	victim := realClient(t, out.Token, "")
	if _, err := victim.GetMe(ctx); err != nil {
		t.Fatalf("a fresh real token must work: %v", err)
	}
	if err := acc.admin.RevokeServiceToken(ctx, out.ServiceToken.ID, "acceptance: revoked token"); err != nil {
		t.Fatal(err)
	}
	_, err = victim.GetMe(ctx)
	if !halosapi.IsStatus(err, 401) {
		t.Fatalf("revoked token: err = %v, want the server's 401", err)
	}
	noSecrets(t, "revoked-token diagnostic", diagFor(t, "reading /api/v1/me", err))
	noSecrets(t, "raw error", err.Error()+out.Token)
}

func TestAccRealAuth_ViewerTokenGets403(t *testing.T) {
	accPreCheck(t)
	ctx := context.Background()
	viewer := realClient(t, acc.viewTok, "")

	// Read-level calls work for a viewer.
	if _, err := viewer.GetMe(ctx); err != nil {
		t.Fatalf("viewer GetMe: %v", err)
	}
	// Listing and revoking tokens need admin.
	_, err := viewer.ListServiceTokens(ctx)
	if !halosapi.IsStatus(err, 403) {
		t.Fatalf("viewer list: err = %v, want 403", err)
	}
	if text := diagFor(t, "reading the service token", err); !strings.Contains(text, "Permission denied") {
		t.Errorf("diagnostic: %s", text)
	}
	err = viewer.RevokeServiceToken(ctx, acc.adminID, "acceptance: a viewer must not revoke")
	if !halosapi.IsStatus(err, 403) {
		t.Fatalf("viewer revoke: err = %v, want 403", err)
	}
	if text := diagFor(t, "revoking the service token", err); !strings.Contains(text, "Permission denied") {
		t.Errorf("diagnostic: %s", text)
	}
	if tok := serverToken(t, acc.adminID); tok == nil || tok.Revoked {
		t.Fatal("the admin token was revoked by a viewer")
	}
	// Create: the server refuses a bearer outright (viewer or admin); the provider's
	// client never sends one for create.
	if got := rawCreate(t, acc.viewTok, ""); got != 403 {
		t.Errorf("viewer bearer create = %d, want 403", got)
	}
	if got := rawCreate(t, acc.adminTok, ""); got != 403 {
		t.Errorf("even an admin bearer cannot create: got %d, want 403", got)
	}
	// A viewer token alone has no session, so the provider refuses before any request.
	_, err = viewer.CreateServiceToken(ctx, halosapi.CreateServiceTokenRequest{Name: "acc-nope", Role: "viewer"})
	if err == nil || !strings.Contains(diagFor(t, "creating the service token", err), "interactive admin session") {
		t.Errorf("token-only create: %v", err)
	}
}

func TestAccRealAuth_TokenPlusSessionAsDocumented(t *testing.T) {
	accPreCheck(t)
	ctx := context.Background()

	// Create uses the session (cookie), never the bearer: it works even though the bearer is only a viewer's.
	mixed := realClient(t, acc.viewTok, acc.session)
	out, err := mixed.CreateServiceToken(ctx, halosapi.CreateServiceTokenRequest{Name: "acc-mixed", Role: "viewer", TTL: "2h"})
	if err != nil {
		t.Fatalf("create with viewer token + admin session: %v", err)
	}
	// Everything else uses the token: the viewer bearer cannot list.
	if _, err := mixed.ListServiceTokens(ctx); !halosapi.IsStatus(err, 403) {
		t.Fatalf("list with viewer token + admin session: err = %v, want 403 (reads use the token)", err)
	}
	// And the admin token revokes what the session created.
	if err := acc.admin.RevokeServiceToken(ctx, out.ServiceToken.ID, "acceptance: cleanup"); err != nil {
		t.Fatal(err)
	}
	// A garbage session is a 401, not a silent fallback to the token for create.
	_, err = realClient(t, acc.adminTok, "garbage-session").CreateServiceToken(ctx, halosapi.CreateServiceTokenRequest{Name: "acc-bad-session", Role: "viewer"})
	if !halosapi.IsStatus(err, 401) {
		t.Fatalf("garbage session: err = %v, want 401", err)
	}
	diagFor(t, "creating the service token", err)
}

// Through OpenTofu: the provider surfaces the server's 401 and 403 as diagnostics.
func TestAccRealAuth_ProviderDiagnostics(t *testing.T) {
	accPreCheck(t)
	cfg := providerBlock() + `data "halos_fleet" "this" {}` + "\n"
	resource.Test(t, resource.TestCase{
		ProtoV6ProviderFactories: protoV6Factories,
		Steps: []resource.TestStep{
			{
				PreConfig:   func() { accEnv(t, garbageToken, acc.session) },
				Config:      cfg,
				ExpectError: regexp.MustCompile(`(?s)Authentication failed while reading /api/v1/fleet.*invalid service token`),
			},
			{
				// A viewer token has `read`, so the fleet view is allowed...
				PreConfig: func() { accEnv(t, acc.viewTok, acc.session) },
				Config:    cfg,
			},
			{
				// ...but importing a halos_service_token needs admin (it lists tokens).
				PreConfig: func() { accEnv(t, acc.viewTok, acc.session) },
				Config: providerBlock() + `resource "halos_service_token" "probe" {
  name = "acc-viewer-probe"
  role = "viewer"
}
`,
				ResourceName:  "halos_service_token.probe",
				ImportState:   true,
				ImportStateId: acc.adminID,
				ExpectError:   regexp.MustCompile(`(?s)Permission denied while reading the service token.*HTTP 403`),
			},
		},
	})
}
