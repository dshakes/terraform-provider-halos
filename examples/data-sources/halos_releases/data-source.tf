data "halos_releases" "this" {}

# Warn when any ring pointer is stale or any host drifted.
check "no_release_drift" {
  assert {
    condition     = !data.halos_releases.this.stale && alltrue([for r in data.halos_releases.this.rings : r.drift_hosts == 0])
    error_message = "a ring has drifted hosts or the registry view is stale"
  }
}
