data "halos_kill_switch" "this" {}

# Alert (do not act) when something is killed: unkill is a human decision.
check "nothing_killed" {
  assert {
    condition     = !data.halos_kill_switch.this.any_active
    error_message = "the Halos kill switch is active; see `halo kill list`"
  }
}
