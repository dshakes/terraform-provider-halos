data "halos_me" "this" {}

# Fail the plan early if the credential cannot administer tokens.
check "provider_can_admin" {
  assert {
    condition     = contains(data.halos_me.this.permissions, "admin")
    error_message = "the Halos credential lacks the admin permission"
  }
}
