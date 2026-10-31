# A read-only token for a dashboard, valid for 30 days and limited to one ring.
resource "halos_service_token" "dashboard" {
  name        = "fleet-dashboard"
  role        = "viewer"
  ttl         = "720h"
  owner       = "platform"
  description = "Grafana datasource for the canary ring"

  scope = {
    rings = ["ring1-canary"]
  }
}

# The secret exists only in state: send it straight to a secret manager and
# keep state encrypted.
output "dashboard_token" {
  value     = halos_service_token.dashboard.token
  sensitive = true
}
