terraform {
  required_providers {
    halos = {
      source = "dshakes/halos"
    }
  }
}

# endpoint, token and session may instead come from HALO_SERVER, HALO_TOKEN and
# HALO_SESSION, which keeps credentials out of configuration and state.
provider "halos" {
  endpoint = "https://halos.example.com"

  # Optional: trust a private CA, and bound each request.
  # ca_bundle_file = "/etc/ssl/acme-ca.pem"
  # timeout        = "30s"
}
