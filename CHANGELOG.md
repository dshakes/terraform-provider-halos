# Changelog

All notable changes to this provider are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- `halos_service_token` resource: create, read (list and match by id), destroy (revoke), import by id. Every argument forces replacement.
- Data sources `halos_me`, `halos_capabilities`, `halos_releases`, `halos_experiments`, `halos_rollouts`, `halos_kill_switch`, `halos_fleet`.
- Provider arguments `endpoint`, `token`, `session`, `ca_bundle_file`, `timeout` and the `HALO_SERVER`, `HALO_TOKEN`, `HALO_SESSION`, `HALO_CA_BUNDLE_FILE` environment variables.
- Typed API client `internal/halosapi`.
