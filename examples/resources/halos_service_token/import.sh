# Import by token id (the 16 hex characters from `halo service-token list`).
# The secret cannot be recovered: `token` stays null.
terraform import halos_service_token.dashboard 0123456789abcdef
