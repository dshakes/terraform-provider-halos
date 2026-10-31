.PHONY: build test lint docs testacc
build:
	go build ./...

test:
	go test -race ./...

lint:
	golangci-lint run ./...

# Regenerate docs/ from the schema, examples/ and templates/ (needs terraform or tofu on PATH).
docs:
	go generate ./...

# Acceptance: HALOS_SERVER_BIN and HALOS_POLICY_DIR must be set (see internal/provider/acc_test.go).
testacc:
	TF_ACC=1 go test -race -count=1 -v ./internal/provider/
