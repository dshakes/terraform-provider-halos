// Command terraform-provider-halos is the Terraform/OpenTofu provider for
// Halos server-side state that is not policy-as-code.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/dshakes/terraform-provider-halos/internal/provider"
)

//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0 generate --provider-name halos --rendered-provider-name Halos

// version is set by goreleaser (-X main.version=...).
var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with debugger support")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/dshakes/halos",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
