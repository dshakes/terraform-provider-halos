data "halos_capabilities" "this" {}

output "kill_switch_configured" {
  value = data.halos_capabilities.this.kill_switch
}
