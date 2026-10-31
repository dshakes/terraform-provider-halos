data "halos_rollouts" "this" {}

output "halted_rollouts" {
  value = [for r in data.halos_rollouts.this.rollouts : r.name if r.halted != ""]
}
