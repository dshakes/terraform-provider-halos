data "halos_fleet" "this" {}

output "fleet_size" {
  value = data.halos_fleet.this.total
}
