data "halos_experiments" "this" {}

output "running_experiments" {
  value = [for e in data.halos_experiments.this.experiments : e.name if e.status == "running"]
}
