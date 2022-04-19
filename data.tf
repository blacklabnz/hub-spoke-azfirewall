data "external" "my_ip" {
  program = ["curl", "https://api.ipify.org?format=json"]
}