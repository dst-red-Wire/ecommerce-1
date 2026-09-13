module "hcloud_qualification" {
  source = "../../modules/hcloud-qualification"

  location           = var.hcloud_location
  image              = var.qualification_image
  server_type        = var.qualification_server_type
  ssh_key_id         = var.qualification_ssh_key_id
  ssh_allowed_cidrs  = var.qualification_ssh_allowed_cidrs
  qualification_user = var.qualification_user
}
