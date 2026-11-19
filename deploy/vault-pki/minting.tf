locals {
  minting = length(var.github_apps) > 0
}

resource "vault_mount" "transit" {
  count = local.minting ? 1 : 0
  path  = var.transit_mount_path
  type  = "transit"
}

resource "vault_auth_backend" "egress_approle" {
  count = local.minting ? 1 : 0
  type  = "approle"
  path  = var.egress_approle_path
}

resource "vault_policy" "egress_minting" {
  count = local.minting ? 1 : 0
  name  = "maknae-egress-minting"
  policy = join("", [
    for name in sort(keys(var.github_apps)) :
    "path \"${var.transit_mount_path}/sign/${var.github_apps[name].transit_key}/sha2-256\" { capabilities = [\"update\"] }\n"
  ])
}

resource "vault_approle_auth_backend_role" "egress" {
  count                   = local.minting ? 1 : 0
  backend                 = vault_auth_backend.egress_approle[0].path
  role_name               = "maknae-egress"
  token_policies          = [vault_policy.egress_minting[0].name]
  token_ttl               = var.egress_token_ttl
  token_max_ttl           = var.egress_token_max_ttl
  token_explicit_max_ttl  = var.egress_token_max_ttl
  token_bound_cidrs       = var.egress_bind_cidrs
  secret_id_bound_cidrs   = var.egress_bind_cidrs
  secret_id_ttl           = 0
  secret_id_num_uses      = 0
  token_no_default_policy = true
  bind_secret_id          = true
  token_type              = "service"
}
