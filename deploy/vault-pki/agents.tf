locals {
  agent_kv = "${vault_mount.maknae_kv.path}/%s/${var.agent_prefix}/%s"
}

# Keeps agent login leases off maknaed's prefix (ADR-0006 decision 9).
resource "vault_auth_backend" "agent_approle" {
  type = "approle"
  path = var.agent_approle_path

  lifecycle {
    precondition {
      condition     = var.agent_approle_path != var.approle_path
      error_message = "agent_approle_path must differ from approle_path: agent and maknaed logins must not share a lease prefix (ADR-0006 decision 9)."
    }
  }
}

resource "vault_policy" "agent" {
  for_each = var.maknae_agents
  name     = "maknae-agent-${each.key}"
  policy   = <<-EOT
    path "${format(local.agent_kv, "data", each.key)}/*" {
      capabilities     = ["read"]
      min_wrapping_ttl = "1s"
      max_wrapping_ttl = "300s"
    }
    path "${format(local.agent_kv, "metadata", each.key)}" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "metadata", each.key)}/*" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "delete", each.key)}" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "delete", each.key)}/*" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "destroy", each.key)}" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "destroy", each.key)}/*" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "undelete", each.key)}" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "undelete", each.key)}/*" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "subkeys", each.key)}" { capabilities = ["deny"] }
    path "${format(local.agent_kv, "subkeys", each.key)}/*" { capabilities = ["deny"] }
    path "auth/token/renew-self"  { capabilities = ["update"] }
    path "auth/token/lookup-self" { capabilities = ["read"] }
    path "auth/token/revoke-self" { capabilities = ["update"] }
  EOT
}

resource "vault_approle_auth_backend_role" "agent" {
  for_each                = var.maknae_agents
  backend                 = vault_auth_backend.agent_approle.path
  role_name               = "agent-${each.key}"
  token_policies          = [vault_policy.agent[each.key].name]
  token_ttl               = var.agent_token_ttl
  token_max_ttl           = var.agent_token_max_ttl
  token_explicit_max_ttl  = var.agent_token_max_ttl
  secret_id_ttl           = 0
  secret_id_num_uses      = 0
  token_no_default_policy = true
  bind_secret_id          = true
  token_type              = "service"
}

resource "vault_policy" "agent_credential_admin" {
  name   = "maknae-admin-agent-credentials"
  policy = <<-EOT
    path "${vault_mount.maknae_kv.path}/data/${var.agent_prefix}/*" {
      capabilities = ["create", "read", "update", "patch", "delete", "list"]
    }
    path "${vault_mount.maknae_kv.path}/metadata/${var.agent_prefix}/*" {
      capabilities = ["read", "list", "delete"]
    }
    path "${vault_mount.maknae_kv.path}/delete/${var.agent_prefix}/*" { capabilities = ["update"] }
    path "${vault_mount.maknae_kv.path}/destroy/${var.agent_prefix}/*" { capabilities = ["update"] }
    path "${vault_mount.maknae_kv.path}/undelete/${var.agent_prefix}/*" { capabilities = ["update"] }
  EOT
}
