mock_provider "vault" {}

variables {
  deployment_id = "test"
  maknae_agents = {
    hobi = {}
    suga = {}
  }
}

run "agents_shape" {
  command = plan

  assert {
    condition     = toset(keys(vault_policy.agent)) == toset(["hobi", "suga"]) && toset(keys(vault_approle_auth_backend_role.agent)) == toset(["hobi", "suga"])
    error_message = "one policy and one AppRole role per agent id"
  }
  assert {
    condition     = vault_auth_backend.agent_approle.path == "maknae-agent-approle" && vault_auth_backend.agent_approle.path != vault_auth_backend.approle.path
    error_message = "agents log in through their own AppRole mount, never maknaed's"
  }
  assert {
    condition     = vault_approle_auth_backend_role.agent["hobi"].role_name == "agent-hobi" && vault_approle_auth_backend_role.agent["hobi"].backend == "maknae-agent-approle"
    error_message = "role agent-<id> on the agent mount"
  }
  assert {
    condition     = vault_approle_auth_backend_role.agent["hobi"].token_policies == toset(["maknae-agent-hobi"])
    error_message = "an agent's token carries exactly its own policy"
  }
  assert {
    condition     = vault_approle_auth_backend_role.agent["hobi"].token_no_default_policy == true
    error_message = "the default policy is never attached"
  }
  assert {
    condition     = vault_approle_auth_backend_role.agent["hobi"].token_ttl == 3600 && vault_approle_auth_backend_role.agent["hobi"].token_max_ttl == 86400 && vault_approle_auth_backend_role.agent["hobi"].token_explicit_max_ttl == 86400
    error_message = "token ttl, max_ttl and the hard explicit_max_ttl come from the variables"
  }
  assert {
    condition     = coalesce(vault_approle_auth_backend_role.agent["hobi"].token_period, 0) == 0
    error_message = "an agent token is never periodic (ADR-0006 decision 9)"
  }
  assert {
    condition     = vault_approle_auth_backend_role.agent["hobi"].secret_id_ttl == 0 && vault_approle_auth_backend_role.agent["hobi"].secret_id_num_uses == 0
    error_message = "standing SecretID (custody and rotation are maknae enroll agent)"
  }
  assert {
    condition     = vault_approle_auth_backend_role.agent["hobi"].bind_secret_id == true && vault_approle_auth_backend_role.agent["hobi"].token_type == "service"
    error_message = "a SecretID is required to log in (the RoleID is a published output), and the token is a revocable service token, never batch (#472 revokes per agent)"
  }
  assert {
    condition     = vault_policy.agent["hobi"].policy == <<-EOT
      path "maknae-kv/data/maknae/agents/hobi/*" {
        capabilities     = ["read"]
        min_wrapping_ttl = "1s"
        max_wrapping_ttl = "300s"
      }
      path "maknae-kv/metadata/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/metadata/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-kv/delete/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/delete/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-kv/destroy/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/destroy/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-kv/undelete/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/undelete/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-kv/subkeys/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/subkeys/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-pki-int/sign/maknae-agent-hobi" {
        capabilities      = ["update"]
        denied_parameters = { "not_after" = [] }
      }
      path "maknae-pki-int/issuer/default/json" { capabilities = ["read"] }
      path "auth/token/renew-self"  { capabilities = ["update"] }
      path "auth/token/lookup-self" { capabilities = ["read"] }
      path "auth/token/revoke-self" { capabilities = ["update"] }
    EOT
    error_message = "hobi's policy is read-only, wrapped (1s-300s) on its own subtree, denies every metadata/delete/destroy/undelete/subkeys path, and grants nothing else"
  }
  assert {
    condition     = strcontains(vault_policy.agent["suga"].policy, "maknae-kv/data/maknae/agents/suga/*") && !strcontains(vault_policy.agent["suga"].policy, "agents/hobi")
    error_message = "each agent's policy names only its own subtree"
  }
  assert {
    condition     = vault_policy.agent_credential_admin.policy == <<-EOT
      path "maknae-kv/data/maknae/agents/*" {
        capabilities = ["create", "read", "update", "patch", "delete", "list"]
      }
      path "maknae-kv/metadata/maknae/agents/*" {
        capabilities = ["read", "list", "delete"]
      }
      path "maknae-kv/delete/maknae/agents/*" { capabilities = ["update"] }
      path "maknae-kv/destroy/maknae/agents/*" { capabilities = ["update"] }
      path "maknae-kv/undelete/maknae/agents/*" { capabilities = ["update"] }
    EOT
    error_message = "the admin policy writes agent credentials and reaches nothing outside the agent prefix"
  }
  assert {
    condition     = vault_policy.enroll_agent.policy == <<-EOT
      path "auth/maknae-agent-approle/role/+/role-id"                    { capabilities = ["read"] }
      path "auth/maknae-agent-approle/role/+/secret-id"                  { capabilities = ["create", "update", "list"] }
      path "auth/maknae-agent-approle/role/+/secret-id-accessor/destroy" { capabilities = ["update"] }
      path "identity/entity/name/maknae-agent-*" {
        capabilities       = ["read", "update"]
        allowed_parameters = { "disabled" = [] }
      }
    EOT
    error_message = "maknae-enroll-agent policy text drifted"
  }
  assert {
    condition     = vault_policy.enroll_agent.name == "maknae-enroll-agent" && output.agent_enroll_policy_name == "maknae-enroll-agent"
    error_message = "maknae-enroll-agent name drifted"
  }
  assert {
    condition     = output.agent_role_names == { hobi = "agent-hobi", suga = "agent-suga" } && output.agent_policy_names == { hobi = "maknae-agent-hobi", suga = "maknae-agent-suga" }
    error_message = "outputs name each agent's role and policy"
  }
  assert {
    condition     = output.agent_credential_admin_policy_name == "maknae-admin-agent-credentials" && output.agent_prefix == "maknae/agents" && output.agent_approle_mount_path == "maknae-agent-approle"
    error_message = "outputs carry the admin policy, prefix and mount"
  }
}

run "no_agents" {
  command = plan

  variables {
    maknae_agents = {}
  }

  assert {
    condition     = length(vault_policy.agent) == 0 && length(vault_approle_auth_backend_role.agent) == 0
    error_message = "no agents, no agent policies or roles"
  }
  assert {
    condition     = vault_policy.agent_credential_admin.name == "maknae-admin-agent-credentials" && vault_auth_backend.agent_approle.path == "maknae-agent-approle"
    error_message = "the admin policy and the agent mount exist with no agents"
  }
  assert {
    condition     = vault_policy.enroll_agent.name == "maknae-enroll-agent"
    error_message = "the agent enrollment policy exists with no agents"
  }
}

run "agent_id_glob_refused" {
  command = plan
  variables {
    maknae_agents = { "hob*" = {} }
  }
  expect_failures = [var.maknae_agents]
}

run "agent_id_slash_refused" {
  command = plan
  variables {
    maknae_agents = { "a/b" = {} }
  }
  expect_failures = [var.maknae_agents]
}

run "agent_id_data_refused" {
  command = plan
  variables {
    maknae_agents = { data = {} }
  }
  expect_failures = [var.maknae_agents]
}

run "agent_id_uppercase_refused" {
  command = plan
  variables {
    maknae_agents = { Hobi = {} }
  }
  expect_failures = [var.maknae_agents]
}

run "agent_id_too_long_refused" {
  command = plan
  variables {
    maknae_agents = { "abcdefghijklmnopqrstuvwxyz0123456" = {} }
  }
  expect_failures = [var.maknae_agents]
}

run "agent_prefix_equal_to_user_prefix_refused" {
  command = plan
  variables {
    agent_prefix = "maknae/users"
  }
  expect_failures = [var.agent_prefix]
}

run "agent_prefix_inside_user_prefix_refused" {
  command = plan
  variables {
    agent_prefix = "maknae/users/agents"
  }
  expect_failures = [var.agent_prefix]
}

run "agent_prefix_containing_user_prefix_refused" {
  command = plan
  variables {
    agent_prefix = "maknae"
  }
  expect_failures = [var.agent_prefix]
}

run "sibling_prefix_is_not_overlap" {
  command = plan
  variables {
    agent_prefix = "maknae/users-agents"
  }
  assert {
    condition     = strcontains(vault_policy.agent["hobi"].policy, "maknae-kv/data/maknae/users-agents/hobi/*")
    error_message = "a prefix that only shares leading characters with user_prefix is not an overlap"
  }
}

run "agent_mount_equal_to_maknaed_mount_refused" {
  command = plan
  variables {
    agent_approle_path = "maknae-approle"
  }
  expect_failures = [vault_auth_backend.agent_approle]
}

run "unbounded_token_refused" {
  command = plan
  variables {
    agent_token_max_ttl = 0
  }
  expect_failures = [var.agent_token_max_ttl]
}

run "ttl_above_max_refused" {
  command = plan
  variables {
    agent_token_ttl     = 7200
    agent_token_max_ttl = 3600
  }
  expect_failures = [var.agent_token_ttl]
}

run "agent_prefix_overlap_refused_with_no_agents" {
  command = plan
  variables {
    maknae_agents = {}
    agent_prefix  = "maknae"
  }
  expect_failures = [var.agent_prefix]
}

run "no_agent_policy_can_take_the_admin_policy_name" {
  command = plan
  variables {
    maknae_agents = { "credential-admin" = {}, "admin-agent-credentials" = {} }
  }
  assert {
    condition     = !startswith(vault_policy.agent_credential_admin.name, "maknae-agent-") && alltrue([for p in vault_policy.agent : p.name != vault_policy.agent_credential_admin.name])
    error_message = "the admin policy's name lies outside the maknae-agent-* namespace, so no agent id can collide with it"
  }
}

run "zero_token_ttl_refused" {
  command = plan
  variables {
    agent_token_ttl = 0
  }
  expect_failures = [var.agent_token_ttl]
}

run "agent_prefix_segment_glob_refused" {
  command = plan
  variables {
    agent_prefix = "maknae/+"
  }
  expect_failures = [var.agent_prefix]
}

run "agent_prefix_trailing_glob_refused" {
  command = plan
  variables {
    agent_prefix = "maknae/*"
  }
  expect_failures = [var.agent_prefix]
}

run "agent_pki_role_and_grant" {
  command = plan

  assert {
    condition     = toset(keys(vault_pki_secret_backend_role.agent)) == toset(["hobi", "suga"]) && vault_pki_secret_backend_role.agent["hobi"].name == "maknae-agent-hobi" && vault_pki_secret_backend_role.agent["hobi"].backend == vault_mount.maknae_int.path
    error_message = "one PKI role maknae-agent-<id> per agent on the intermediate mount"
  }
  assert {
    condition     = vault_pki_secret_backend_role.agent["hobi"].allowed_uri_sans == tolist(["spiffe://test/plane/agent/hobi"]) && vault_pki_secret_backend_role.agent["suga"].allowed_uri_sans == tolist(["spiffe://test/plane/agent/suga"])
    error_message = "each role admits exactly its own agent SAN"
  }
  assert {
    condition     = vault_pki_secret_backend_role.agent["hobi"].use_csr_sans == true && vault_pki_secret_backend_role.agent["hobi"].use_csr_common_name == false
    error_message = "the SAN comes from the CSR, never a CN"
  }
  assert {
    condition     = vault_pki_secret_backend_role.agent["hobi"].allow_ip_sans == false && vault_pki_secret_backend_role.agent["hobi"].allow_localhost == false && vault_pki_secret_backend_role.agent["hobi"].allow_wildcard_certificates == false && length(vault_pki_secret_backend_role.agent["hobi"].allowed_domains) == 0 && length(vault_pki_secret_backend_role.agent["hobi"].allowed_other_sans) == 0 && vault_pki_secret_backend_role.agent["hobi"].require_cn == false && vault_pki_secret_backend_role.agent["hobi"].allow_any_name == false
    error_message = "every other SAN channel is closed"
  }
  assert {
    condition     = vault_pki_secret_backend_role.agent["hobi"].client_flag == true && vault_pki_secret_backend_role.agent["hobi"].server_flag == false && vault_pki_secret_backend_role.agent["hobi"].no_store == true
    error_message = "an agent leaf is client-only and unstored"
  }
  assert {
    condition     = vault_pki_secret_backend_role.agent["hobi"].ttl == "3600" && vault_pki_secret_backend_role.agent["hobi"].max_ttl == "3600"
    error_message = "agent leaf ttl and max_ttl default to 3600 seconds"
  }
  assert {
    condition     = vault_pki_secret_backend_role.agent["hobi"].key_type == local.plane_key.key_type && vault_pki_secret_backend_role.agent["hobi"].parameter_set == local.plane_key.parameter_set && vault_pki_secret_backend_role.agent["hobi"].key_usage == tolist(["DigitalSignature"])
    error_message = "agent keys come from plane_key"
  }
  assert {
    condition     = vault_policy.agent["hobi"].policy == <<-EOT
      path "maknae-kv/data/maknae/agents/hobi/*" {
        capabilities     = ["read"]
        min_wrapping_ttl = "1s"
        max_wrapping_ttl = "300s"
      }
      path "maknae-kv/metadata/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/metadata/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-kv/delete/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/delete/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-kv/destroy/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/destroy/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-kv/undelete/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/undelete/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "maknae-kv/subkeys/maknae/agents/hobi" { capabilities = ["deny"] }
      path "maknae-kv/subkeys/maknae/agents/hobi/*" { capabilities = ["deny"] }
      path "${vault_mount.maknae_int.path}/sign/maknae-agent-hobi" {
        capabilities      = ["update"]
        denied_parameters = { "not_after" = [] }
      }
      path "${vault_mount.maknae_int.path}/issuer/default/json" { capabilities = ["read"] }
      path "auth/token/renew-self"  { capabilities = ["update"] }
      path "auth/token/lookup-self" { capabilities = ["read"] }
      path "auth/token/revoke-self" { capabilities = ["update"] }
    EOT
    error_message = "hobi's policy adds its own sign path and the issuer bundle, and nothing else"
  }
  assert {
    condition     = !strcontains(vault_policy.agent["hobi"].policy, "agent-suga") && !strcontains(vault_policy.agent["hobi"].policy, "revoke\"")
    error_message = "no cross-agent sign path and no revoke path in an agent policy"
  }
}

run "no_agent_policy_grants_certificate_revoke" {
  command = plan

  assert {
    condition     = alltrue([for p in vault_policy.agent : !strcontains(p.policy, "/revoke\"") && !strcontains(p.policy, "revoke-prefix") && !strcontains(p.policy, "/sign/maknae-kernel") && !strcontains(p.policy, "/sign/maknae-cli")])
    error_message = "no agent policy may revoke a certificate or sign for another plane"
  }
}

run "agent_leaf_ttl_above_leaf_ttl_refused" {
  command = plan
  variables {
    agent_leaf_ttl_seconds = 259201
  }
  expect_failures = [var.agent_leaf_ttl_seconds]
}

run "agent_leaf_ttl_zero_refused" {
  command = plan
  variables {
    agent_leaf_ttl_seconds = 0
  }
  expect_failures = [var.agent_leaf_ttl_seconds]
}

run "agent_leaf_ttl_override" {
  command = plan
  variables {
    agent_leaf_ttl_seconds = 600
  }
  assert {
    condition     = vault_pki_secret_backend_role.agent["hobi"].ttl == "600" && vault_pki_secret_backend_role.agent["hobi"].max_ttl == "600"
    error_message = "the agent leaf ttl follows the variable"
  }
}

run "agent_entity_and_alias" {
  command = apply

  assert {
    condition     = vault_identity_entity.agent["hobi"].name == "maknae-agent-hobi" && toset(keys(vault_identity_entity_alias.agent)) == toset(["hobi", "suga"])
    error_message = "one entity maknae-agent-<id> and one alias per agent"
  }
  assert {
    condition     = vault_identity_entity_alias.agent["hobi"].name == vault_approle_auth_backend_role.agent["hobi"].role_id && vault_identity_entity_alias.agent["hobi"].mount_accessor == vault_auth_backend.agent_approle.accessor
    error_message = "the alias is the agent AppRole RoleID on the agent mount accessor"
  }
  assert {
    condition     = vault_identity_entity_alias.agent["hobi"].canonical_id == vault_identity_entity.agent["hobi"].id
    error_message = "the alias belongs to its own entity"
  }
  assert {
    condition     = output.agent_entity_names == { hobi = "maknae-agent-hobi", suga = "maknae-agent-suga" } && output.agent_pki_role_names == { hobi = "maknae-agent-hobi", suga = "maknae-agent-suga" }
    error_message = "outputs name each agent's entity and PKI role"
  }
}

run "every_sign_grant_denies_not_after" {
  command = plan
  variables {
    maknae_users = { alice = { password_version = 1 } }
  }

  assert {
    condition     = alltrue([for id, p in vault_policy.agent : strcontains(p.policy, "sign/maknae-agent-${id}\" {\n  capabilities      = [\"update\"]\n  denied_parameters = { \"not_after\" = [] }\n}")])
    error_message = "every agent sign grant denies a caller-supplied not_after"
  }
  assert {
    condition     = strcontains(vault_policy.maknae_kernel.policy, "sign/maknae-kernel\" {\n  capabilities      = [\"update\"]\n  denied_parameters = { \"not_after\" = [] }\n}")
    error_message = "the kernel sign grant denies a caller-supplied not_after"
  }
  assert {
    condition     = strcontains(vault_policy.maknae_user.policy, "sign/maknae-cli\" {\n  capabilities      = [\"update\"]\n  denied_parameters = { \"not_after\" = [] }\n}")
    error_message = "the CLI sign grant denies a caller-supplied not_after"
  }
}

run "user_key_in_the_agent_entity_namespace_refused" {
  command = plan
  variables {
    maknae_users = { "agent-hobi" = { password_version = 1 } }
  }
  expect_failures = [var.maknae_users]
}

run "user_keys_near_the_agent_prefix_accepted" {
  command = plan
  variables {
    maknae_users = { agentx = { password_version = 1 }, agent = { password_version = 1 } }
  }
  assert {
    condition     = vault_identity_entity.maknae_user["agentx"].name == "maknae-agentx" && vault_identity_entity.maknae_user["agent"].name == "maknae-agent"
    error_message = "only keys starting with agent- collide with the maknae-agent-* entity namespace"
  }
}
