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
    error_message = "standing SecretID (custody and rotation are slice 2)"
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
    condition = vault_policy.enroll_agent.policy == <<-EOT
      path "auth/maknae-agent-approle/role/+/role-id"                    { capabilities = ["read"] }
      path "auth/maknae-agent-approle/role/+/secret-id"                  { capabilities = ["create", "update"] }
      path "auth/maknae-agent-approle/role/+/secret-id-accessor/destroy" { capabilities = ["update"] }
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
