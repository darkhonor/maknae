mock_provider "vault" {}

variables {
  deployment_id = "test"
}

run "no_apps_plans_no_minting" {
  command = plan

  assert {
    condition     = length(vault_mount.transit) == 0 && length(vault_policy.egress_minting) == 0 && length(vault_approle_auth_backend_role.egress) == 0 && length(vault_auth_backend.egress_approle) == 0
    error_message = "with no github_apps there is no Transit mount, egress mount, role or policy"
  }
  assert {
    condition     = output.egress_role_name == null && output.egress_minting_policy_name == null
    error_message = "the egress outputs are null with no github_apps"
  }
}

run "one_app" {
  command = plan
  variables {
    github_apps       = { acme = { transit_key = "gh-acme" } }
    egress_bind_cidrs = ["10.0.0.5/32"]
  }

  assert {
    condition     = vault_policy.egress_minting[0].name == "maknae-egress-minting" && vault_policy.egress_minting[0].policy == <<-EOT
      path "maknae-transit/sign/gh-acme/sha2-256" { capabilities = ["update"] }
    EOT
    error_message = "the egress policy signs with exactly the one App's key"
  }
  assert {
    condition     = vault_mount.transit[0].path == "maknae-transit" && vault_mount.transit[0].type == "transit"
    error_message = "the Transit mount is created at transit_mount_path"
  }
  assert {
    condition     = vault_auth_backend.egress_approle[0].path == "maknae-egress-approle" && vault_auth_backend.egress_approle[0].type == "approle"
    error_message = "egress logs in through its own AppRole mount"
  }
  assert {
    condition     = vault_approle_auth_backend_role.egress[0].role_name == "maknae-egress" && vault_approle_auth_backend_role.egress[0].backend == "maknae-egress-approle" && vault_approle_auth_backend_role.egress[0].token_policies == toset(["maknae-egress-minting"])
    error_message = "role maknae-egress carries exactly the minting policy"
  }
  assert {
    condition     = vault_approle_auth_backend_role.egress[0].bind_secret_id == true && vault_approle_auth_backend_role.egress[0].token_type == "service" && vault_approle_auth_backend_role.egress[0].token_no_default_policy == true
    error_message = "a SecretID is required, the token is a service token and the default policy is never attached"
  }
  assert {
    condition     = vault_approle_auth_backend_role.egress[0].secret_id_bound_cidrs == toset(["10.0.0.5/32"]) && vault_approle_auth_backend_role.egress[0].token_bound_cidrs == toset(["10.0.0.5/32"])
    error_message = "SecretID and token are bound to egress_bind_cidrs"
  }
  assert {
    condition     = vault_approle_auth_backend_role.egress[0].token_ttl == 900 && vault_approle_auth_backend_role.egress[0].token_max_ttl == 3600 && vault_approle_auth_backend_role.egress[0].token_explicit_max_ttl == 3600 && coalesce(vault_approle_auth_backend_role.egress[0].token_period, 0) == 0
    error_message = "token ttl 900, max ttl 3600, never periodic"
  }
  assert {
    condition     = output.egress_role_name == "maknae-egress" && output.egress_minting_policy_name == "maknae-egress-minting" && output.egress_approle_mount_path == "maknae-egress-approle"
    error_message = "outputs name the egress role, policy and mount"
  }
}

run "two_apps_sorted_by_map_key" {
  command = plan
  variables {
    github_apps = {
      zeta  = { transit_key = "gh-a" }
      alpha = { transit_key = "gh-z" }
    }
    egress_bind_cidrs = ["10.0.0.5/32"]
  }

  assert {
    condition     = vault_policy.egress_minting[0].policy == <<-EOT
      path "maknae-transit/sign/gh-z/sha2-256" { capabilities = ["update"] }
      path "maknae-transit/sign/gh-a/sha2-256" { capabilities = ["update"] }
    EOT
    error_message = "one block per App, ordered by map key"
  }
}

run "policy_grants_nothing_else" {
  command = plan
  variables {
    github_apps = {
      zeta  = { transit_key = "gh-a" }
      alpha = { transit_key = "gh-z" }
    }
    egress_bind_cidrs  = ["10.0.0.5/32"]
    transit_mount_path = "tr"
  }

  assert {
    condition     = !strcontains(vault_policy.egress_minting[0].policy, "kv") && !strcontains(vault_policy.egress_minting[0].policy, "data/") && !strcontains(vault_policy.egress_minting[0].policy, "metadata/") && !strcontains(vault_policy.egress_minting[0].policy, "export") && !strcontains(vault_policy.egress_minting[0].policy, "keys/")
    error_message = "the egress policy names no KV, export or key-management path"
  }
  assert {
    condition     = length(regexall("capabilities", vault_policy.egress_minting[0].policy)) == 2 && length(regexall("\\[\"update\"\\]", vault_policy.egress_minting[0].policy)) == 2
    error_message = "every grant is update and nothing else"
  }
  assert {
    condition     = strcontains(vault_policy.egress_minting[0].policy, "path \"tr/sign/gh-z/sha2-256\"")
    error_message = "the policy follows transit_mount_path"
  }
}

run "enroll_policy_gains_the_egress_paths" {
  command = plan

  assert {
    condition     = vault_policy.maknae_enroll.policy == <<-EOT
      path "auth/maknae-approle/role/maknaed/role-id"                    { capabilities = ["read"] }
      path "auth/maknae-approle/role/maknaed/secret-id"                   { capabilities = ["create","update"] }
      path "auth/maknae-approle/role/maknaed/secret-id-accessor/destroy" { capabilities = ["update"] }
      path "maknae-pki-int/issuer/default/json"                               { capabilities = ["read"] }
      path "auth/maknae-egress-approle/role/maknae-egress/role-id"                    { capabilities = ["read"] }
      path "auth/maknae-egress-approle/role/maknae-egress/secret-id"                  { capabilities = ["create", "update", "list"] }
      path "auth/maknae-egress-approle/role/maknae-egress/secret-id-accessor/destroy" { capabilities = ["update"] }
    EOT
    error_message = "maknae-enroll names the egress role-id and SecretID paths"
  }
}

run "egress_mount_equal_to_maknaed_mount_refused" {
  command = plan
  variables {
    egress_approle_path = "maknae-approle"
  }
  expect_failures = [var.egress_approle_path]
}

run "egress_mount_equal_to_agent_mount_refused" {
  command = plan
  variables {
    egress_approle_path = "maknae-agent-approle"
  }
  expect_failures = [var.egress_approle_path]
}

run "transit_key_with_a_glob_refused" {
  command = plan
  variables {
    github_apps       = { acme = { transit_key = "gh-*" } }
    egress_bind_cidrs = ["10.0.0.5/32"]
  }
  expect_failures = [var.github_apps]
}

run "transit_key_with_a_slash_refused" {
  command = plan
  variables {
    github_apps       = { acme = { transit_key = "a/b" } }
    egress_bind_cidrs = ["10.0.0.5/32"]
  }
  expect_failures = [var.github_apps]
}

run "app_name_with_a_glob_refused" {
  command = plan
  variables {
    github_apps       = { "ac*" = { transit_key = "gh-acme" } }
    egress_bind_cidrs = ["10.0.0.5/32"]
  }
  expect_failures = [var.github_apps]
}

run "apps_without_bind_cidrs_refused" {
  command = plan
  variables {
    github_apps = { acme = { transit_key = "gh-acme" } }
  }
  expect_failures = [var.egress_bind_cidrs]
}

run "malformed_bind_cidr_refused" {
  command = plan
  variables {
    egress_bind_cidrs = ["not-a-cidr"]
  }
  expect_failures = [var.egress_bind_cidrs]
}

run "egress_ttl_above_max_refused" {
  command = plan
  variables {
    egress_token_ttl     = 7200
    egress_token_max_ttl = 3600
  }
  expect_failures = [var.egress_token_ttl]
}

run "zero_egress_token_ttl_refused" {
  command = plan
  variables {
    egress_token_ttl = 0
  }
  expect_failures = [var.egress_token_ttl]
}
