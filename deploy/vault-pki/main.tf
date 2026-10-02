# Maknae Vault PKI (dev) — CA chain, plane roles and policies, the maknaed AppRole, the userpass users.
# All wiring is by resource reference so Terraform derives the create-ordering edges.

# ---- Root CA (dedicated Maknae dev root; signs exactly one intermediate) --------
resource "vault_mount" "maknae_root" {
  path                  = var.root_mount_path
  type                  = "pki"
  description           = "Maknae dedicated dev Root CA"
  max_lease_ttl_seconds = var.root_ttl_seconds
}

resource "vault_pki_secret_backend_root_cert" "maknae_root" {
  backend        = vault_mount.maknae_root.path
  type           = "internal" # private key stays in Vault; never enters TF state
  common_name    = "Maknae Dev Root CA"
  key_type       = "ec"
  key_bits       = 384
  signature_bits = 384
  ttl            = "${var.root_ttl_seconds}s" # backend cert ttl is a DURATION STRING
  issuer_name    = "maknae-root"
}

resource "vault_mount" "maknae_kv" {
  path        = var.kv_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "Maknae provider API keys, one subtree per Vault user"
}

# ---- Intermediate CA (the one and only intermediate; issues plane leaves) -------
resource "vault_mount" "maknae_int" {
  path                  = var.int_mount_path
  type                  = "pki"
  description           = "Maknae Intermediate CA (issues plane leaves)"
  max_lease_ttl_seconds = var.int_ttl_seconds # >= leaf_ttl_seconds (enforced below)

  # Fail closed at PLAN time if an override inverts the lifetime hierarchy. Vault would
  # otherwise reject the apply or silently cap leaves below their configured role TTL,
  # leaving the PKI immediately unusable. Preconditions (TF >= 1.2) reference vars only.
  lifecycle {
    precondition {
      condition     = var.root_ttl_seconds >= var.int_ttl_seconds
      error_message = "root_ttl_seconds (${var.root_ttl_seconds}) must be >= int_ttl_seconds (${var.int_ttl_seconds}): the root must outlive the intermediate it signs."
    }
    precondition {
      condition     = var.int_ttl_seconds >= var.leaf_ttl_seconds
      error_message = "int_ttl_seconds (${var.int_ttl_seconds}) must be >= leaf_ttl_seconds (${var.leaf_ttl_seconds}): the intermediate mount max_lease caps leaf TTLs, so a smaller value silently truncates plane certs."
    }
  }
}

resource "vault_pki_secret_backend_intermediate_cert_request" "maknae_int" {
  backend     = vault_mount.maknae_int.path
  type        = "internal"
  common_name = "Maknae Dev Intermediate CA"
  key_type    = "ec"
  key_bits    = 384
}

resource "vault_pki_secret_backend_root_sign_intermediate" "maknae_int" {
  backend        = vault_mount.maknae_root.path
  csr            = vault_pki_secret_backend_intermediate_cert_request.maknae_int.csr
  common_name    = "Maknae Dev Intermediate CA"
  signature_bits = 384
  ttl            = "${var.int_ttl_seconds}s"
}

resource "vault_pki_secret_backend_intermediate_set_signed" "maknae_int" {
  backend = vault_mount.maknae_int.path
  # Signed intermediate concatenated with the root cert forms the chain the mount serves.
  certificate = "${vault_pki_secret_backend_root_sign_intermediate.maknae_int.certificate}\n${vault_pki_secret_backend_root_cert.maknae_root.certificate}"
}

# ---- Plane roles — every SAN channel but the plane URI-SAN is closed ------------
# The provider DEFAULTS allow_ip_sans / allow_localhost / allow_wildcard_certificates
# to TRUE; omitting them is a real SAN escape. Pin them all off on BOTH roles.
resource "vault_pki_secret_backend_role" "maknae_kernel" {
  backend        = vault_mount.maknae_int.path
  name           = "maknae-kernel"
  key_type       = "ec"
  key_bits       = 384
  signature_bits = 384

  allowed_uri_sans    = ["maknae://${var.deployment_id}/plane/kernel"]
  use_csr_sans        = true  # honor the plane's URI-SAN as presented in its CSR
  use_csr_common_name = false # the URI-SAN is the WHOLE identity — never take a CN from the CSR

  allow_ip_sans               = false
  allow_localhost             = false
  allow_wildcard_certificates = false
  allowed_domains             = []
  allowed_other_sans          = []
  require_cn                  = false
  allow_any_name              = false

  client_flag = true # each plane is both TLS client and server on the socket
  server_flag = true

  ttl     = var.leaf_ttl_seconds # role ttl/max_ttl are INTEGER SECONDS (not "${..}s")
  max_ttl = var.leaf_ttl_seconds
}

resource "vault_pki_secret_backend_role" "maknae_cli" {
  backend        = vault_mount.maknae_int.path
  name           = "maknae-cli"
  key_type       = "ec"
  key_bits       = 384
  signature_bits = 384

  allowed_uri_sans    = ["maknae://${var.deployment_id}/plane/cli"]
  use_csr_sans        = true
  use_csr_common_name = false # the URI-SAN is the WHOLE identity — never take a CN from the CSR

  allow_ip_sans               = false
  allow_localhost             = false
  allow_wildcard_certificates = false
  allowed_domains             = []
  allowed_other_sans          = []
  require_cn                  = false
  allow_any_name              = false

  client_flag = true
  server_flag = true

  ttl     = var.leaf_ttl_seconds
  max_ttl = var.leaf_ttl_seconds
}

# ---- Per-plane policies — signing-scoped isolation ------------------------------
# Paths INTERPOLATE from the mount resource (heredoc supports ${..}); a hardcoded
# literal would silently 403 an overridden-mount deployment.
# renew-self / lookup-self / revoke-self are re-granted explicitly because
# token_no_default_policy (AppRoles below) drops Vault's built-in `default` policy —
# its sole grantor. revoke-self lets the maknae-vault plane client revoke its token on
# shutdown per ADR-0005 (zero-trust: don't leave a usable token to live out its TTL).
# Without it the client's best-effort shutdown revoke 403s and the token lingers until
# its lease lapses (worse for the daemon's periodic token, which otherwise renews indefinitely).
resource "vault_policy" "maknae_kernel" {
  name   = "maknae-kernel"
  policy = <<-EOT
    path "${vault_mount.maknae_int.path}/sign/maknae-kernel"  { capabilities = ["update"] }
    path "${vault_mount.maknae_int.path}/revoke"              { capabilities = ["update"] }
    path "${vault_mount.maknae_int.path}/issuer/default/json" { capabilities = ["read"] }
    path "auth/token/renew-self"  { capabilities = ["update"] }
    path "auth/token/lookup-self" { capabilities = ["read"] }
    path "auth/token/revoke-self" { capabilities = ["update"] }
  EOT
}

# ---- Operator enroll policy — grants `maknae enroll` its own-token privileges --
# `maknae enroll` runs under the OPERATOR's own Vault token, not the plane's
# AppRole token, so it needs its own least-privilege policy: read the `maknaed`
# RoleID, mint/destroy its SecretIDs, and read the intermediate issuer
# bundle it hands to the daemon and CLI at enrollment. AUTH-METHOD paths need the literal `auth/`
# prefix (vault_auth_backend.approle.path is the BARE mount name; vaultrs/Vault
# addresses auth methods under `auth/<mount>` — omitting the prefix 403s every
# enroll op). The PKI issuer path takes NO prefix (secret engines mount at root),
# mirroring how maknae_kernel/maknae_user interpolate the int-mount path.
# No `list` anywhere (§4.5): enroll destroys SecretID accessors by the id it
# recorded at creation time, never by listing the mount's accessors.
resource "vault_policy" "maknae_enroll" {
  name   = "maknae-enroll"
  policy = <<-EOT
    path "auth/${vault_auth_backend.approle.path}/role/maknaed/role-id"                    { capabilities = ["read"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknaed/secret-id"                   { capabilities = ["create","update"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknaed/secret-id-accessor/destroy" { capabilities = ["update"] }
    path "${vault_mount.maknae_int.path}/issuer/default/json"                               { capabilities = ["read"] }
  EOT
}

# ---- AppRole auth (dedicated mount; NOT the shared default 'approle') -----------
resource "vault_auth_backend" "approle" {
  type = "approle"
  path = var.approle_path
}

# Token & SecretID model per ADR-0018 (supersedes ADR-0005's single-use / max-ttl clauses):
#  - maknaed (daemon): a PERIODIC token (token_period, no max-ttl ceiling) the plane renews
#    indefinitely; fail-closed only on genuine Vault failure or revocation, never on a
#    scheduled self-outage. Its SecretID is STANDING (num_uses=0, ttl=0) so reboots re-login
#    hands-free; the bootstrap secret is _maknae-owned and HRoT-sealed at rest by
#    `maknae enroll` (the daemon holds no SecretID-minting capability).
# token_no_default_policy drops `default`; the per-plane policy above re-grants
# renew-self/lookup-self/revoke-self so renewal + zero-trust shutdown-revoke still work.
# secret_id_ttl and secret_id_num_uses are HARD-CODED to 0 (not variables): a standing
# SecretID is an ADR-0018 invariant, and an advisory default would let a stale override
# silently reintroduce a time-expiring SecretID (fail closed, not advisory) — see variables.tf.
resource "vault_approle_auth_backend_role" "maknaed" {
  backend                 = vault_auth_backend.approle.path
  role_name               = "maknaed"
  token_policies          = [vault_policy.maknae_kernel.name] # reference, not raw string
  secret_id_ttl           = 0                                 # ADR-0018 invariant: standing (non-expiring) bootstrap SecretID
  secret_id_num_uses      = 0                                 # ADR-0018 invariant: unlimited logins (hands-free reboots)
  token_period            = var.token_period                  # PERIODIC token — renews indefinitely
  token_max_ttl           = 0                                 # no ceiling; only Vault failure/revoke fails closed
  token_no_default_policy = true
}

resource "vault_auth_backend" "userpass" {
  type = "userpass"
  path = var.userpass_mount
}

resource "vault_policy" "maknae_user" {
  name   = "maknae-user"
  policy = <<-EOT
    path "${vault_mount.maknae_kv.path}/data/${var.user_prefix}/{{identity.entity.aliases.${vault_auth_backend.userpass.accessor}.name}}/*" {
      capabilities     = ["create", "read", "update", "delete", "list"]
      min_wrapping_ttl = "1s"
    }
    path "${vault_mount.maknae_kv.path}/metadata/${var.user_prefix}/{{identity.entity.aliases.${vault_auth_backend.userpass.accessor}.name}}/*" {
      capabilities = ["read", "list", "delete"]
    }
    path "${vault_mount.maknae_int.path}/sign/${vault_pki_secret_backend_role.maknae_cli.name}" { capabilities = ["update"] }
    path "auth/token/lookup-self" { capabilities = ["read"] }
    path "auth/token/revoke-self" { capabilities = ["update"] }
  EOT
}

ephemeral "random_password" "maknae_user" {
  for_each = var.maknae_users
  length   = 32
}

resource "vault_userpass_auth_backend_user" "maknae" {
  for_each                = var.maknae_users
  mount                   = vault_auth_backend.userpass.path
  username                = each.key
  password_wo             = ephemeral.random_password.maknae_user[each.key].result
  password_wo_version     = each.value.password_version
  token_policies          = []
  token_ttl               = 28800
  token_max_ttl           = 86400
  token_no_default_policy = true
}

resource "vault_identity_entity" "maknae_user" {
  for_each = var.maknae_users
  name     = each.key
}

resource "vault_identity_entity_alias" "maknae_user" {
  for_each       = var.maknae_users
  name           = each.key
  mount_accessor = vault_auth_backend.userpass.accessor
  canonical_id   = vault_identity_entity.maknae_user[each.key].id
}

resource "vault_identity_group" "maknae_users" {
  name              = "maknae-users"
  type              = "internal"
  policies          = [vault_policy.maknae_user.name]
  member_entity_ids = [for e in vault_identity_entity.maknae_user : e.id]
}
