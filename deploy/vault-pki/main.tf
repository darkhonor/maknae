# Maknae Vault PKI (dev) — CA chain, plane roles, per-plane policies, AppRoles.
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

# ---- Intermediate CA (the one and only intermediate; issues plane leaves) -------
# The KV v2 mount for platform secrets the daemons read and the CLI never can
# (#243, ADR-0023 decision 3): the model provider's API key lives at
# `<kv>/data/<provider.key_vault_path>`. NO policy here grants a read on it —
# the `maknae-egress` principal that does is #240's, and the CLI policy below
# names no KV path at all. Mounting it is the whole of #243's Vault obligation.
resource "vault_mount" "maknae_kv" {
  path        = var.kv_mount_path
  type        = "kv"
  options     = { version = "2" }
  description = "Maknae platform secrets (provider API keys) — read by maknae-egress only"
}

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

resource "vault_policy" "maknae_cli" {
  name   = "maknae-cli"
  policy = <<-EOT
    path "${vault_mount.maknae_int.path}/sign/maknae-cli"     { capabilities = ["update"] }
    path "${vault_mount.maknae_int.path}/revoke"              { capabilities = ["update"] }
    path "${vault_mount.maknae_int.path}/issuer/default/json" { capabilities = ["read"] }
    path "auth/token/renew-self"  { capabilities = ["update"] }
    path "auth/token/lookup-self" { capabilities = ["read"] }
    path "auth/token/revoke-self" { capabilities = ["update"] }
  EOT
}

# ---- #240a: the egress deputy's policy -----------------------------------------
# The THIRD plane. Deliberately the narrowest of the three: a read on the
# provider-key prefix and its own token lifecycle, and nothing else. No
# `pki/sign` role — the deputy's socket carries NO on-host mTLS (ADR-0023
# decision 3's recorded delta); its peer is authenticated by peer credentials,
# so there is no plane certificate for it to sign and no URI SAN to verify.
#
# The PREFIX, not a literal path: a second provider must not require a policy
# change and a re-enrolment. The blast radius is stated and accepted — a
# compromised deputy can read every provider key, which is the same reach it
# already has by holding the only route out.
resource "vault_policy" "maknae_egress" {
  name   = "maknae-egress"
  policy = <<-EOT
    path "${vault_mount.maknae_kv.path}/data/${var.provider_key_prefix}/*" { capabilities = ["read"] }
    path "auth/token/renew-self"  { capabilities = ["update"] }
    path "auth/token/lookup-self" { capabilities = ["read"] }
    path "auth/token/revoke-self" { capabilities = ["update"] }
  EOT
}

# ---- Operator enroll policy — grants `maknae enroll` its own-token privileges --
# `maknae enroll` runs under the OPERATOR's own Vault token, not either plane's
# AppRole token, so it needs its own least-privilege policy: read both RoleIDs,
# mint/destroy both SecretIDs, and read the intermediate issuer bundle it hands to
# the daemon and CLI at enrollment. AUTH-METHOD paths need the literal `auth/`
# prefix (vault_auth_backend.approle.path is the BARE mount name; vaultrs/Vault
# addresses auth methods under `auth/<mount>` — omitting the prefix 403s every
# enroll op). The PKI issuer path takes NO prefix (secret engines mount at root),
# mirroring how maknae_kernel/maknae_cli interpolate the int-mount path above.
# No `list` anywhere (§4.5): enroll destroys SecretID accessors by the id it
# recorded at creation time, never by listing the mount's accessors.
resource "vault_policy" "maknae_enroll" {
  name   = "maknae-enroll"
  policy = <<-EOT
    path "auth/${vault_auth_backend.approle.path}/role/maknaed/role-id"                    { capabilities = ["read"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknae/role-id"                      { capabilities = ["read"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknaed/secret-id"                   { capabilities = ["create","update"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknae/secret-id"                    { capabilities = ["create","update"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknaed/secret-id-accessor/destroy" { capabilities = ["update"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknae/secret-id-accessor/destroy"  { capabilities = ["update"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknae-egress/role-id"                    { capabilities = ["read"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknae-egress/secret-id"                  { capabilities = ["create","update"] }
    path "auth/${vault_auth_backend.approle.path}/role/maknae-egress/secret-id-accessor/destroy" { capabilities = ["update"] }
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
#  - maknae (CLI): a SHORT-LIVED token (token_ttl/token_max_ttl, dies fast per invocation)
#    plus a STANDING, operator-owned SecretID (num_uses=0, ttl=0) so the CLI mints per
#    invocation without re-seeding.
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

# #240a: the deputy's AppRole. Standing SecretID like the daemon's (ADR-0018)
# and a PERIODIC token — it is a long-lived service, not a per-invocation CLI.
resource "vault_approle_auth_backend_role" "maknae_egress" {
  backend                 = vault_auth_backend.approle.path
  role_name               = "maknae-egress"
  token_policies          = [vault_policy.maknae_egress.name]
  secret_id_ttl           = 0                # ADR-0018 invariant: standing SecretID
  secret_id_num_uses      = 0                # unlimited logins (hands-free reboots)
  token_period            = var.token_period # PERIODIC token — renews indefinitely
  token_max_ttl           = 0
  token_no_default_policy = true
}

resource "vault_approle_auth_backend_role" "maknae" {
  backend                 = vault_auth_backend.approle.path
  role_name               = "maknae"
  token_policies          = [vault_policy.maknae_cli.name]
  secret_id_ttl           = 0             # ADR-0018 invariant: standing (non-expiring), operator-owned
  secret_id_num_uses      = 0             # ADR-0018 invariant: CLI mints per invocation w/o re-seed
  token_ttl               = var.token_ttl # short-lived token, dies fast per invocation
  token_max_ttl           = var.token_max_ttl
  token_no_default_policy = true
}
