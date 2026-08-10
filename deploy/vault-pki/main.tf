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
resource "vault_mount" "maknae_int" {
  path                  = var.int_mount_path
  type                  = "pki"
  description           = "Maknae Intermediate CA (issues plane leaves)"
  max_lease_ttl_seconds = var.int_ttl_seconds # >= leaf_ttl_seconds (see variables.tf)
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

  allowed_uri_sans = ["maknae://${var.deployment_id}/plane/kernel"]
  use_csr_sans     = true # honor the plane's URI-SAN as presented in its CSR

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

  allowed_uri_sans = ["maknae://${var.deployment_id}/plane/cli"]
  use_csr_sans     = true

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
