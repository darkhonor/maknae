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
