# CA material the planes pin (public certs only — type="internal" keeps keys out of state).
output "root_ca_certificate" {
  description = "Maknae dev Root CA cert (PEM). Planes pin this in their CA bundle."
  value       = vault_pki_secret_backend_root_cert.maknae_root.certificate
}

output "intermediate_ca_certificate" {
  description = "Signed Maknae Intermediate CA cert (PEM)."
  value       = vault_pki_secret_backend_root_sign_intermediate.maknae_int.certificate
}

output "ca_chain_pem" {
  description = "Full chain (intermediate + root) the planes pin to verify plane leaves."
  value       = "${vault_pki_secret_backend_root_sign_intermediate.maknae_int.certificate}\n${vault_pki_secret_backend_root_cert.maknae_root.certificate}"
}

# Mount paths + names for the operational SecretID-delivery step and plane config.
output "root_mount_path" {
  description = "Vault mount path of the Maknae dev Root PKI."
  value       = vault_mount.maknae_root.path
}

output "intermediate_mount_path" {
  description = "Vault mount path of the Maknae Intermediate PKI (issues plane leaves)."
  value       = vault_mount.maknae_int.path
}

output "kernel_role_name" {
  description = "PKI role the trust plane (maknaed) signs against."
  value       = vault_pki_secret_backend_role.maknae_kernel.name
}

output "cli_role_name" {
  description = "PKI role the CLI plane (maknae) signs against."
  value       = vault_pki_secret_backend_role.maknae_cli.name
}

output "approle_mount_path" {
  description = "Dedicated AppRole auth mount path (target of auth/<path>/role/<r>/secret-id)."
  value       = vault_auth_backend.approle.path
}

output "maknaed_approle_name" {
  description = "AppRole role name for the trust plane."
  value       = vault_approle_auth_backend_role.maknaed.role_name
}

output "maknaed_role_id" {
  description = "AppRole RoleID for the trust plane (maknaed). Non-secret; pair with an out-of-band SecretID to log in."
  value       = vault_approle_auth_backend_role.maknaed.role_id
}

output "userpass_mount_path" {
  description = "Userpass auth mount path local users log in through (maknae enroll --userpass-mount)."
  value       = vault_auth_backend.userpass.path
}

output "kv_mount_path" {
  description = "KV v2 mount holding each user's provider API keys (maknae enroll --kv-mount)."
  value       = vault_mount.maknae_kv.path
}

output "user_prefix" {
  description = "Per-user key prefix within kv_mount_path (maknae enroll --user-prefix)."
  value       = var.user_prefix
}

output "user_policy_name" {
  description = "Templated user policy, bound to every userpass user through the maknae-users group."
  value       = vault_policy.maknae_user.name
}
