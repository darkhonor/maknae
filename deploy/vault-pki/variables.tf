variable "deployment_id" {
  type        = string
  description = "Deployment identity branded into every plane leaf SAN (maknae://<deployment_id>/plane/*). No default — an explicit value is REQUIRED so a prod apply cannot silently emit 'dev'-branded certs."

  validation {
    condition     = length(trimspace(var.deployment_id)) > 0
    error_message = "deployment_id must be an explicit non-empty value (there is deliberately no default)."
  }
}

variable "root_ttl_seconds" {
  type        = number
  description = "Root CA cert validity AND root mount max_lease, in seconds. Default ~10y."
  default     = 315360000
}

variable "int_ttl_seconds" {
  type        = number
  description = "Intermediate CA cert validity AND intermediate mount max_lease, in seconds. MUST be >= leaf_ttl_seconds, else a raised leaf ttl is silently capped at Vault's 768h system default. Default ~5y."
  default     = 157680000
}

variable "leaf_ttl_seconds" {
  type        = number
  description = "Plane leaf cert ttl/max_ttl, in seconds. Default 72h."
  default     = 259200
}

variable "token_ttl" {
  type        = number
  description = "AppRole token TTL (background-renewal increment), in seconds. Default 20m."
  default     = 1200
}

variable "token_max_ttl" {
  type        = number
  description = "AppRole token max TTL (fail-closed re-auth boundary; the binding operational cadence, deliberately tighter than the 72h leaf), in seconds. Default 24h."
  default     = 86400
}

variable "secret_id_ttl" {
  type        = number
  description = "AppRole SecretID TTL, in seconds. Default 10m."
  default     = 600
}

variable "root_mount_path" {
  type        = string
  description = "Vault mount path for the Maknae dev Root PKI."
  default     = "maknae-pki-root"
}

variable "int_mount_path" {
  type        = string
  description = "Vault mount path for the Maknae Intermediate PKI."
  default     = "maknae-pki-int"
}

variable "approle_path" {
  type        = string
  description = "Dedicated AppRole auth mount path. NOT the shared default 'approle', which commonly already exists and would hard-fail apply with 'path is already in use'."
  default     = "maknae-approle"
}
