variable "deployment_id" {
  type        = string
  description = "Deployment identity branded into every plane leaf SAN (maknae://<deployment_id>/plane/*). No default — an explicit value is REQUIRED so a prod apply cannot silently emit 'dev'-branded certs. Constrained to [A-Za-z0-9._-] so it cannot inject a Vault glob into allowed_uri_sans."

  # Charset lock (also enforces non-empty via `+`). CRITICAL — not cosmetic:
  # Vault's `allowed_uri_sans` treats `*` as a GLOB. If deployment_id could contain
  # `*`, then allowed_uri_sans = ["maknae://*/plane/kernel"] would match ANY
  # deployment's plane SAN, silently defeating SAN-locked plane isolation. Slashes
  # and spaces would likewise corrupt the SAN. Restrict to a safe identifier charset.
  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.deployment_id))
    error_message = "deployment_id must be non-empty and contain only [A-Za-z0-9._-] — no glob metacharacters (notably '*'), slashes, or spaces. A '*' would turn the leaf allowed_uri_sans into a Vault glob (maknae://*/plane/...), matching ANY deployment and defeating plane isolation."
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
  description = "Token TTL for the SHORT-LIVED CLI token (the `maknae` role): the CLI token lives at most this long and dies with the invocation (no background renewal). The `maknaed` daemon token is periodic (var.token_period) and does not use this. Default 20m."
  default     = 1200
}

variable "token_max_ttl" {
  type        = number
  description = "Token max TTL for the SHORT-LIVED CLI token (the `maknae` role), in seconds. The `maknaed` daemon uses a periodic token (var.token_period) with NO max-TTL ceiling instead (ADR-0018). Default 24h."
  default     = 86400
}

variable "token_period" {
  type        = number
  description = "Period for the `maknaed` daemon's PERIODIC token (ADR-0018): the token renews indefinitely as long as it is renewed within each period and is never force-expired by a max-TTL ceiling — only genuine Vault failure or revocation fails it closed. A shorter period tightens custody (a leaked/orphaned token dies sooner after the last renewal) at the cost of transient-outage tolerance; longer favors availability. Mirrors the retired 24h operational cadence as a renewable floor. Only the daemon role is periodic; the CLI token stays short-lived. Seconds. Default 24h."
  default     = 86400
}

variable "secret_id_ttl" {
  type        = number
  description = "AppRole SecretID TTL, in seconds. 0 = non-expiring (STANDING SecretID). Both roles use a standing SecretID per ADR-0018: the daemon bootstrap is `_maknae`-owned and HRoT-sealed at rest via `maknae enroll`; the CLI SecretID is operator-owned. A standing SecretID needs BOTH ttl=0 and secret_id_num_uses=0. Default 0."
  default     = 0
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
