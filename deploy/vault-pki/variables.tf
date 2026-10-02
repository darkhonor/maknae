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

variable "token_period" {
  type        = number
  description = "Period for the `maknaed` daemon's PERIODIC token (ADR-0018): the token renews indefinitely as long as it is renewed within each period and is never force-expired by a max-TTL ceiling — only genuine Vault failure or revocation fails it closed. A shorter period tightens custody (a leaked/orphaned token dies sooner after the last renewal) at the cost of transient-outage tolerance; longer favors availability. Mirrors the retired 24h operational cadence as a renewable floor. Seconds. Default 24h."
  default     = 86400

  # Fail closed on the one invariant-breaking value: token_period = 0 makes the daemon
  # token NON-periodic, silently reinstating the token_max_ttl self-expiry that ADR-0018
  # removes (a scheduled daemon self-outage — the exact Availability vector ADR-0018 rejects).
  # The period is tunable across any positive duration; it may never be disabled.
  validation {
    condition     = var.token_period > 0
    error_message = "token_period must be > 0: a period of 0 disables the daemon's periodic token and reintroduces the ADR-0018-removed scheduled self-outage. Tune the duration, never zero it."
  }
}

# NOTE: there is deliberately NO `secret_id_ttl` variable. A standing SecretID (ttl=0) is an
# ADR-0018 invariant for the `maknaed` role, so it is HARD-CODED to 0 in main.tf rather than exposed
# as a variable — an advisory default would let a stale `terraform.tfvars` / `TF_VAR_secret_id_ttl`
# override silently reintroduce a time-expiring SecretID and break hands-free reboot.
# secret_id_num_uses=0 is likewise hard-coded. (Fail closed, not advisory.)

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

variable "user_prefix" {
  description = "KV v2 path prefix, relative to kv_mount_path, under which each Vault user owns <user_prefix>/<username>/*. Must equal user_prefix in /etc/maknae/egress-bounds.yaml."
  type        = string
  default     = "maknae/users"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", var.user_prefix)) && !contains(split("/", var.user_prefix), ".") && !contains(split("/", var.user_prefix), "..") && !contains(split("/", var.user_prefix), "data") && length(var.user_prefix) <= 256
    error_message = "user_prefix must be 1-256 bytes of '/'-separated [A-Za-z0-9._-] segments, with no empty, '.', '..' or 'data' segment and no leading or trailing '/'."
  }
}

variable "userpass_mount" {
  description = "Userpass auth mount path for local users. Must equal vault.user_auth.mount in maknae.yaml."
  type        = string
  default     = "maknae-userpass"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", var.userpass_mount)) && !contains(split("/", var.userpass_mount), ".") && !contains(split("/", var.userpass_mount), "..") && split("/", var.userpass_mount)[0] != "auth" && length(var.userpass_mount) <= 256
    error_message = "userpass_mount must be 1-256 bytes of '/'-separated [A-Za-z0-9._-] segments, with no empty, '.' or '..' segment, no leading or trailing '/', and no leading 'auth' segment (write the bare mount name)."
  }
}

variable "maknae_users" {
  description = "Local users to create in the userpass mount, keyed by local username. Increment password_version to replace that user's password with a new random one."
  type = map(object({
    password_version = number
  }))
  default = {}

  validation {
    condition     = alltrue([for name in keys(var.maknae_users) : can(regex("^[a-z0-9_]([a-z0-9._-]{0,62}[a-z0-9_])?$", name)) && name != "data"])
    error_message = "Each maknae_users key must be 1-64 bytes of [a-z0-9._-], starting and ending with [a-z0-9_], and not 'data': Vault userpass lower-cases usernames, and maknaed derives the key path from the local username and refuses a 'data' segment in it."
  }
}

variable "kv_mount_path" {
  description = "Mount path of the KV v2 engine holding each user's provider API keys. Must equal kv_mount in /etc/maknae/egress-bounds.yaml."
  type        = string
  default     = "maknae-kv"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", var.kv_mount_path)) && !contains(split("/", var.kv_mount_path), ".") && !contains(split("/", var.kv_mount_path), "..") && !contains(split("/", var.kv_mount_path), "data") && length(var.kv_mount_path) <= 256
    error_message = "kv_mount_path must be 1-256 bytes of '/'-separated [A-Za-z0-9._-] segments, with no empty, '.', '..' or 'data' segment and no leading or trailing '/'."
  }
}
