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

variable "plane_key_algorithm" {
  type        = string
  description = "Key algorithm of the Maknae root, intermediate and plane leaves (#573): ml-dsa-87 (needs Vault >= 2.2.0), ecdsa-p384-sha384 or ecdsa-p521-sha512. Must equal vault.plane_key in maknae.yaml."
  default     = "ml-dsa-87"
  validation {
    condition     = contains(["ml-dsa-87", "ecdsa-p384-sha384", "ecdsa-p521-sha512"], var.plane_key_algorithm)
    error_message = "plane_key_algorithm must be one of ml-dsa-87, ecdsa-p384-sha384, ecdsa-p521-sha512."
  }
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
    condition     = alltrue([for name in keys(var.maknae_users) : can(regex("^[a-z0-9_]([a-z0-9._-]{0,30}[a-z0-9_])?$", name)) && name != "data"])
    error_message = "Each maknae_users key must be 1-32 bytes of [a-z0-9._-], starting and ending with [a-z0-9_], and not 'data': Vault userpass lower-cases usernames, and maknaed derives the key path from the local username and refuses a 'data' segment in it."
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

variable "maknae_agents" {
  description = "Agent Daemons to provision, keyed by agent id. Each gets its own policy, reading only <kv_mount_path>/data/<agent_prefix>/<id>/*, and its own AppRole role agent-<id>."
  type        = map(object({}))
  default     = {}

  validation {
    condition     = alltrue([for id in keys(var.maknae_agents) : can(regex("^[a-z0-9_]([a-z0-9._-]{0,30}[a-z0-9_])?$", id)) && id != "data"])
    error_message = "Each maknae_agents key must be 1-32 bytes of [a-z0-9._-], starting and ending with [a-z0-9_], and not 'data': the id lands in Vault paths and must never carry a glob ('*'), a '/' or a space (ADR-0006 decision 9)."
  }
}

variable "agent_prefix" {
  description = "KV v2 path prefix, relative to kv_mount_path, under which each agent's credentials live at <agent_prefix>/<id>/*. Must not equal, contain or sit inside user_prefix."
  type        = string
  default     = "maknae/agents"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+(/[A-Za-z0-9._-]+)*$", var.agent_prefix)) && !contains(split("/", var.agent_prefix), ".") && !contains(split("/", var.agent_prefix), "..") && !contains(split("/", var.agent_prefix), "data") && length(var.agent_prefix) <= 256
    error_message = "agent_prefix must be 1-256 bytes of '/'-separated [A-Za-z0-9._-] segments, with no empty, '.', '..' or 'data' segment and no leading or trailing '/'."
  }

  validation {
    condition     = !(var.agent_prefix == var.user_prefix || startswith("${var.agent_prefix}/", "${var.user_prefix}/") || startswith("${var.user_prefix}/", "${var.agent_prefix}/"))
    error_message = "agent_prefix and user_prefix must not be equal or nested: an agent's credential must never sit inside a subtree a human can write, and the agent admin policy must never reach a human's keys."
  }
}

variable "agent_approle_path" {
  description = "AppRole auth mount for Agent Daemons. Must differ from approle_path (maknaed's)."
  type        = string
  default     = "maknae-agent-approle"

  validation {
    condition     = can(regex("^[A-Za-z0-9._-]+$", var.agent_approle_path))
    error_message = "agent_approle_path must be a non-empty bare mount name of [A-Za-z0-9._-]."
  }
}

variable "agent_token_ttl" {
  description = "Agent token TTL, in seconds. Default 1h."
  type        = number
  default     = 3600

  validation {
    condition     = var.agent_token_ttl > 0 && var.agent_token_ttl <= var.agent_token_max_ttl
    error_message = "agent_token_ttl must be > 0 and <= agent_token_max_ttl."
  }
}

variable "agent_token_max_ttl" {
  description = "Hard ceiling on an agent token's life, in seconds. Never 0: an agent token is bounded, unlike maknaed's periodic token (ADR-0006 decision 9). Default 24h."
  type        = number
  default     = 86400

  validation {
    condition     = var.agent_token_max_ttl > 0
    error_message = "agent_token_max_ttl must be > 0: an agent token is never unbounded (ADR-0006 decision 9)."
  }
}
