terraform {
  required_version = ">= 1.11"

  required_providers {
    vault = {
      source = "hashicorp/vault"
      # vault_userpass_auth_backend_user does not exist before 5.10.0
      version = "~> 5.10"
    }
    random = {
      source = "hashicorp/random"
      # ephemeral random_password does not exist before 3.7.0
      version = "~> 3.7"
    }
  }
}

# Auth comes from the environment (VAULT_ADDR + a Vault token). No credentials in code.
provider "vault" {}
