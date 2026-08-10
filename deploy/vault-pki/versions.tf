terraform {
  required_version = ">= 1.5"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 5.0"
    }
  }
}

# Auth comes from the environment (VAULT_ADDR + a Vault token). No credentials in code.
provider "vault" {}
