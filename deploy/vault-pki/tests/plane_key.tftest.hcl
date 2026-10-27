mock_provider "vault" {}

variables {
  deployment_id = "test"
}

run "default_is_ml_dsa_87_everywhere" {
  command = plan

  assert {
    condition     = vault_pki_secret_backend_root_cert.maknae_root.key_type == "ml-dsa" && vault_pki_secret_backend_root_cert.maknae_root.parameter_set == "ml-dsa-87"
    error_message = "the root is ML-DSA-87 by default"
  }
  assert {
    condition     = vault_pki_secret_backend_intermediate_cert_request.maknae_int.key_type == "ml-dsa" && vault_pki_secret_backend_intermediate_cert_request.maknae_int.parameter_set == "ml-dsa-87"
    error_message = "the intermediate is ML-DSA-87 by default"
  }
  assert {
    condition     = vault_pki_secret_backend_role.maknae_kernel.key_type == "ml-dsa" && vault_pki_secret_backend_role.maknae_kernel.parameter_set == "ml-dsa-87" && vault_pki_secret_backend_role.maknae_cli.key_type == "ml-dsa" && vault_pki_secret_backend_role.maknae_cli.parameter_set == "ml-dsa-87"
    error_message = "both plane roles issue ML-DSA-87 by default"
  }
}

run "p384_plans_the_pre_573_hierarchy" {
  command = plan

  variables {
    plane_key_algorithm = "ecdsa-p384-sha384"
  }

  assert {
    condition     = vault_pki_secret_backend_root_cert.maknae_root.key_type == "ec" && vault_pki_secret_backend_root_cert.maknae_root.key_bits == 384 && vault_pki_secret_backend_root_cert.maknae_root.signature_bits == 384
    error_message = "ecdsa-p384-sha384 keeps the EC P-384 root exactly"
  }
  assert {
    condition     = vault_pki_secret_backend_intermediate_cert_request.maknae_int.key_type == "ec" && vault_pki_secret_backend_intermediate_cert_request.maknae_int.key_bits == 384
    error_message = "ecdsa-p384-sha384 keeps the EC P-384 intermediate exactly"
  }
  assert {
    condition     = vault_pki_secret_backend_root_sign_intermediate.maknae_int.signature_bits == 384
    error_message = "ecdsa-p384-sha384 keeps the 384-bit intermediate signature"
  }
  assert {
    condition     = vault_pki_secret_backend_role.maknae_kernel.key_type == "ec" && vault_pki_secret_backend_role.maknae_kernel.key_bits == 384 && vault_pki_secret_backend_role.maknae_kernel.signature_bits == 384 && vault_pki_secret_backend_role.maknae_cli.key_type == "ec" && vault_pki_secret_backend_role.maknae_cli.key_bits == 384 && vault_pki_secret_backend_role.maknae_cli.signature_bits == 384
    error_message = "ecdsa-p384-sha384 keeps both EC P-384 roles exactly"
  }
}

run "ecdsa_p521_sha512" {
  command = plan

  variables {
    plane_key_algorithm = "ecdsa-p521-sha512"
  }

  assert {
    condition     = vault_pki_secret_backend_root_cert.maknae_root.key_type == "ec" && vault_pki_secret_backend_root_cert.maknae_root.key_bits == 521 && vault_pki_secret_backend_root_cert.maknae_root.signature_bits == 512
    error_message = "ecdsa-p521-sha512: an EC P-521 root signed with SHA-512"
  }
  assert {
    condition     = vault_pki_secret_backend_intermediate_cert_request.maknae_int.key_bits == 521 && vault_pki_secret_backend_role.maknae_kernel.key_bits == 521 && vault_pki_secret_backend_role.maknae_cli.key_bits == 521
    error_message = "ecdsa-p521-sha512: the intermediate and both roles are P-521"
  }
}

run "an_unknown_algorithm_is_refused" {
  command = plan

  variables {
    plane_key_algorithm = "p384"
  }

  expect_failures = [var.plane_key_algorithm]
}
