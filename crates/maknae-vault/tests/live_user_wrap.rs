//! Operator-gated: MAKNAE_VAULT_ADDR, MAKNAE_VAULT_CA, MAKNAE_VAULT_TOKEN; optional MAKNAE_KV_MOUNT, MAKNAE_USERPASS_MOUNT.
#![cfg(unix)]

use maknae_vault::{
    Password, UserAuth, UserAuthMethod, VaultApi, VaultError, WrapExpectation, WrapMismatch,
    WrappingToken,
};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use vaultrs::api::auth::userpass::requests::CreateUserRequest;
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};
use zeroize::Zeroizing;

fn env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("set {key}"))
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    aws_lc_rs::rand::fill(&mut b).unwrap();
    b.iter().map(|x| format!("{x:02x}")).collect()
}

async fn scenario(
    api: &VaultApi,
    auth: &UserAuth,
    kv_mount: &str,
    user: &str,
    password: &Zeroizing<String>,
    own: &str,
    other: &str,
) -> Result<(), String> {
    let ttl = Duration::from_secs(60);
    let login = api
        .login(
            auth,
            user,
            &Password::new(password.clone()).map_err(|e| e.to_string())?,
        )
        .await
        .map_err(|e| format!("login: {e}"))?;
    if login.lease.is_zero() {
        return Err("login returned no lease".into());
    }
    match api.read_wrapped(&login.token, kv_mount, other, ttl).await {
        Err(VaultError::VaultStatus { status: 403, .. }) => {}
        got => {
            return Err(format!(
                "another user's path must be 403, got {:?}",
                got.map(|_| "a wrapping token")
            ))
        }
    }
    let wrapped = api
        .read_wrapped(&login.token, kv_mount, own, ttl)
        .await
        .map_err(|e| format!("wrapped read: {e}"))?;
    let lookup = api
        .lookup_wrapping(&wrapped.token)
        .await
        .map_err(|e| format!("lookup: {e}"))?;
    if lookup.creation_path != format!("{kv_mount}/data/{own}") {
        return Err(format!("creation_path {}", lookup.creation_path));
    }
    let copy = || WrappingToken::new(Zeroizing::new(wrapped.token.expose().to_string())).unwrap();
    let wrong = WrapExpectation::new(kv_mount, other, "api_key", ttl).map_err(|e| e.to_string())?;
    match api.unwrap_kv_field(copy(), &wrong).await {
        Err(VaultError::WrapMismatch(WrapMismatch::CreationPath)) => {}
        got => {
            return Err(format!(
                "wrong path must refuse before unwrap, got {:?}",
                got.map(|_| "a key")
            ))
        }
    }
    let replay = copy();
    let right = WrapExpectation::new(kv_mount, own, "api_key", ttl).map_err(|e| e.to_string())?;
    let key = api
        .unwrap_kv_field(wrapped.token, &right)
        .await
        .map_err(|e| format!("unwrap: {e}"))?;
    if key.as_str() != "LIVE-SENTINEL-KEY" {
        return Err("unwrapped the wrong value".into());
    }
    match api.unwrap_kv_field(replay, &right).await {
        Err(VaultError::WrapMismatch(WrapMismatch::Invalid)) => Ok(()),
        got => Err(format!(
            "a used wrapping token must be invalid, got {:?}",
            got.map(|_| "a key")
        )),
    }
}

#[tokio::test]
#[ignore = "needs a live Vault, an operator token and a userpass mount (operator-gated)"]
async fn userpass_login_wrapped_read_lookup_and_checked_unwrap_against_live_vault() {
    maknae_vault::install_default_crypto_provider();
    let addr = env("MAKNAE_VAULT_ADDR");
    let ca = env("MAKNAE_VAULT_CA");
    let operator = Zeroizing::new(env("MAKNAE_VAULT_TOKEN"));
    let kv_mount = env_or("MAKNAE_KV_MOUNT", "maknae-kv");
    let userpass_mount = env_or("MAKNAE_USERPASS_MOUNT", "userpass");
    let admin = VaultClient::new(
        VaultClientSettingsBuilder::default()
            .address(&addr)
            .ca_certs(vec![ca.clone()])
            .token(operator.as_str())
            .build()
            .unwrap(),
    )
    .unwrap();

    let user = format!("maknae-live-{}", random_hex(4));
    let password = Zeroizing::new(random_hex(24));
    let own = format!("maknae-live/{user}/openai");
    let other = format!("maknae-live/{user}-other/openai");
    let policy =
        format!("path \"{kv_mount}/data/maknae-live/{user}/*\" {{ capabilities = [\"read\"] }}");
    vaultrs::sys::policy::set(&admin, &user, &policy)
        .await
        .unwrap();
    let mut opts = CreateUserRequest::builder();
    opts.token_policies(vec![user.clone()]).token_ttl("10m");
    vaultrs::auth::userpass::user::set(&admin, &userpass_mount, &user, &password, Some(&mut opts))
        .await
        .unwrap();
    vaultrs::kv2::set(
        &admin,
        &kv_mount,
        &own,
        &HashMap::from([("api_key", "LIVE-SENTINEL-KEY")]),
    )
    .await
    .unwrap();
    vaultrs::kv2::set(
        &admin,
        &kv_mount,
        &other,
        &HashMap::from([("api_key", "OTHER")]),
    )
    .await
    .unwrap();

    let api = VaultApi::new(&addr, Path::new(&ca)).unwrap();
    let auth = UserAuth::new(UserAuthMethod::Userpass, &userpass_mount).unwrap();
    let outcome = scenario(&api, &auth, &kv_mount, &user, &password, &own, &other).await;

    let _ = vaultrs::kv2::delete_metadata(&admin, &kv_mount, &own).await;
    let _ = vaultrs::kv2::delete_metadata(&admin, &kv_mount, &other).await;
    let _ = vaultrs::auth::userpass::user::delete(&admin, &userpass_mount, &user).await;
    let _ = vaultrs::sys::policy::delete(&admin, &user).await;
    outcome.unwrap();
    println!("LIVE USER WRAP OK: login, 403 on another path, wrapped read, lookup, refusal before unwrap, unwrap, single use");
}
