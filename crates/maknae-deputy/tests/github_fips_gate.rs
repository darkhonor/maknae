//! Its own test binary: installing a crypto provider is process-global and
//! irreversible, and this file installs none.
#![cfg(unix)]

use maknae_deputy::mint::github::{ForgeError, GithubClient};

#[test]
fn new_refuses_without_the_fips_provider() {
    assert_eq!(GithubClient::new().unwrap_err(), ForgeError::Transport);
}
