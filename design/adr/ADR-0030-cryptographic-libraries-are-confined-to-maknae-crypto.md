# ADR-0030: Cryptographic libraries are confined to `maknae-crypto`

- **Status:** Accepted (maintainer-ruled 2026-10-27)
- **Date:** 2026-10-27
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#564](https://github.com/darkhonor/maknae/issues/564) (post-quantum TLS key exchange), part of the PQC epic [#569](https://github.com/darkhonor/maknae/issues/569)

> **Amended 2026-10-27 (#573, maintainer).** This record confined the *libraries*, which is narrower than the intent. The intent is one implementation of each cryptographic function, in `maknae-crypto`, so the CBOM (#570) reads one crate and no two implementations can diverge. Crates outside it keep their domain work (for `maknae-vault`, requesting certificates and talking to Vault) and call `maknae-crypto` for the cryptography. #573 moved the plane signature algorithms and `rcgen` here (decisions 1 to 3); decision 5 states the rule; the code that predates it is #578.

## Context

Before this decision, four workspace manifests declared the FIPS cryptographic libraries directly: `maknae-vault` (`aws-lc-rs` and `rustls`, with the posture comment [ADR-0025](ADR-0025-fips-validation-is-a-goal-not-a-constraint.md) records), `maknae-seal`, `maknae-state` and the `maknae` binary (`aws-lc-rs`). The process-wide TLS provider and its start-up assertion lived in `maknae-vault`, so `maknae-llm` and `maknae-deputy` depended on the whole Vault client crate for one function each.

#564 made the TLS key-exchange groups explicit and asserted at start. That added cryptographic policy to the same crate. The PQC epic will next change the seal's key agreement (#565) and needs a cryptographic inventory and CBOM (#570). With the libraries spread over four manifests, an upgrade has four places to edit, and the CBOM has no single manifest to read.

## Decision

1. **`maknae-crypto` is the only workspace member that declares `aws-lc-rs` or `rustls`.** It carries their version requirements and the FIPS posture comment, and re-exports both (`pub use aws_lc_rs; pub use rustls;`). Every other member reaches them through the re-exports. *(Amended 2026-10-27, #573: and `rcgen`, re-exported the same way.)*
2. **It owns the cryptographic policy over them:** `crypto_provider()` (the aws-lc-rs FIPS provider with `KX_GROUPS`), `install_default_crypto_provider()`, `assert_fips_provider()`, and the pure decisions behind the assertion. Its refusals are `CryptoError`; `maknae-vault` maps them to its own variants of the same name. *(Amended 2026-10-27, #573: it also owns the plane identity's signature algorithms, `signature::PlaneKey` with each algorithm's rcgen algorithm, TLS signature scheme and SubjectPublicKeyInfo check, and `generate_csr()`, the keypair and PKCS#10 request a plane sends to Vault.)*
3. **Enforcement.** `deny.toml` `[bans]` denies `aws-lc-rs` and `rustls` to every direct dependent except `maknae-crypto` and the third-party crates that wrap them today. `tokio-rustls` re-exports rustls, so it is confined to `maknae-vault` the same way, as is `rcgen`, which selects aws-lc-rs's FIPS backend. *(Amended 2026-10-27, #573: `rcgen` is now confined to `maknae-crypto`, which re-exports it; `maknae-vault` uses the re-export only in test fixtures. Observed red by planting `rcgen` back in `maknae-vault`.)* `[[bans.features]]` denies `reqwest` the features that install a stock provider (`default-tls`, `rustls`, `__rustls-aws-lc-rs`, `native-tls`, `native-tls-no-alpn`); its `rustls-no-provider` leaves the provider to `maknae-crypto`'s process default. `ring` is banned outright (maintainer ruling 2026-10-27): it is a second, non-FIPS crypto library, absent from the graph since #320, and a `ring` feature on rustls or a wrapper would expose `rustls::crypto::ring::default_provider()`, a stock provider a single connection could use while the start-up assertion, which sees only the process default, still passes. `aws-lc-sys` and `aws-lc-fips-sys` are not banned as direct dependencies: their API is `unsafe` to call, which `unsafe_code = "forbid"` refuses outside `maknae-sys` (ADR-0027). `cargo deny --locked check` runs in `build-and-gate`. `clippy.toml` refuses the rustls functions that build or install a stock provider (#564).
4. **Mutation.** `maknae-crypto` is a mutation crate; its decisions are T1.
5. **One implementation per cryptographic function** *(added 2026-10-27, #573)*. A cryptographic function (key generation, signing and its algorithm choice, hashing, random bytes, AEAD, key agreement, KDF, TLS configuration) is implemented once, in `maknae-crypto`, and every other crate calls it. A second implementation elsewhere is a defect. Decoding (X.509 and PEM parsing) is not a cryptographic function; a decision over decoded data, such as which algorithm a public key is, is.

## Consequences

- An upgrade of `aws-lc-rs` or `rustls` is one manifest. The CBOM reads the algorithms and libraries Maknae ships from one crate.
- `maknae-llm` and `maknae-deputy` no longer depend on `maknae-vault`.
- **Residuals.**
  - Third-party wrappers still name the libraries in their own manifests (`tokio-rustls` and `reqwest` in `maknae-vault`, `reqwest` in `maknae-llm`). A major version bump of either library also moves them. *(Amended 2026-10-27, #573: this listed `rcgen` in `maknae-vault`; it moved here.)*
  - Decision 5 is not yet true of the code that predates it: SHA-256, random bytes, AES-256-GCM, the seal's key agreement and KDF, and the plane TLS configuration are still implemented outside `maknae-crypto`, some more than once. #578 moves them and adds the control that refuses a new one.
  - `maknae-seal` keeps its own FIPS check over aws-lc-rs until #565 decides the seal's shape.
  - The `deny.toml` controls were observed red by planting a direct dependency in a member (normal and dev) `reqwest`'s `rustls` feature in `maknae-llm`, and a `ring` feature on `rustls` and on `tokio-rustls`; no negative-control probe repeats them, because that gate's environment has no `cargo-deny`.
  - `cargo test -p maknae-crypto` builds rustls with `fips` and `std` only; the shipped binaries also unify `tls12` onto it. The decisions this crate tests do not depend on it.

## Related

ADR-0025 (the module line and the claim), ADR-0027 (the same confinement shape for `unsafe`), #564, #565, #569, #570, #573, #578.
