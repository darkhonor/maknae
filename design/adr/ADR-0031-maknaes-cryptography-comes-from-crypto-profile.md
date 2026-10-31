# ADR-0031: Maknae's cryptography comes from crypto-profile

- **Status:** Accepted (maintainer-ruled 2026-10-31)
- **Date:** 2026-10-31
- **Deciders:** Alex Ackerman (maintainer)
- **Raised by:** [#589](https://github.com/darkhonor/maknae/issues/589)

## Context

`maknae-crypto` (ADR-0030) was extracted into the public `crypto-profile` crates, published as 0.9.0 on 2026-10-30: a core crate of algorithm types, profiles and a conformance suite, and one backend per AWS-LC FIPS module line. Maknae and other projects then share one reviewed implementation instead of each carrying its own.

## Decision

1. **Maknae consumes `crypto-profile-awslc4`**, the AWS-LC FIPS 4.x backend, through `maknae-crypto`, which is now an adapter. It re-exports the backend's API and owns three Maknae choices: the profile (`preferred`, resolved once by `policy()`), the start-up check (`init()` and `assert_fips_provider()`, refusing with `PolicyDrift` when the process default differs from the policy), and the plane signature keys (`plane_key::PlaneKey`, the three algorithms a plane may hold).
2. **Module line.** Maknae stays on the 4.x line; ADR-0025 governs the claim. `crypto-profile-awslc3` is banned in `deny.toml`.
3. **Exact pins and their cadence.** The backend pins `aws-lc-rs`, `rustls`, `rustls-webpki` and `rcgen` exactly. Its build script also refuses any FIPS module but `aws-lc-fips-sys` 0.14.2, which aws-lc-rs requires only by caret, so Cargo.lock holds it and Dependabot ignores it. A fix to any of them reaches Maknae only through a crypto-profile release. Under ADR-0025's rule that a published vulnerability whose fix is inside the vendor's supported channel is taken, the maintainer cuts that release.
4. **External connections are TLS 1.3 only.** The `preferred` profile is TLS 1.3 with AES-GCM. Before this change, external connections (Vault's HTTP API, model providers) also allowed TLS 1.2, because reqwest offers every version the process default supports. Vault 2.0+ is the declared minimum, and a survey on 2026-10-31 of sixteen model-provider endpoints completed TLS 1.3 with exactly this offer (#589). TLS 1.2 returns only per destination, through the `fips1402` profile (#574).
5. **No built-in rustls provider.** Nothing in the graph enables rustls's `aws_lc_rs`, `fips` or `ring` features, and `deny.toml` bans them, so rustls's stock-provider entry points do not compile anywhere in Maknae.

## Consequences

- `maknae-crypto` holds no cryptographic implementation; its tests cover the adapter, and the backend's conformance suite (Wycheproof, NIST vectors, the sealed box's known answer) covers the cryptography in crypto-profile's CI, on Linux x86_64 and arm64 and on macOS arm64. Maknae keeps its own sealed-box known-answer test and the golden offer test.
- The handshake verification schemes narrow to `preferred`'s: Ed25519, RSA PKCS#1 v1.5 and ML-DSA-44/65 are no longer accepted in a handshake. Certificate-chain signatures are not restricted.
- **Known issue inherited from the module:** on aarch64, AWS-LC refuses two valid Wycheproof P-256 signatures (crypto-profile#24, aws/aws-lc#3715). It fails closed, and the module Maknae linked before this change has the same defect.

## Related

ADR-0025, ADR-0030, #574, #581, #590, crypto-profile/crypto-profile#28.
