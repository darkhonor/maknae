# FIPS Crypto and Supply-Chain Visibility Assessment

| | |
|---|---|
| **Status** | Reference record for issues #155 and #156. Most questions confirm; one native-code advisory-coverage gap is split out as #191 for separate tracking. |
| **Date** | 2026-08-30 |
| **Subject** | Maknae dependency graph, FIPS provider selection, OS-crypto independence, `cargo-deny` advisory database failure mode, and `cargo auditable` native-code visibility at `origin/main` after PR #190 (`baab3c790c4ee02f982e3bcc7cace064cb32fc87`). |
| **Method** | Read-only source review plus local empirical checks: issue bodies #155/#156; `Cargo.lock`; `deny.toml`; `.github/workflows/ci.yml`; `Cargo.toml` files under `bins/` and `crates/`; provider call-site grep; `cargo tree --target all --edges normal,build,features`; `cargo auditable build -p {maknaed,maknae,maknae-spifc} --release`; `rust-audit-info`; `ldd`; `nm -D`; `strings`; `cargo deny check`; and an unreachable-RustSec-DB negative test using an empty `CARGO_HOME` plus a Git URL rewrite to `http://127.0.0.1:9/RustSec/advisory-db`. |
| **Audience** | Maknae maintainers and future deployment reviewers. |
| **Purpose** | Record the engineering answer to whether Maknae's current FIPS posture depends on OS-provided cryptography, and whether the current supply-chain gates can see the dependency surface that reaches the shipped binaries. Maknae is a personal project targeting DoD deployability; this is not an ATO package or compliance submission. |

## 1. Executive Findings

Maknae's external Rust dependency graph is registry-only. `Cargo.lock` has 259 package stanzas total; 240 of those have a `source = "registry+https://github.com/rust-lang/crates.io-index"` entry, and no package has a `git+`, file, sparse-file, or unknown registry source. The remaining stanzas are local workspace packages. `deny.toml` already denies unknown registries and unknown git sources.

The git-submodule blind spot that issue #156 was filed against is structurally impossible in this tree as it stands. There are no git-sourced Cargo dependencies and no vendored source trees outside the crates.io package boundary. Cargo can still compile native code from registry crates, which is a different problem discussed below.

`maknaed` and `maknae` release binaries contain `aws-lc-fips-sys`, `aws-lc-rs`, `aws-lc-sys`, and `ring` in their embedded `cargo auditable` manifests. `maknae-spifc` does not contain those crypto crates. `ring` is therefore compiled into the two Vault/TLS-bearing release binaries, but source review found no Maknae call site that explicitly selects `rustls::crypto::ring` or passes a ring provider. Maknae's own explicit provider builders use `rustls::crypto::aws_lc_rs::default_provider()`.

No production Linux release binary dynamically links OS OpenSSL, NSS, GnuTLS, or native-tls. `ldd` on `target/release/{maknaed,maknae,maknae-spifc}` shows only libc/libm/libgcc/ld-linux dependencies. The `OPENSSL_memory_*` dynamic symbols and `/aws-lc/crypto/...` strings in `maknaed` and `maknae` are from the vendored AWS-LC/BoringSSL-derived code, not from OS OpenSSL.

The current `cargo deny check` CI step fails closed when the RustSec advisory database cannot be fetched. The empirical negative test exited `1` and emitted `failed to fetch advisory database https://github.com/RustSec/advisory-db`; it did not report a clean gate with an unseen database.

The real gap is native-code advisory visibility for AWS-LC. `aws-lc-sys` and `aws-lc-fips-sys` vendor C and assembly from AWS-LC inside crates.io crates. `cargo deny` checks the RustSec crate advisory database; `cargo auditable` embeds the Rust crate graph and build-dependency graph. Neither records AWS-LC file-level provenance or independently maps upstream AWS-LC CVEs to the vendored C/asm snapshot. That gap should be tracked separately from this confirm-and-close record.

## 2. Dependency Source Visibility (#156)

Evidence:

- `Cargo.lock`: 259 `[[package]]` stanzas; 240 `source = ...` entries; every source entry is exactly `registry+https://github.com/rust-lang/crates.io-index`.
- `Cargo.lock`: `rg` for non-crates.io source forms found no git, file, sparse-file, or unknown registry source.
- Workspace manifests: local `path = ...` entries are only workspace member wiring, binary `path = "src/main.rs"` declarations, and test/local crate edges.
- `deny.toml`: `[sources] unknown-registry = "deny"` and `unknown-git = "deny"`.

Conclusion:

Cargo-deny can see the resolved external Rust crate graph in the usual Cargo sense. The failure class from the motivating incident, where git submodules with no manifest bypassed the package manager and scanner, does not apply to Maknae's current tree.

Important boundary:

This finding does not mean every line of native C/assembly inside a registry crate is independently visible to RustSec. It means there is no extra dependency surface outside the Cargo package graph.

## 3. FIPS Provider and `ring` Reachability (#155)

`ring` enters the graph through the `reqwest` / `hyper-rustls` / `rustls-webpki` rustls stack. The relevant `cargo tree --target all --edges normal,build,features -i ring` path for `maknaed` and `maknae` is:

```text
ring v0.17.14
└── rustls-webpki v0.103.13
    └── rustls v0.23.43
        └── hyper-rustls v0.27.9
            └── reqwest v0.12.28
                ├── rustify v0.6.1
                └── vaultrs v0.7.4
```

`rustls` also has both `aws_lc_rs` / `fips` and `ring` features unified in the resolved graph. That means dependency presence alone is not sufficient evidence for FIPS posture.

Compiled-artifact evidence:

- `cargo auditable build -p maknaed --release` succeeded.
- `cargo auditable build -p maknae --release` succeeded.
- `cargo auditable build -p maknae-spifc --release` succeeded.
- `rust-audit-info target/release/maknaed` lists `aws-lc-fips-sys`, `aws-lc-rs`, `aws-lc-sys`, and `ring`.
- `rust-audit-info target/release/maknae` lists `aws-lc-fips-sys`, `aws-lc-rs`, `aws-lc-sys`, and `ring`.
- `rust-audit-info target/release/maknae-spifc` lists only `maknae-spif-compile` and `maknae-spifc`.

Provider-selection evidence:

- `crates/maknae-vault/src/fips_glue.rs` installs `rustls::crypto::aws_lc_rs::default_provider()` and asserts `CryptoProvider::get_default().fips()`.
- `crates/maknae-kernel/src/run.rs` calls `maknae_vault::install_default_crypto_provider()` and then `maknae_vault::assert_fips_provider()` before booting config, building Vault clients, minting plane credentials, binding, or accepting requests.
- `bins/maknae/src/cli.rs` installs the aws-lc-rs default provider before `PlaneClient::from_document(...)` and `mint()`.
- `bins/maknae/src/enroll/mod.rs` installs the aws-lc-rs default provider before building the operator/Vault enrollment flow.
- `crates/maknae-vault/src/tls.rs`, `plane_verify.rs`, and `resolver.rs` build Maknae's explicit TLS configs and verifiers with `rustls::crypto::aws_lc_rs::default_provider()`.
- Repository grep found no Maknae production call site for `rustls::crypto::ring`, no direct `ring::` provider use, and no explicit non-default rustls provider selection that names ring.

Dependency-source note:

`reqwest 0.12.28` will use a process-default rustls provider if one has been installed; if none is installed and its ring feature is compiled, it falls back to `rustls::crypto::ring::default_provider()`. Maknae's load-bearing control is therefore enforced at Vault-client construction, not only by caller convention: `crates/maknae-vault/src/client.rs` documents the load-bearing ordering and calls `assert_fips_provider()` inside `VaultClient::from_document_with_secret()` before building the `reqwest` Vault client. The daemon and CLI paths also install and assert the aws-lc-rs FIPS default before constructing Vault clients.

The `deny.toml` comment at lines 9-12 summarizes this as a present-but-dead `ring` dependency. This record is the compiled-artifact evidence for that statement: `ring` is present in the shipped `maknaed` and `maknae` binaries, but is not selected by Maknae call sites under the current provider gate.

Conclusion:

`ring` is compiled into the release artifacts for `maknaed` and `maknae`, but no Maknae call site selects it explicitly. The current production paths install and assert the aws-lc-rs FIPS provider before constructing the TLS/Vault clients that could otherwise fall back to ring. The FIPS assertion is load-bearing and is not replaceable by Cargo graph hygiene.

## 4. OS-Provided Crypto (#155)

Lockfile and manifest evidence:

- No `openssl`, `openssl-sys`, or `native-tls` package is present in `Cargo.lock`.
- `deny.toml` explicitly bans `native-tls` and `openssl-sys`.
- Grep found no production dependency on GnuTLS, NSS, `rustls-native-certs`, AF_ALG/kernel crypto APIs, or platform TLS backends.
- `webpki-roots` is present as a registry crate in the rustls/reqwest stack; it is not OS trust-store crypto.

Binary evidence on the local Linux build host:

```text
target/release/maknaed: libc, libm, libgcc_s, ld-linux
target/release/maknae: libc, libm, libgcc_s, ld-linux
target/release/maknae-spifc: libc, libgcc_s, ld-linux
```

Notes on apparent matches:

- `OPENSSL_memory_*` weak symbols and `/aws-lc/crypto/...` strings appear in `maknaed` and `maknae`. Those are from AWS-LC's BoringSSL/OpenSSL-derived internal naming, not from OS OpenSSL linkage.
- `nix` is syscall binding surface for peer credentials, ownership, and filesystem operations. It is not crypto.
- `security-framework = "3"` is a macOS-only CLI enrollment dependency. The current implementation documents Keychain/SEP stubs as fail-closed for SecretID storage; this record did not build or link a macOS artifact.

> **ADDENDUM 2026-09-12 (#227) — the macOS artifact has now been built and linked, and it does NOT share this record's linkage finding.** The assessment above is Linux-only by its own statement, and its conclusion *"No production **Linux** release binary dynamically links…"* remains true as written. A reader must not generalise it to macOS, because the macOS artifact **dynamically links the AWS-LC FIPS module by design and by upstream requirement**. Measured on Wrathion (macOS 26.6.2, Apple Silicon): `otool -L target/debug/maknaed` reports `@rpath/libaws_lc_fips_0_13_17_crypto.dylib`, and `otool -l` reports **zero `LC_RPATH`**.
>
> This is upstream's mandated configuration, not drift: `aws-lc/CMakeLists.txt:842` refuses a static FIPS build outside Linux (verified — `AWS_LC_FIPS_SYS_STATIC=1 cargo build --target aarch64-apple-darwin` fails on that line), and `aws-lc-fips-sys/README.md:143` calls a shared `libcrypto` *"the required form for FIPS on macOS and Windows"*.
>
> **Two consequences for supply-chain visibility specifically, which is this record's subject:**
> 1. **The validated module differs by platform.** Linux links the static module (CMVP **#5314**); macOS necessarily links the dynamic one (**#5298**). Any artifact inventory, SBOM narrative or SC-13 claim that names a single certificate across both platforms is wrong on one of them.
> 2. **`ldd`-equivalent evidence does not transfer.** The Linux finding rests on `ldd` showing only libc/libm/libgcc/ld-linux. On macOS the correct instrument is `otool -L`, and a *clean* result there would mean the FIPS module is **missing**, not that it is absent by design. The macOS analogue of this record's finding is "the only non-system dylib is the AWS-LC FIPS module, resolved by absolute install name" — and establishing that is owed once #227's packaging lands.
- `openssl req ...` appears only in comments describing how fixed test CA fixtures were generated once. It is not a production runtime dependency.

Conclusion:

For the local Linux release build examined here, Maknae's shipped cryptography does not depend on OS-provided OpenSSL, NSS, GnuTLS, native-tls, or kernel crypto APIs. The crypto that reaches `maknaed` and `maknae` is vendored through registry crates, primarily AWS-LC and ring as described above.

## 5. `cargo-deny` Advisory DB Failure Mode (#156)

CI currently runs a bare:

```text
cargo deny check
```

Empirical negative test:

```text
CARGO_HOME="$PWD/.hobi-evidence/cargo-home-unreachable-2" \
GIT_CONFIG_COUNT=1 \
GIT_CONFIG_KEY_0=url.http://127.0.0.1:9/RustSec/advisory-db.insteadOf \
GIT_CONFIG_VALUE_0=https://github.com/RustSec/advisory-db \
timeout 120 cargo deny check
```

Observed result:

```text
exit=1
failed to fetch advisory database https://github.com/RustSec/advisory-db
fatal: unable to access 'http://127.0.0.1:9/RustSec/advisory-db/': Could not connect to server
```

Normal baseline result:

```text
advisories ok, bans ok, licenses ok, sources ok
```

Conclusion:

The current gate does not pass clean when a fresh advisory DB cannot be fetched. This directly answers the silent-clean failure concern for the RustSec DB fetch path.

## 6. `cargo auditable` Native-Code Visibility (#156)

`cargo auditable` embeds the Rust package graph that reached each binary:

- `maknaed`: 190 crates.io packages, 16 local packages, 41 build-kind entries.
- `maknae`: 205 crates.io packages, 6 local packages, 43 build-kind entries.
- `maknae-spifc`: 2 local packages, no build-kind entries.

For `maknaed` and `maknae`, the embedded manifest lists `aws-lc-fips-sys`, `aws-lc-rs`, `aws-lc-sys`, and `ring`. That is valuable: an operator can see that the AWS-LC wrapper crates and ring are present in the binary.

What it does not show is the native file inventory inside those crates. The manifest does not enumerate `/aws-lc/crypto/*.c`, assembly files, upstream AWS-LC commit provenance, or whether an upstream AWS-LC CVE maps to the vendored snapshot included by `aws-lc-sys` or `aws-lc-fips-sys`.

Conclusion:

`cargo auditable` helps prove which registry crates reached a binary, but it does not close the native AWS-LC C/assembly advisory-visibility gap.

## 7. Split-Out Finding

Finding:

Maknae currently has no in-repo gate or documented process that independently tracks upstream AWS-LC CVEs against the native C/assembly vendored by `aws-lc-sys` and `aws-lc-fips-sys`. RustSec/cargo-deny sees the Rust crates, and cargo-auditable embeds those crate identities in the binary, but neither mechanism validates the upstream AWS-LC native-code snapshot at file/CVE granularity.

Disposition:

Split into #191. This record intentionally does not choose the remedy; candidate remedies such as an upstream advisory watch, version-pin review discipline, or an explicitly accepted documented gap belong in that issue.

## 8. Limits of this record

This record is not a compliance submission, an ATO artifact, or a claim that Maknae satisfies any external control regime today. It is an engineering reference for a personal project targeting DoD deployability.

The compiled-artifact checks were performed on the local Linux host only. They did not build el9, el10, trixie, or macOS packages in their native CI/container environments. The source-level boot-ordering evidence applies across platforms, but platform-specific linker evidence is limited to the local Linux release build.

This record did not perform live Vault integration, live mTLS handshakes, FIPS module certificate validation, CMVP paperwork review, or AWS-LC upstream source archaeology. It relied on rustls/aws-lc-rs `.fips()` semantics as Maknae's current runtime gate and on the compiled crate graph present in the local release artifacts.

This record did not evaluate Vault-side cryptography, audit-record signing (#82/#96/#188), license policy beyond confirming the current `cargo deny check` result, or remedy design for the split-out AWS-LC native-code visibility gap.

This record did not audit every line of third-party dependency code. Grep of selected dependency source was used only to understand the `reqwest` rustls provider fallback and Maknae's own provider-selection risk.

The documentation site issue (#152) should carry the operator-facing version of this answer when that site lands. This file is the citable source record until then.
