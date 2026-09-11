# macOS packaging

**macOS is a deployment target.** Not a dev profile, not a reduced tier — a platform Maknae
intends to serve, alongside the Linux reference. `packaging/isolation-contract.md` carries the
normative statement; this directory holds the packaging that follows from it.

> **Rewritten 2026-08-30.** The previous text read *"macOS is a dev profile, not an enforcement
> reference."* That phrasing was never a decision about macOS's status — it was a note that work
> should not stall while macOS hardware was unavailable to test on. It was read as a status
> ruling anyway, including by an agent that used it to argue an unverified macOS syscall lane was
> acceptable because "macOS is a dev host". Replaced outright rather than annotated, because the
> sentence was the problem: a scheduling caveat written as an architectural claim.

## What ships

| Artifact | Tool | State |
|---|---|---|
| `maknaed` + `maknae` universal binaries | `cargo build --target {aarch64,x86_64}-apple-darwin` → `lipo` | not built |
| launchd plist for `maknaed` | hand-authored; `plutil -lint` in smoke | not authored |
| `_maknae` daemon user | `sysadminctl` / installer preinstall | not authored |
| `.pkg` installer | `pkgbuild` → `productbuild` | not built |
| Signature + notarization | Developer ID Installer cert → `notarytool` → `stapler` | not configured |

## The isolation delta, stated

macOS has **no seccomp equivalent**, so the systemd `SystemCallFilter=` half of the Linux
profile has no counterpart. That is a genuine platform fact and is recorded as a delta in the
isolation contract. **"We have not tested it there" is not a delta** — it is an unmet
obligation, and the distinction is the whole point of the rewrite above.

The launchd plist must still deliver the properties that *do* have equivalents: a dedicated
unprivileged daemon user, no elevated capabilities, restricted filesystem exposure, and a
service that fails closed rather than degrading.

## Signing is a different trust chain from Linux

`packaging/sign.sh` signs rpm/deb with the project GPG key. **That does not transfer.** Gatekeeper
does not consult GPG; macOS distribution requires Apple's chain:

- a **Developer ID Application** certificate for the binaries,
- a **Developer ID Installer** certificate for the `.pkg` — a different cert, not the same one,
- **notarization** through `notarytool` with an App Store Connect API key, then `stapler` to
  attach the ticket so first launch works offline.

Unsigned or un-notarized packages are refused on any Mac that has not had the policy relaxed.
An MDM-managed fleet can carry an exception, but designing for that narrows deployment to
managed estates only — decide it deliberately rather than by omission.

**Mechanism for CI.** GitHub documents the runner-side pattern —
[Installing an Apple certificate on macOS runners for Xcode development](https://docs.github.com/en/actions/how-tos/deploy/deploy-to-third-party-platforms/sign-xcode-applications):
base64 the `.p12` into a secret, import it into a **temporary keychain** created for
the run, and delete the keychain in an `if: always()` cleanup step. The same shape
applies to a `pkgbuild`/`productbuild` flow — the certificate is different (Installer,
not Application) but the custody pattern is identical. Notarization credentials
(App Store Connect key id, issuer id, `.p8`) are separate secrets on the same footing.

Two things that guide does not decide for us: the cleanup step is **not optional** on a
hosted runner (an un-deleted keychain outlives the job only if the runner is reused —
which is exactly the case on a self-hosted one), and `if: always()` is what makes it
hold on a failed run.

**The key-custody question is sharper here than for GPG.** A leaked Developer ID certificate
signs software attributed to the operator's identity, and revoking it invalidates everything
previously shipped under it. The GPG-key-on-ephemeral-runners trade was accepted knowingly; this
one deserves its own decision rather than inheriting that one.

**Shared with the iOS surface.** The proposed iOS remote-interface app needs the same Apple
Developer infrastructure — membership, certificates, API keys, notarization workflow. This is not
a macOS-only cost, and sequencing the two together avoids standing it up twice.

## Verification status

CI verifies macOS in two layers, neither of which is a substitute for the other:

1. **Cross-compile check** (`darwin-cross`, on the Linux runner) — checks every workspace member for `aarch64-apple-darwin` and names what the Linux host cannot build (the SDK crates), the supported Apple Silicon target. No hosted Mac is needed. It caught `RecvFlags::CMSG_CLOEXEC` not existing on darwin, which meant `maknae-io::recv_delegated` did not compile there at all. The corresponding `FD_CLOEXEC` handling must be checked on the supported platform.
2. **Native test run** (`darwin-native`, on the `macos-26` hosted runner) — executes `cargo test --locked --workspace`: the **whole** workspace, SDK crates included, with the unified-log round-trip a hard failure. This is what turned "written" into "verified" for ADR-0009's `F_GETPATH` lane. It runs whenever Rust is affected (docs-only changes skip it). *(Corrected 2026-09-11, #198: this said the native lane ran "the suites for the crates that build without a macOS SDK" and ran only when "a covered crate or one of its dependencies" changed — both were true while it inherited the cross-check's hand list, and both are now false.)*

**Corrected 2026-09-11 (#198).** This paragraph said `maknae-vault` and everything above it were covered by neither lane and rested on manual Wrathion runs. That was true while `darwin-native` inherited the cross-check's SDK-free list; it now tests the **whole workspace** — the `macos-26` runner has the SDK, and GitHub's billing doc is explicit that standard hosted runners, macOS included, are free on public repositories. What remains true: `aws-lc-fips-sys` and `ring` cannot be **cross-checked from Linux** (their build scripts need the SDK), so the cross-check lane runs the check per member and reports what the Linux host cannot build, by name, on every run, and the native lane is the only CI evidence for them. Separately and more importantly:
whether `aws-lc-fips` is FIPS-140-3 **validated** on macOS arm64 — as opposed to merely
compiling — is an open compliance question, and the answer may reshape what macOS deployment
means for a FIPS-posture product.

**RESOLVED 2026-09-11 (#200, maintainer ruling).** It is not. The module Maknae pins (`aws-lc-fips-sys` 0.13.x, the AWS-LC FIPS 3.x line) is CMVP-validated as **certificate #5314** (static; #5298 dynamic), and that certificate's security policy, Table 3 *Tested Operational Environments*, lists exactly: **Amazon Linux 2023 on Graviton4 (ARMv9, r8g.metal-24xl) and on Intel Xeon Platinum 8375C (c6i.metal), each with and without PAA** — vendor-affirmed environments: *N/A*. The policy's own words: *"CMVP makes no statement as to the correct operation of the module or the security strengths of the generated keys when so ported if the specific operational environment is not listed on the validation certificate."* macOS on Apple Silicon is therefore a **ported**, unvalidated operational environment: the module compiles and its self-tests and our suites pass there in CI (`darwin-native`, observed green 2026-09-11), and Maknae does **not** claim FIPS 140-3 validation on macOS. Note the same table for the Linux profile: RHEL/Rocky 9 on generic x86_64/aarch64 is not a listed environment either — the validated deployment is Amazon Linux 2023 on those two CPUs; everything else runs a validated *module* outside its tested *environments*, which is the honest form of the claim on every platform Maknae ships today. The ruling: macOS stays a production target; a deployment with a FIPS compliance obligation will not be on macOS regardless (there is a macOS STIG, but a STIG'd host is still an unlisted environment for this module), so the posture statement is the fact above, not a plan to change it. The normative statement lives in `packaging/isolation-contract.md`; this paragraph mirrors it.

## References

- `packaging/isolation-contract.md` — the normative property × profile table
- **ADR-0009** — the `F_GETPATH` lane and its verification condition
- **ADR-0006** decision 4 — the macOS local-authentication predicate (`auid` + `utmpx`/console)
  and its documented attribution residual (no per-message sender credentials)
- the maintainer's out-of-repo host notes — why no standing Linux host can verify macOS
