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

**The key-custody question is sharper here than for GPG.** A leaked Developer ID certificate
signs software attributed to the operator's identity, and revoking it invalidates everything
previously shipped under it. The GPG-key-on-ephemeral-runners trade was accepted knowingly; this
one deserves its own decision rather than inheriting that one.

**Shared with the iOS surface.** The proposed iOS remote-interface app needs the same Apple
Developer infrastructure — membership, certificates, API keys, notarization workflow. This is not
a macOS-only cost, and sequencing the two together avoids standing it up twice.

## Verification status

CI verifies macOS in two layers, neither of which is a substitute for the other:

1. **Cross-compile check** (`darwin-cross`, on the Linux runner) — proves the workspace's
   Rust-only crates *build* for `aarch64-` and `x86_64-apple-darwin`. Free, no Mac needed. It
   earned its place immediately: it caught `RecvFlags::CMSG_CLOEXEC` not existing on darwin,
   which meant `maknae-io::recv_delegated` did not compile there at all — a security-relevant
   delta (`FD_CLOEXEC` must then be set explicitly) that a Linux-only CI would never surface.
2. **Native test run** (`darwin-native`, on a `macos-15` runner) — actually executes the suites
   for the crates that build without a macOS SDK. This is what turns "written" into "verified".

**Not covered by either:** `maknae-vault` and everything above it. `aws-lc-fips-sys` and `ring`
have build scripts requiring a macOS SDK, so they cannot be cross-checked from Linux, and a
FIPS build on a hosted macOS runner has not been attempted. **macOS FIPS therefore rests on
manual runs on the operator's own Apple Silicon machine.** Separately and more importantly:
whether `aws-lc-fips` is FIPS-140-3 **validated** on macOS arm64 — as opposed to merely
compiling — is an open compliance question, and the answer may reshape what macOS deployment
means for a FIPS-posture product.

## References

- `packaging/isolation-contract.md` — the normative property × profile table
- **ADR-0009** — the `F_GETPATH` lane and its verification condition
- **ADR-0006** decision 4 — the macOS local-authentication predicate (`auid` + `utmpx`/console)
  and its documented attribution residual (no per-message sender credentials)
- `state/linux-test-hosts.md` — why no standing host can verify macOS
