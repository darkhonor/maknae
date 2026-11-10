## What and why

Closes #

## Trust-plane, protocol, or ADR impact

None / describe.

## Evidence

- [ ] tests before implementation; a reported defect has a failing test first
- [ ] `cargo fmt`, `bash ci/gates/clippy-all.sh` clean, the drift gates pass locally
- [ ] If this touches `#[cfg(target_os = ...)]` code: `bash ci/gates/clippy-all.sh --linux` ran and PASSED (a SKIP is a lane gap, not a pass)
- [ ] in-diff mutation run through the hook (`MAKNAE_PRE_PUSH_MUTANTS=1 git push`, every `[t1].mutants_crates` crate): zero missed. State `in-diff: N caught, N unviable, 0 timeout, 0 missed` with the `RUN` and `SKIP:` lines
- [ ] every commit carries a `Signed-off-by` (DCO)
