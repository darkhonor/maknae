## What and why

Closes #

## Trust-plane, protocol, or ADR impact

None / describe.

## Evidence

- [ ] tests before implementation; a reported defect has a failing test first
- [ ] `cargo fmt`, `bash ci/gates/clippy-all.sh` clean, the drift gates pass locally
- [ ] If this touches `#[cfg(target_os = ...)]` code: `bash ci/gates/clippy-all.sh --linux` ran and PASSED (a SKIP is a lane gap, not a pass)
- [ ] mutation run on touched T1 files: zero missed (state the numbers)
- [ ] every commit carries a `Signed-off-by` (DCO)
