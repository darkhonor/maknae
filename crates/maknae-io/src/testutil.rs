//! Test-only helpers shared across the crate's module test suites.
//!
//! A separate module rather than a helper inside `anchor.rs`'s `mod tests`, because
//! `dir.rs` and `syscall.rs` need it too and the coverage gate requires `#[cfg(test)]`
//! to be followed by a line beginning `mod ` -- so `pub(crate) mod tests` is not
//! available as a way to share it.

/// Skips in this crate are FAIL-CLOSED, and that is not pedantry.
///
/// libtest CAPTURES `eprintln!` from a test that PASSES, and CI runs plain
/// `cargo test` -- so a printed "SKIP" is invisible in exactly the situation it
/// exists for. Measured: a marker printed from a passing test appears 0 times
/// under `cargo test` and 1 time under `cargo test -- --nocapture`. That also
/// means "no SKIP lines in the CI log" proves nothing either way.
///
/// What is at stake: `execute_only_descendant_separates_the_two_lanes` is the ONLY
/// test that discriminates the two lanes, and the non-UTF-8 fixture is the only
/// control over the raw-name classification. If the host loses `openat2` (a
/// seccomp filter returning EPERM) or the filesystem rejects the name, a quiet
/// `return` turns each of them into a green no-op. Panicking makes that loud;
/// a host that genuinely cannot run them opts out explicitly.
/// Is the fail-closed skip explicitly opted out of on this host?
///
/// Requires exactly `1`. `var_os(..).is_some()` also accepted `MAKNAE_..=0` and an
/// empty value, so a host could opt out of every control while believing it had not
/// -- and the panic message tells the reader to set `=1`. The check now matches the
/// message.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn opted_out() -> bool {
    std::env::var("MAKNAE_IO_ALLOW_SKIPPED_LANES").map(|v| v == "1") == Ok(true)
}

// Every caller is inside a `#[cfg(target_os = "linux")]` test, so on darwin this is
// genuinely unreferenced rather than accidentally so.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn skip_or_fail(what: &str, why: &str) {
    if opted_out() {
        eprintln!("SKIP {what}: {why} (allowed by MAKNAE_IO_ALLOW_SKIPPED_LANES)");
    } else {
        panic!(
            "{what} could not run: {why}.\n\
             This test is a CONTROL, not a nicety -- skipping it silently is how a \
             security property stops being tested without anyone noticing. If this \
             host genuinely cannot run it, set MAKNAE_IO_ALLOW_SKIPPED_LANES=1."
        );
    }
}

#[cfg(test)]
mod tests {
    /// `skip_or_fail` is itself a control, so it needs one.
    ///
    /// It is invisible to `cargo mutants` (cfg(test) modules are not mutated) and no
    /// test referenced it, so inverting `is_some()` to `is_none()` at its one branch
    /// silently restored the round-2 regression it exists to prevent: every skip goes
    /// back to passing quietly. This asserts the FAIL-CLOSED direction, which is the
    /// one that matters and the one that needs no environment mutation -- so it is
    /// safe under the parallel harness, unlike a test that would have to set or clear
    /// MAKNAE_IO_ALLOW_SKIPPED_LANES for the whole process.
    #[test]
    #[should_panic(expected = "could not run")]
    fn skip_or_fail_panics_when_the_opt_out_is_absent() {
        if super::opted_out() {
            // The opt-out is deliberately set on this host, so the fail-closed branch
            // cannot be reached. Panic with the expected text so the test still
            // asserts something rather than passing vacuously.
            panic!("could not run: MAKNAE_IO_ALLOW_SKIPPED_LANES is set on this host");
        }
        super::skip_or_fail("a_control", "a simulated reason");
    }
}
