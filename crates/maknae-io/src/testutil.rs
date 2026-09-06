//! Test-only helpers shared across the crate's module test suites.
//!
//! A separate module rather than a helper inside `anchor.rs`'s `mod tests`, because
//! `dir.rs` and `syscall.rs` need it too and the coverage gate requires `#[cfg(test)]`
//! to be followed by a line beginning `mod ` -- so `pub(crate) mod tests` is not
//! available as a way to share it.

/// Is the fail-closed skip explicitly opted out of on this host?
///
/// Requires exactly `1`. `var_os(..).is_some()` also accepted `MAKNAE_..=0` and an
/// empty value, so a host could opt out of every control while believing it had not
/// -- and the panic message tells the reader to set `=1`. The check matches the
/// message.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn opted_out() -> bool {
    std::env::var("MAKNAE_IO_ALLOW_SKIPPED_LANES").is_ok_and(|v| v == "1")
}

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
///
/// Every caller is inside a `#[cfg(target_os = "linux")]` test, so on darwin this is
/// genuinely unreferenced rather than accidentally so.
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

/// Re-exec one test so an intentionally broken blocking syscall can be killed
/// and reaped. A completion file proves the exact test body actually ran; an
/// empty libtest selection exits zero and is not a passing witness.
pub(crate) fn isolated(name: &str, case: impl FnOnce()) {
    isolated_with_timeout(name, std::time::Duration::from_secs(5), case);
}

fn isolated_with_timeout(name: &str, timeout: std::time::Duration, case: impl FnOnce()) {
    const CHILD: &str = "MAKNAE_IO_ISOLATED_TEST";
    const COMPLETE: &str = "MAKNAE_IO_ISOLATED_COMPLETE";
    if let Some(selected) = std::env::var_os(CHILD) {
        assert_eq!(selected, name, "unexpected isolated test selected");
        case();
        std::fs::write(std::env::var_os(COMPLETE).expect("completion path"), name)
            .expect("record completed witness");
        return;
    }

    // Child fixtures are beneath this parent-owned directory, so a killed
    // child cannot leave FIFO fixtures behind. Files avoid full-pipe deadlocks.
    let scratch = tempfile::tempdir().unwrap();
    let log_path = scratch.path().join("child.log");
    let log = std::fs::File::create(&log_path).unwrap();
    let proof = scratch.path().join("complete");
    struct Reap(std::process::Child);
    impl Drop for Reap {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = Reap(
        std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(CHILD, name)
            .env(COMPLETE, &proof)
            .env("TMPDIR", scratch.path())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        if std::time::Instant::now() >= deadline {
            drop(child); // kill AND reap before reporting a failure
            panic!("isolated test {name} exceeded {timeout:?}; child killed and reaped");
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    let output = std::fs::read_to_string(log_path).unwrap();
    assert!(status.success(), "isolated test {name} failed: {output}");
    assert_eq!(
        std::fs::read_to_string(proof).ok().as_deref(),
        Some(name),
        "isolated test body did not complete: {output}"
    );
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
        // No vacuous guard. An earlier version panicked with the same expected
        // substring when the opt-out was set, so on such a host the test passed
        // WITHOUT EVER CALLING the subject -- a control that asserted nothing while
        // reporting green, which is the exact failure this whole helper exists to
        // prevent. If the opt-out is set, say so and fail: the control genuinely
        // cannot run, and that is information, not an inconvenience.
        assert!(
            !super::opted_out(),
            "MAKNAE_IO_ALLOW_SKIPPED_LANES is set, so skip_or_fail's fail-closed \
             branch cannot be exercised and this control is inert on this host"
        );
        super::skip_or_fail("a_control", "a simulated reason");
    }

    #[test]
    #[should_panic(expected = "child killed and reaped")]
    fn a_blocked_child_is_a_bounded_failure() {
        super::isolated_with_timeout(
            "testutil::tests::a_blocked_child_is_a_bounded_failure",
            std::time::Duration::from_millis(100),
            || std::thread::sleep(std::time::Duration::from_secs(60)),
        );
    }

    #[test]
    #[should_panic(expected = "isolated test body did not complete")]
    fn an_empty_test_selection_is_not_success() {
        super::isolated("no_such_maknae_io_test_126", || {});
    }
}
