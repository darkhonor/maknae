use std::io::Write;
use std::process::{Command, Stdio};

fn login_with_stdin(input: Option<&[u8]>) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_maknae"))
        .arg("login")
        .env("MAKNAE_CONFIG_DIR", "/nonexistent/maknae-login-off-tty")
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(bytes) = input {
        let _ = child.stdin.take().unwrap().write_all(bytes);
    }
    child.wait_with_output().unwrap()
}

#[test]
fn login_refuses_without_a_terminal_before_reading_anything() {
    for input in [None, Some(b"hunter2\n".as_slice())] {
        let out = login_with_stdin(input);
        assert_eq!(out.status.code(), Some(1));
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("no terminal on standard input"), "{err}");
        assert!(!err.contains("hunter2"), "{err}");
        assert!(out.stdout.is_empty());
    }
}
