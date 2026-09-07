//! Opt-in developmental proof across real subject/service credentials.
//! Run as root with MAKNAE_TEST_SUBJECT and MAKNAE_TEST_SERVICE naming existing
//! non-root accounts. Ordinary CI does not provision accounts or run this test.
use std::io::{Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::os::unix::{
    fs::PermissionsExt,
    net::{UnixListener, UnixStream},
};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn permissions(path: &Path, mode: u32) {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}
fn receive(stream: &UnixStream) -> OwnedFd {
    let received = maknae_io::recv_delegated(stream.as_fd(), &mut [0]).unwrap();
    assert_eq!(received.fds.len(), 1);
    received.fds.into_iter().next().unwrap()
}
fn send(stream: &UnixStream, fd: &OwnedFd) {
    assert_eq!(
        maknae_io::send_delegated(stream.as_fd(), b"f", fd.as_fd()).unwrap(),
        1
    );
}
fn wait(child: &mut std::process::Child) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert!(status.success(), "credential helper failed: {status}");
            return;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("credential helper stalled");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
#[ignore = "requires explicitly named development accounts and root orchestration"]
fn distinct_credentials_preserve_os_authority() {
    assert!(nix::unistd::geteuid().is_root());
    let subject = std::env::var("MAKNAE_TEST_SUBJECT").expect("existing subject account");
    let service = std::env::var("MAKNAE_TEST_SERVICE").expect("existing service account");
    let user = nix::unistd::User::from_name(&subject).unwrap().unwrap();
    let daemon = nix::unistd::User::from_name(&service).unwrap().unwrap();
    assert_ne!(user.uid, daemon.uid);
    assert!(!user.uid.is_root() && !daemon.uid.is_root());
    let base =
        std::env::temp_dir().join(format!("maknae-subject-mutations-{}", std::process::id()));
    std::fs::create_dir(&base).unwrap();
    permissions(&base, 0o755);
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let _cleanup = Cleanup(base.clone());
    let home = base.join("home");
    let project = home.join("projects");
    std::fs::create_dir_all(&project).unwrap();
    for path in [&home, &project] {
        nix::unistd::chown(path, Some(user.uid), Some(user.gid)).unwrap();
    }
    permissions(&home, 0o700);
    permissions(&project, 0o300);
    let existing = project.join("existing");
    std::fs::write(&existing, b"subject-writable-original").unwrap();
    nix::unistd::chown(&existing, Some(user.uid), Some(user.gid)).unwrap();
    permissions(&existing, 0o600);
    let locked = project.join("locked");
    std::fs::write(&locked, b"root-only-sentinel").unwrap();
    permissions(&locked, 0o400);
    let socket = base.join("socket");
    let listener = UnixListener::bind(&socket).unwrap();
    listener.set_nonblocking(true).unwrap();
    permissions(&socket, 0o666);
    let executable = std::env::current_exe().unwrap();
    // Pass fixture inputs explicitly after sudo so its environment policy cannot hide them.
    let spawn = |account: &str, role: &str| {
        Command::new("sudo")
            .args(["-n", "-u", account, "--", "env"])
            .arg(format!("MAKNAE_CREDENTIAL_ROLE={role}"))
            .arg(format!("MAKNAE_CREDENTIAL_BASE={}", base.display()))
            .arg(format!("MAKNAE_CREDENTIAL_UID={}", user.uid.as_raw()))
            .arg(&executable)
            .args(["--ignored", "--exact", "credential_helper", "--nocapture"])
            .spawn()
            .unwrap()
    };
    let accept = || {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(10)))
                        .unwrap();
                    return stream;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(10))
                }
                Err(e) => panic!("accept helper: {e}"),
            }
        }
    };
    let mut subject_child = spawn(&subject, "subject");
    let mut subject_socket = accept();
    let writable = receive(&subject_socket);
    let directory = receive(&subject_socket);
    let mut service_child = spawn(&service, "service");
    let mut service_socket = accept();
    send(&service_socket, &writable);
    send(&service_socket, &directory);
    service_socket.read_exact(&mut [0]).unwrap();
    subject_socket.write_all(b"g").unwrap();
    wait(&mut service_child);
    wait(&mut subject_child);
    assert_eq!(
        std::fs::read(existing).unwrap(),
        b"written-through-subject-fd"
    );
    assert_eq!(std::fs::read(locked).unwrap(), b"root-only-sentinel");
    assert!(!project.join("created").exists());
    assert!(!project.join("directory").exists());
}

#[test]
#[ignore = "subprocess entrypoint for the opt-in credential test"]
fn credential_helper() {
    let Ok(role) = std::env::var("MAKNAE_CREDENTIAL_ROLE") else {
        return;
    };
    let base = PathBuf::from(std::env::var_os("MAKNAE_CREDENTIAL_BASE").unwrap());
    let home = base.join("home");
    let project = home.join("projects");
    let mut stream = UnixStream::connect(base.join("socket")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let required = maknae_io::MutationRequired {
        confined_beneath: home.clone(),
        root_required: maknae_io::AnchorRequired {
            owner: Some(
                std::env::var("MAKNAE_CREDENTIAL_UID")
                    .unwrap()
                    .parse()
                    .unwrap(),
            ),
            mode_mask: Some(0o022),
        },
    };
    if role == "subject" {
        let file = maknae_io::open_writable_for_delegation(&project.join("existing")).unwrap();
        assert_eq!(
            maknae_io::open_writable_for_delegation(&project.join("locked"))
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
        let directory = maknae_io::open_directory_for_delegation(&project).unwrap();
        send(&stream, &file);
        send(&stream, &directory);
        stream.read_exact(&mut [0]).unwrap();
        let directory = maknae_io::verify_mutation_directory(directory, required).unwrap();
        directory.create_exclusive("created", b"new").unwrap();
        directory.remove_entry("created").unwrap();
        directory.mkdir_one("directory").unwrap();
        directory.remove_entry("directory").unwrap();
    } else {
        assert_eq!(role, "service");
        let file = receive(&stream);
        let directory = receive(&stream);
        assert!(maknae_io::open_writable_for_delegation(&project.join("existing")).is_err());
        let object = maknae_io::verify_writable_object(
            file,
            maknae_io::DelegatedRequired {
                confined_beneath: home,
                root_required: required.root_required.clone(),
                target: maknae_io::TargetRequired {
                    owner: None,
                    mode_mask: None,
                    nlink_exactly_one: true,
                    regular_file: true,
                    max_bytes: None,
                },
            },
        )
        .unwrap();
        maknae_io::replace_existing(object, b"written-through-subject-fd").unwrap();
        let directory = maknae_io::verify_mutation_directory(directory, required).unwrap();
        for failure in [
            directory
                .create_exclusive("service-create", b"forbidden")
                .unwrap_err(),
            directory.mkdir_one("service-mkdir").unwrap_err(),
            directory.remove_entry("existing").unwrap_err(),
        ] {
            assert_eq!(failure.state, maknae_io::EffectState::NoEffect);
            assert!(matches!(
                failure.source,
                maknae_io::IoError::Io {
                    kind: maknae_io::IoKind::PermissionDenied,
                    ..
                }
            ));
        }
        stream.write_all(b"d").unwrap();
    }
}
