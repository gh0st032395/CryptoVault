//! End-to-end tests that run the actual binary.
//!
//! The unit tests cover parsing and the layers underneath cover the vault. What
//! is left — and what these check — is whether the program as a whole does what
//! someone typing at a shell would expect: the exit codes, the round trip
//! through the filesystem, and the promise that nothing readable is left on
//! disk.
//!
//! They shell out rather than calling into the code, because an exit code that
//! is only correct in a unit test is not an exit code.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code: a panic is a failing test"
)]

use std::path::Path;
use std::process::{Command, Output};

const PASSWORD: &str = "the vector password";

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_cryptovault"))
        .args(args)
        .env("CRYPTOVAULT_PASSWORD", PASSWORD)
        .output()
        .expect("the binary should be runnable")
}

fn run_ok(args: &[&str]) -> String {
    let output = run(args);
    assert!(
        output.status.success(),
        "`{}` failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn code(output: &Output) -> i32 {
    output.status.code().unwrap_or(-1)
}

/// Create a vault, put files in it, take one out again, and check it survived.
#[test]
fn a_vault_can_be_created_filled_and_read_back() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let vault_str = vault.to_str().unwrap();

    let source = dir.path().join("source.bin");
    let contents: Vec<u8> = (0..70_000)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();
    std::fs::write(&source, &contents).unwrap();

    run_ok(&["init", vault_str]);
    run_ok(&["mkdir", vault_str, "/Documents/2026"]);
    run_ok(&[
        "add",
        vault_str,
        source.to_str().unwrap(),
        "/Documents/2026/report.bin",
    ]);

    let listing = run_ok(&["ls", vault_str, "/Documents/2026"]);
    assert!(listing.contains("report.bin"), "{listing}");
    assert!(listing.contains("70000"), "the size is missing: {listing}");

    let extracted = dir.path().join("extracted.bin");
    run_ok(&[
        "get",
        vault_str,
        "/Documents/2026/report.bin",
        extracted.to_str().unwrap(),
    ]);
    assert_eq!(std::fs::read(&extracted).unwrap(), contents);
}

/// Scripts distinguish these, so they are a contract.
#[test]
fn exit_codes_mean_what_they_say() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let vault_str = vault.to_str().unwrap();

    run_ok(&["init", vault_str]);

    // 0: success.
    assert_eq!(code(&run(&["ls", vault_str])), 0);

    // 2: the command line was wrong.
    assert_eq!(code(&run(&["frobnicate", vault_str])), 2);
    assert_eq!(code(&run(&["mkdir", vault_str])), 2);

    // 1: the operation ran and failed.
    assert_eq!(code(&run(&["ls", vault_str, "/missing"])), 1);

    // 3: wrong password, and only wrong password.
    let wrong = Command::new(env!("CARGO_BIN_EXE_cryptovault"))
        .args(["ls", vault_str])
        .env("CRYPTOVAULT_PASSWORD", "not the password")
        .output()
        .unwrap();
    assert_eq!(code(&wrong), 3);
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("wrong password"));
}

#[test]
fn moving_and_removing_work_from_the_command_line() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let vault_str = vault.to_str().unwrap();

    let source = dir.path().join("f.txt");
    std::fs::write(&source, b"contents").unwrap();

    run_ok(&["init", vault_str]);
    run_ok(&["mkdir", vault_str, "/sub"]);
    run_ok(&["add", vault_str, source.to_str().unwrap(), "/f.txt"]);

    run_ok(&["mv", vault_str, "/f.txt", "/sub/moved.txt"]);
    assert!(run_ok(&["ls", vault_str, "/sub"]).contains("moved.txt"));
    assert!(!run_ok(&["ls", vault_str]).contains("f.txt"));

    run_ok(&["rm", vault_str, "/sub/moved.txt"]);
    assert!(!run_ok(&["ls", vault_str, "/sub"]).contains("moved.txt"));
}

#[test]
fn verify_reports_a_healthy_vault() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let vault_str = vault.to_str().unwrap();

    let source = dir.path().join("f.bin");
    std::fs::write(&source, vec![7_u8; 100_000]).unwrap();

    run_ok(&["init", vault_str]);
    run_ok(&["add", vault_str, source.to_str().unwrap(), "/f.bin"]);

    let report = run_ok(&["verify", vault_str]);
    assert!(report.contains("Everything authenticates"), "{report}");
    assert!(report.contains("100000"), "{report}");
}

/// A damaged vault must be reported as damaged rather than read as though
/// nothing were wrong. This is the case `verify` exists for.
#[test]
fn verify_notices_a_damaged_file() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let vault_str = vault.to_str().unwrap();

    let source = dir.path().join("f.bin");
    std::fs::write(&source, vec![7_u8; 50_000]).unwrap();

    run_ok(&["init", vault_str]);
    run_ok(&["add", vault_str, source.to_str().unwrap(), "/f.bin"]);
    assert!(run_ok(&["verify", vault_str]).contains("Everything authenticates"));

    corrupt_one_byte_of_a_chunk(&vault);

    let output = run(&["verify", vault_str]);
    assert_eq!(code(&output), 1, "a damaged vault reported success");
    let report = String::from_utf8_lossy(&output.stdout);
    assert!(report.contains("DAMAGED"), "{report}");
}

/// Flips a byte well past any header, so the damage lands in chunk data.
fn corrupt_one_byte_of_a_chunk(vault: &Path) {
    let mut victim = None;
    let mut stack = vec![vault.to_path_buf()];

    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).unwrap().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "cvf")
                && std::fs::metadata(&path).unwrap().len() > 10_000
            {
                victim = Some(path);
            }
        }
    }

    let path = victim.expect("the vault should contain a large encrypted file");
    let mut bytes = std::fs::read(&path).unwrap();
    let target = bytes.len() / 2;
    bytes[target] ^= 0xFF;
    std::fs::write(&path, bytes).unwrap();
}

/// The whole point. Nothing the user typed may be readable in the vault
/// directory — not in a filename, not inside a file.
#[test]
fn nothing_readable_is_left_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let vault_str = vault.to_str().unwrap();

    let source = dir.path().join("s.txt");
    std::fs::write(&source, b"DISTINCTIVE-CONTENTS").unwrap();

    run_ok(&["init", vault_str]);
    run_ok(&["mkdir", vault_str, "/DISTINCTIVE-FOLDER"]);
    run_ok(&[
        "add",
        vault_str,
        source.to_str().unwrap(),
        "/DISTINCTIVE-FOLDER/DISTINCTIVE-NAME.txt",
    ]);

    let mut stack = vec![vault.clone()];
    let mut files = 0;
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).unwrap().filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            files += 1;
            let bytes = std::fs::read(&path).unwrap();
            let name = path.to_string_lossy();

            for needle in [
                "DISTINCTIVE-FOLDER",
                "DISTINCTIVE-NAME",
                "DISTINCTIVE-CONTENTS",
            ] {
                assert!(!name.contains(needle), "{needle} is in the path {name}");
                assert!(
                    !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                    "{needle} is inside {name}"
                );
            }
        }
    }
    assert!(files >= 3, "the walk found only {files} files");
}

/// `inspect` is for a vault that will not open, so it must work without one.
#[test]
fn inspect_describes_a_vault_without_a_password() {
    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");
    let vault_str = vault.to_str().unwrap();

    run_ok(&["init", vault_str, "--sealed"]);

    let described = Command::new(env!("CARGO_BIN_EXE_cryptovault"))
        .args(["inspect", vault_str])
        .env_remove("CRYPTOVAULT_PASSWORD")
        .output()
        .unwrap();

    assert!(described.status.success());
    let text = String::from_utf8_lossy(&described.stdout);
    assert!(text.contains("AES-256-GCM"), "{text}");
    assert!(text.contains("sealed:    true"), "{text}");
    assert!(
        text.contains("Password"),
        "the slot is not described: {text}"
    );
    // …and it says plainly that none of it is verified yet.
    assert!(text.contains("Not verified"), "{text}");
}

/// The password has to be able to arrive without an environment variable, since
/// the help text tells people to prefer that.
#[test]
fn the_password_can_come_from_stdin() {
    use std::io::Write as _;
    use std::process::Stdio;

    let dir = tempfile::tempdir().unwrap();
    let vault = dir.path().join("vault");

    let mut child = Command::new(env!("CARGO_BIN_EXE_cryptovault"))
        .args(["init", vault.to_str().unwrap(), "--password-stdin"])
        .env_remove("CRYPTOVAULT_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"a password from stdin\n")
        .unwrap();
    assert!(child.wait().unwrap().success());

    let listed = Command::new(env!("CARGO_BIN_EXE_cryptovault"))
        .args(["ls", vault.to_str().unwrap()])
        .env("CRYPTOVAULT_PASSWORD", "a password from stdin")
        .output()
        .unwrap();
    assert!(
        listed.status.success(),
        "the stdin password did not open the vault"
    );
}

/// Refusing an empty password is the interface's job, and this is the interface.
#[test]
fn an_empty_password_is_refused_at_creation() {
    let dir = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cryptovault"))
        .args(["init", dir.path().join("vault").to_str().unwrap()])
        .env("CRYPTOVAULT_PASSWORD", "")
        .output()
        .unwrap();

    assert_eq!(code(&output), 1);
    assert!(String::from_utf8_lossy(&output.stderr).contains("empty password"));
}
