//! `cryptovault` — command-line interface to a vault.
//!
//! Built first as the project's own test instrument: it lets every vault
//! operation be exercised end to end before a single pixel of interface exists.
//! It becomes a supported tool after the desktop release, once the command
//! surface has stopped moving.
//!
//! # The password
//!
//! From `CRYPTOVAULT_PASSWORD`, or from standard input with `--password-stdin`.
//! There is no interactive prompt yet: reading a password without echoing it
//! needs platform-specific terminal handling, and that belongs with the release
//! rather than with a test instrument.
//!
//! An environment variable is not a good place for a password — it is visible
//! to other processes on some systems and lands in shell history — so the help
//! text says so rather than pretending otherwise.
//!
//! # Exit codes
//!
//! Scripts rely on the difference, so it is a contract rather than an accident:
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | Success |
//! | 1 | The operation ran and failed |
//! | 2 | The command line was wrong |
//! | 3 | Wrong password |

// Unit tests are allowed the shortcuts production code is not: a panicking
// assertion in a test is a failing test, which is the point.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod args;

use std::io::{Read, Write};
use std::path::Path;
use std::process::ExitCode;

use args::{Command, Invocation, PasswordSource};
use cv_format::names::EntryKind;
use cv_vault::{CreateOptions, Vault, VaultError};
use cv_vfs::{DirectVaultFs, VPath, VaultFs, VfsError};

/// Version of the CryptoVault workspace, taken from `Cargo.toml`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Environment variable holding the password.
const PASSWORD_VARIABLE: &str = "CRYPTOVAULT_PASSWORD";

/// Buffer used when copying a file in or out. Four chunks at a time.
const COPY_BUFFER: usize = 4 * 32 * 1024;

/// Widens a byte count. Saturating keeps the conversion total; the buffer is a
/// fixed constant, so it can never be reached.
fn read_as_u64(read: usize) -> u64 {
    u64::try_from(read).unwrap_or(u64::MAX)
}

fn main() -> ExitCode {
    let arguments: Vec<String> = std::env::args().skip(1).collect();

    let invocation = match args::parse(&arguments) {
        Ok(invocation) => invocation,
        Err(error) => {
            eprintln!("cryptovault: {error}");
            eprintln!("Try 'cryptovault --help'.");
            return ExitCode::from(2);
        }
    };

    match run(&invocation) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::WrongPassword) => {
            eprintln!("cryptovault: wrong password");
            ExitCode::from(3)
        }
        Err(Failure::Message(message)) => {
            eprintln!("cryptovault: {message}");
            ExitCode::FAILURE
        }
    }
}

/// Why a command did not complete.
enum Failure {
    /// The credential was wrong. Its own variant because scripts distinguish it.
    WrongPassword,
    /// Anything else, already phrased for a human.
    Message(String),
}

impl From<VaultError> for Failure {
    fn from(error: VaultError) -> Self {
        if error.is_wrong_credential() {
            Self::WrongPassword
        } else {
            Self::Message(error.to_string())
        }
    }
}

impl From<VfsError> for Failure {
    fn from(error: VfsError) -> Self {
        match error {
            VfsError::Vault(vault) => Self::from(vault),
            other => Self::Message(other.to_string()),
        }
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        Self::Message(error.to_string())
    }
}

fn run(invocation: &Invocation) -> Result<(), Failure> {
    match &invocation.command {
        Command::Help => {
            print_help();
            Ok(())
        }
        Command::Version => {
            println!("cryptovault {VERSION}");
            Ok(())
        }
        Command::Inspect { vault } => inspect(vault),
        Command::Init { vault, sealed } => init(vault, *sealed, invocation.password),
        Command::List { vault, path } => {
            list(&open(vault, invocation.password)?, &parse_path(path)?)
        }
        Command::MakeDir { vault, path } => {
            open(vault, invocation.password)?.create_dir_all(&parse_path(path)?)?;
            Ok(())
        }
        Command::Add {
            vault,
            source,
            destination,
        } => add(
            &open(vault, invocation.password)?,
            source,
            &parse_path(destination)?,
        ),
        Command::Get {
            vault,
            source,
            destination,
        } => get(
            &open(vault, invocation.password)?,
            &parse_path(source)?,
            destination,
        ),
        Command::Remove { vault, path } => {
            open(vault, invocation.password)?.remove(&parse_path(path)?)?;
            Ok(())
        }
        Command::Move { vault, from, to } => {
            open(vault, invocation.password)?.rename(&parse_path(from)?, &parse_path(to)?)?;
            Ok(())
        }
        Command::Verify { vault } => verify(&open(vault, invocation.password)?),
    }
}

// --- commands --------------------------------------------------------------

fn init(root: &Path, sealed: bool, source: PasswordSource) -> Result<(), Failure> {
    let password = read_password(source)?;

    if password.is_empty() {
        return Err(Failure::Message(
            "refusing to create a vault with an empty password".into(),
        ));
    }

    let options = CreateOptions {
        sealed,
        ..CreateOptions::default()
    };
    let vault = Vault::create(root, password.as_bytes(), options)?;

    println!("Created a vault at {}", root.display());
    if sealed {
        println!("  sealed: plaintext may not leave this vault");
    }
    println!();
    println!("There is no way to recover this password. If you lose it, the vault");
    println!("is gone — that is the point of the tool, and it is the most common");
    println!("way people lose data with software like this.");

    // Silences the unused warning while making the point that the handle is
    // dropped — and the keys wiped — as soon as creation is done.
    drop(vault);
    Ok(())
}

fn list(fs: &DirectVaultFs, path: &VPath) -> Result<(), Failure> {
    let mut entries = fs.read_dir(path)?;
    entries.sort_by(|a, b| {
        (a.kind == EntryKind::File)
            .cmp(&(b.kind == EntryKind::File))
            .then_with(|| a.name.cmp(&b.name))
    });

    for entry in entries {
        match entry.kind {
            EntryKind::Directory => println!("{:>12}  {}/", "<dir>", entry.name),
            EntryKind::File => {
                let child = path.join(&entry.name)?;
                let size = fs.stat(&child)?.size;
                println!("{size:>12}  {}", entry.name);
            }
        }
    }
    Ok(())
}

fn add(fs: &DirectVaultFs, source: &Path, destination: &VPath) -> Result<(), Failure> {
    let mut input = std::fs::File::open(source)?;
    fs.create_file(destination)?;

    let mut buffer = vec![0_u8; COPY_BUFFER];
    let mut offset = 0_u64;
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        fs.write_at(destination, offset, &buffer[..read])?;
        offset += read_as_u64(read);
    }

    println!(
        "Added {} ({offset} bytes) as {destination}",
        source.display()
    );
    Ok(())
}

fn get(fs: &DirectVaultFs, source: &VPath, destination: &Path) -> Result<(), Failure> {
    let size = fs.stat(source)?.size;
    let mut output = std::fs::File::create(destination)?;

    let mut buffer = vec![0_u8; COPY_BUFFER];
    let mut offset = 0_u64;
    while offset < size {
        let read = fs.read_at(source, offset, &mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
        offset += read_as_u64(read);
    }
    output.sync_all()?;

    println!("Wrote {offset} bytes to {}", destination.display());
    eprintln!("This copy is not encrypted.");
    Ok(())
}

/// Walks the whole vault and decrypts every chunk, discarding the plaintext.
///
/// Nothing decrypted is written anywhere or printed: the point is to confirm
/// that every authentication tag still verifies, not to produce the contents.
fn verify(fs: &DirectVaultFs) -> Result<(), Failure> {
    let mut files = 0_u64;
    let mut directories = 0_u64;
    let mut bytes = 0_u64;
    let mut damaged: Vec<String> = Vec::new();

    let mut queue = vec![VPath::root()];
    while let Some(directory) = queue.pop() {
        let entries = match fs.read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) => {
                damaged.push(format!("{directory}: {error}"));
                continue;
            }
        };

        for entry in entries {
            let Ok(path) = directory.join(&entry.name) else {
                continue;
            };

            match entry.kind {
                EntryKind::Directory => {
                    directories += 1;
                    queue.push(path);
                }
                EntryKind::File => {
                    files += 1;
                    match read_and_discard(fs, &path) {
                        Ok(read) => bytes += read,
                        Err(error) => damaged.push(format!("{path}: {error}")),
                    }
                }
            }
        }
    }

    println!("Checked {files} files and {directories} directories, {bytes} bytes.");

    if damaged.is_empty() {
        println!("Everything authenticates.");
        return Ok(());
    }

    for problem in &damaged {
        println!("  DAMAGED  {problem}");
    }
    Err(Failure::Message(format!(
        "{} entries failed verification",
        damaged.len()
    )))
}

fn read_and_discard(fs: &DirectVaultFs, path: &VPath) -> Result<u64, VfsError> {
    let size = fs.stat(path)?.size;
    let mut buffer = vec![0_u8; COPY_BUFFER];
    let mut offset = 0_u64;

    while offset < size {
        let read = fs.read_at(path, offset, &mut buffer)?;
        if read == 0 {
            break;
        }
        offset += read_as_u64(read);
    }
    Ok(offset)
}

/// Prints what can be learned about a vault without opening it.
///
/// Deliberately available without a password: it is the command for a vault
/// that will not open, and refusing to describe one until it opens would be
/// exactly backwards.
fn inspect(root: &Path) -> Result<(), Failure> {
    let bytes = std::fs::read(root.join(cv_format::consts::VAULT_CONFIG_NAME))
        .map_err(|error| Failure::Message(format!("no vault at {}: {error}", root.display())))?;

    let config = cv_format::config::VaultConfig::decode_unverified(&bytes)
        .map_err(|error| Failure::Message(error.to_string()))?;

    println!("Vault at {}", root.display());
    println!("  algorithm: {}", config.algorithm.name());
    println!("  sealed:    {}", config.sealed);
    println!("  created:   {} (Unix seconds)", config.created);
    println!("  slots:     {}", config.slots.len());

    for (index, slot) in config.slots.iter().enumerate() {
        let supported = if slot.kind.is_supported() {
            ""
        } else {
            " — not supported by this build"
        };
        println!(
            "    [{index}] {:?} {:?}  argon2id m={} t={} p={}{supported}",
            slot.kind,
            slot.label,
            slot.params.memory_kib(),
            slot.params.iterations(),
            slot.params.parallelism(),
        );
    }

    println!();
    println!("Not verified: the configuration's authenticity can only be checked");
    println!("after a slot has been opened, so nothing above is trustworthy yet.");
    Ok(())
}

// --- helpers ---------------------------------------------------------------

fn open(root: &Path, source: PasswordSource) -> Result<DirectVaultFs, Failure> {
    let password = read_password(source)?;
    Ok(DirectVaultFs::new(Vault::open(root, password.as_bytes())?))
}

fn parse_path(text: &str) -> Result<VPath, Failure> {
    VPath::parse(text).map_err(|error| Failure::Message(error.to_string()))
}

fn read_password(source: PasswordSource) -> Result<String, Failure> {
    match source {
        PasswordSource::Environment => std::env::var(PASSWORD_VARIABLE).map_err(|_| {
            Failure::Message(format!(
                "set {PASSWORD_VARIABLE}, or pass --password-stdin and provide it on stdin"
            ))
        }),
        PasswordSource::Stdin => {
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            Ok(line.trim_end_matches(['\n', '\r']).to_owned())
        }
    }
}

fn print_help() {
    println!(
        "\
cryptovault {VERSION}
Command-line interface to a CryptoVault encrypted vault.

USAGE
    cryptovault <COMMAND> <VAULT> [ARGUMENTS]

COMMANDS
    init    <vault> [--sealed]        Create a vault
    ls      <vault> [path]            List a directory
    mkdir   <vault> <path>            Create a directory and its parents
    add     <vault> <file> <path>     Copy a file into the vault
    get     <vault> <path> <file>     Copy a file out of the vault
    rm      <vault> <path>            Remove an entry
    mv      <vault> <from> <to>       Move or rename an entry
    verify  <vault>                   Check every file without writing plaintext
    inspect <vault>                   Describe a vault without opening it

OPTIONS
    --password-stdin    Read the password from the first line of stdin
    --sealed            With init: forbid plaintext from leaving the vault
    -h, --help          Print this help
    -V, --version       Print the version

THE PASSWORD
    Taken from {PASSWORD_VARIABLE}, or from stdin with --password-stdin.
    An environment variable is a poor place for a password: on some systems
    other processes can read it, and it tends to end up in shell history.
    Prefer --password-stdin. An interactive prompt arrives with the release.

EXIT CODES
    0 success   1 operation failed   2 bad command line   3 wrong password

STATUS
    Milestone M2. The command surface is not stable and this tool is not yet
    supported for scripting.

CryptoVault never sends anything over the network.
https://github.com/gh0st032395/CryptoVault"
    );
}
