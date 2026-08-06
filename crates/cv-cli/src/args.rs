//! Command-line parsing.
//!
//! Hand-written rather than pulled from a crate. Nine commands with positional
//! arguments and two flags is genuinely less code than configuring a parser, and
//! in a project that asks users to trust its dependency list, a dependency
//! avoided is worth a hundred lines.
//!
//! It is also the piece most likely to be got subtly wrong, so it is separated
//! from the commands it dispatches and tested on its own.

// This is a binary crate with one module, so nothing here is reachable from
// outside; `pub` marks the module's own interface for the reader.
#![allow(
    unreachable_pub,
    reason = "the crate is a binary; pub documents intent"
)]

use std::path::PathBuf;

/// How the password reaches the program.
///
/// No interactive prompt yet: reading a password without echoing it needs
/// platform-specific terminal handling, and this tool is currently the
/// project's own test instrument rather than something a person types into.
/// The real command-line release gets a proper prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PasswordSource {
    /// From the `CRYPTOVAULT_PASSWORD` environment variable.
    #[default]
    Environment,
    /// From the first line of standard input.
    Stdin,
}

/// What the user asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Create a vault.
    Init { vault: PathBuf, sealed: bool },
    /// List a directory.
    List { vault: PathBuf, path: String },
    /// Create a directory, and any missing parents.
    MakeDir { vault: PathBuf, path: String },
    /// Copy a file from the host into the vault.
    Add {
        vault: PathBuf,
        source: PathBuf,
        destination: String,
    },
    /// Copy a file out of the vault onto the host.
    Get {
        vault: PathBuf,
        source: String,
        destination: PathBuf,
    },
    /// Remove an entry.
    Remove { vault: PathBuf, path: String },
    /// Move or rename an entry.
    Move {
        vault: PathBuf,
        from: String,
        to: String,
    },
    /// Check every file's integrity without writing any plaintext.
    Verify { vault: PathBuf },
    /// Print what can be read from a vault without unlocking it.
    Inspect { vault: PathBuf },
    /// Print usage.
    Help,
    /// Print the version.
    Version,
}

/// A parsed command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    /// What to do.
    pub command: Command,
    /// Where the password comes from.
    pub password: PasswordSource,
}

/// Why a command line was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError {
    /// What was wrong with it.
    pub message: String,
}

impl std::fmt::Display for UsageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn fail(message: impl Into<String>) -> UsageError {
    UsageError {
        message: message.into(),
    }
}

/// Parses the arguments after the program name.
///
/// # Errors
///
/// Returns a [`UsageError`] describing what was wrong, in terms of the command
/// the user actually typed rather than a generic complaint.
pub fn parse(args: &[String]) -> Result<Invocation, UsageError> {
    let mut password = PasswordSource::default();
    let mut positional: Vec<&str> = Vec::new();
    let mut sealed = false;

    for arg in args {
        match arg.as_str() {
            "--password-stdin" => password = PasswordSource::Stdin,
            "--sealed" => sealed = true,
            "-h" | "--help" => {
                return Ok(Invocation {
                    command: Command::Help,
                    password,
                });
            }
            "-V" | "--version" => {
                return Ok(Invocation {
                    command: Command::Version,
                    password,
                });
            }
            other if other.starts_with('-') => {
                return Err(fail(format!("unknown option {other:?}")));
            }
            other => positional.push(other),
        }
    }

    let Some((verb, rest)) = positional.split_first() else {
        return Ok(Invocation {
            command: Command::Help,
            password,
        });
    };

    let command = match *verb {
        "init" => Command::Init {
            vault: vault_of(rest, "init")?,
            sealed,
        },
        "ls" => Command::List {
            vault: vault_of(rest, "ls")?,
            path: rest.get(1).copied().unwrap_or("/").to_owned(),
        },
        "mkdir" => Command::MakeDir {
            vault: vault_of(rest, "mkdir")?,
            path: required(rest, 1, "mkdir <vault> <path>")?.to_owned(),
        },
        "add" => Command::Add {
            vault: vault_of(rest, "add")?,
            source: PathBuf::from(required(rest, 1, "add <vault> <file> <vault-path>")?),
            destination: required(rest, 2, "add <vault> <file> <vault-path>")?.to_owned(),
        },
        "get" => Command::Get {
            vault: vault_of(rest, "get")?,
            source: required(rest, 1, "get <vault> <vault-path> <file>")?.to_owned(),
            destination: PathBuf::from(required(rest, 2, "get <vault> <vault-path> <file>")?),
        },
        "rm" => Command::Remove {
            vault: vault_of(rest, "rm")?,
            path: required(rest, 1, "rm <vault> <path>")?.to_owned(),
        },
        "mv" => Command::Move {
            vault: vault_of(rest, "mv")?,
            from: required(rest, 1, "mv <vault> <from> <to>")?.to_owned(),
            to: required(rest, 2, "mv <vault> <from> <to>")?.to_owned(),
        },
        "verify" => Command::Verify {
            vault: vault_of(rest, "verify")?,
        },
        "inspect" => Command::Inspect {
            vault: vault_of(rest, "inspect")?,
        },
        "help" => Command::Help,
        other => return Err(fail(format!("unknown command {other:?}"))),
    };

    Ok(Invocation { command, password })
}

fn vault_of(rest: &[&str], verb: &str) -> Result<PathBuf, UsageError> {
    rest.first()
        .map(PathBuf::from)
        .ok_or_else(|| fail(format!("{verb} needs the path to a vault")))
}

fn required<'a>(rest: &[&'a str], index: usize, usage: &str) -> Result<&'a str, UsageError> {
    rest.get(index)
        .copied()
        .ok_or_else(|| fail(format!("usage: cryptovault {usage}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_args(line: &[&str]) -> Result<Invocation, UsageError> {
        let owned: Vec<String> = line.iter().map(|s| (*s).to_owned()).collect();
        parse(&owned)
    }

    #[test]
    fn no_arguments_prints_help() {
        assert_eq!(parse_args(&[]).unwrap().command, Command::Help);
    }

    #[test]
    fn help_and_version_are_recognised_in_every_spelling() {
        for arg in ["-h", "--help", "help"] {
            assert_eq!(parse_args(&[arg]).unwrap().command, Command::Help, "{arg}");
        }
        for arg in ["-V", "--version"] {
            assert_eq!(
                parse_args(&[arg]).unwrap().command,
                Command::Version,
                "{arg}"
            );
        }
    }

    #[test]
    fn init_takes_a_vault_and_an_optional_seal() {
        assert_eq!(
            parse_args(&["init", "/tmp/v"]).unwrap().command,
            Command::Init {
                vault: PathBuf::from("/tmp/v"),
                sealed: false
            }
        );
        assert_eq!(
            parse_args(&["init", "/tmp/v", "--sealed"]).unwrap().command,
            Command::Init {
                vault: PathBuf::from("/tmp/v"),
                sealed: true
            }
        );
    }

    /// Flags must work wherever they appear, because that is where people put
    /// them.
    #[test]
    fn flags_are_position_independent() {
        let before = parse_args(&["--sealed", "init", "/tmp/v"]).unwrap();
        let after = parse_args(&["init", "/tmp/v", "--sealed"]).unwrap();
        assert_eq!(before, after);
    }

    #[test]
    fn listing_defaults_to_the_root() {
        assert_eq!(
            parse_args(&["ls", "/tmp/v"]).unwrap().command,
            Command::List {
                vault: PathBuf::from("/tmp/v"),
                path: "/".into()
            }
        );
        assert_eq!(
            parse_args(&["ls", "/tmp/v", "/sub"]).unwrap().command,
            Command::List {
                vault: PathBuf::from("/tmp/v"),
                path: "/sub".into()
            }
        );
    }

    #[test]
    fn add_and_get_read_their_three_arguments_in_order() {
        assert_eq!(
            parse_args(&["add", "/tmp/v", "./local.txt", "/inside.txt"])
                .unwrap()
                .command,
            Command::Add {
                vault: PathBuf::from("/tmp/v"),
                source: PathBuf::from("./local.txt"),
                destination: "/inside.txt".into(),
            }
        );
        assert_eq!(
            parse_args(&["get", "/tmp/v", "/inside.txt", "./local.txt"])
                .unwrap()
                .command,
            Command::Get {
                vault: PathBuf::from("/tmp/v"),
                source: "/inside.txt".into(),
                destination: PathBuf::from("./local.txt"),
            }
        );
    }

    #[test]
    fn the_password_source_defaults_to_the_environment() {
        assert_eq!(
            parse_args(&["ls", "/tmp/v"]).unwrap().password,
            PasswordSource::Environment
        );
        assert_eq!(
            parse_args(&["ls", "/tmp/v", "--password-stdin"])
                .unwrap()
                .password,
            PasswordSource::Stdin
        );
    }

    /// A missing argument must say what the command expects, not merely that
    /// something was wrong.
    #[test]
    fn missing_arguments_produce_a_usage_message() {
        for line in [
            vec!["mkdir", "/tmp/v"],
            vec!["add", "/tmp/v", "only-one"],
            vec!["get", "/tmp/v"],
            vec!["mv", "/tmp/v", "from-only"],
        ] {
            let error = parse_args(&line).unwrap_err();
            assert!(
                error.message.contains("usage:") || error.message.contains("needs"),
                "{line:?} gave {error}"
            );
        }
    }

    #[test]
    fn a_command_without_a_vault_says_so() {
        for verb in ["init", "ls", "verify", "inspect"] {
            let error = parse_args(&[verb]).unwrap_err();
            assert!(error.message.contains("vault"), "{verb} gave {error}");
        }
    }

    #[test]
    fn unknown_commands_and_options_are_refused() {
        assert!(
            parse_args(&["frobnicate", "/tmp/v"])
                .unwrap_err()
                .message
                .contains("frobnicate")
        );
        assert!(
            parse_args(&["ls", "--wat"])
                .unwrap_err()
                .message
                .contains("--wat")
        );
    }

    /// A path that begins with a dash would otherwise be read as an option.
    /// Refusing is the right answer for now — silently treating it as a path
    /// would be worse than saying so.
    #[test]
    fn a_leading_dash_is_treated_as_an_option_and_refused() {
        assert!(parse_args(&["ls", "/tmp/v", "-weird"]).is_err());
    }
}
