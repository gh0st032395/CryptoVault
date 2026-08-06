//! Tests for the vault itself, against real temporary directories.
//!
//! Everything here goes through the filesystem rather than a mock. A vault is
//! defined by what it puts on disk, and the failures worth catching — a name
//! that does not round-trip, a directory that lists its own companion files, an
//! entry left behind by a remove — only exist there.

use super::*;

/// A throwaway vault. The temporary directory is removed when this drops.
struct Fixture {
    _dir: tempfile::TempDir,
    vault: Vault,
    root: DirId,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let vault = Vault::create(dir.path(), b"the password", cheap()).unwrap();
        let root = vault.root_dir();
        Self {
            _dir: dir,
            vault,
            root,
        }
    }

    fn path(&self) -> PathBuf {
        self.vault.root_path().to_path_buf()
    }

    fn reopen(&self) -> Vault {
        Vault::open(&self.path(), b"the password").unwrap()
    }
}

/// The accepted minimum cost. Every test here creates or opens a vault, and the
/// default profile is calibrated to take about a second.
fn cheap() -> CreateOptions {
    CreateOptions {
        params: Argon2Params::new(
            Argon2Params::MIN_MEMORY_KIB,
            Argon2Params::MIN_ITERATIONS,
            Argon2Params::MIN_PARALLELISM,
        )
        .unwrap(),
        ..CreateOptions::default()
    }
}

fn write_file(vault: &Vault, dir: DirId, name: &str, contents: &[u8]) {
    let mut file = vault
        .create_file(dir, name, FileMetadata::default())
        .unwrap();
    file.write_at(0, contents).unwrap();
    file.flush().unwrap();
}

fn read_file(vault: &Vault, dir: DirId, name: &str) -> Vec<u8> {
    vault
        .open_file(dir, name, false)
        .unwrap()
        .read_all()
        .unwrap()
}

// --- creating and opening --------------------------------------------------

#[test]
fn a_new_vault_is_empty_and_reopens() {
    let fixture = Fixture::new();
    assert!(fixture.vault.read_dir(fixture.root).unwrap().is_empty());
    assert!(Vault::exists_at(&fixture.path()));

    let reopened = fixture.reopen();
    assert_eq!(reopened.root_dir(), fixture.root);
    assert!(reopened.read_dir(reopened.root_dir()).unwrap().is_empty());
}

#[test]
fn the_wrong_password_does_not_open_a_vault() {
    let fixture = Fixture::new();
    let error = Vault::open(&fixture.path(), b"wrong").unwrap_err();
    assert!(error.is_wrong_credential(), "reported as {error}");
}

/// "Wrong password" must be distinguishable from every other failure, however
/// deep the error was wrapped, or a caller will eventually tell someone their
/// vault is corrupt when they merely mistyped.
#[test]
fn other_failures_are_not_mistaken_for_a_wrong_password() {
    let dir = tempfile::tempdir().unwrap();
    let error = Vault::open(dir.path(), b"pw").unwrap_err();
    assert!(
        !error.is_wrong_credential(),
        "a missing vault read as a wrong password"
    );
}

#[test]
fn opening_something_that_is_not_a_vault_says_so() {
    let dir = tempfile::tempdir().unwrap();
    assert!(!Vault::exists_at(dir.path()));
    assert!(matches!(
        Vault::open(dir.path(), b"pw"),
        Err(VaultError::NotAVault { .. })
    ));
}

/// Creating over an existing vault would make its contents permanently
/// unreadable, so it is refused rather than confirmed.
#[test]
fn creating_over_an_existing_vault_is_refused() {
    let fixture = Fixture::new();
    assert!(matches!(
        Vault::create(&fixture.path(), b"another password", cheap()),
        Err(VaultError::VaultExists { .. })
    ));
}

#[test]
fn two_vaults_do_not_share_an_identifier() {
    assert_ne!(Fixture::new().root, Fixture::new().root);
}

// --- files -----------------------------------------------------------------

#[test]
fn a_file_round_trips_through_the_vault() {
    let fixture = Fixture::new();
    write_file(&fixture.vault, fixture.root, "notes.txt", b"the contents");

    assert_eq!(
        read_file(&fixture.vault, fixture.root, "notes.txt"),
        b"the contents"
    );
    assert_eq!(
        fixture.vault.read_dir(fixture.root).unwrap(),
        vec![DirEntry {
            name: "notes.txt".into(),
            kind: EntryKind::File
        }]
    );
}

#[test]
fn a_file_survives_locking_and_unlocking() {
    let fixture = Fixture::new();
    write_file(&fixture.vault, fixture.root, "notes.txt", b"persisted");

    // Dropping the vault is locking it.
    let reopened = fixture.reopen();
    assert_eq!(
        read_file(&reopened, reopened.root_dir(), "notes.txt"),
        b"persisted"
    );
}

#[test]
fn a_large_file_round_trips() {
    let fixture = Fixture::new();
    let data: Vec<u8> = (0..200_000)
        .map(|i| u8::try_from(i % 251).unwrap_or(0))
        .collect();

    write_file(&fixture.vault, fixture.root, "big.bin", &data);

    assert_eq!(read_file(&fixture.vault, fixture.root, "big.bin"), data);
    assert_eq!(
        fixture.vault.stat(fixture.root, "big.bin").unwrap().size,
        200_000
    );
}

#[test]
fn creating_a_file_that_exists_is_refused() {
    let fixture = Fixture::new();
    write_file(&fixture.vault, fixture.root, "notes.txt", b"first");

    assert!(matches!(
        fixture
            .vault
            .create_file(fixture.root, "notes.txt", FileMetadata::default()),
        Err(VaultError::AlreadyExists { .. })
    ));
    // …and the original is untouched.
    assert_eq!(
        read_file(&fixture.vault, fixture.root, "notes.txt"),
        b"first"
    );
}

#[test]
fn opening_a_missing_file_says_so() {
    let fixture = Fixture::new();
    assert!(matches!(
        fixture.vault.open_file(fixture.root, "nothing.txt", false),
        Err(VaultError::NotFound { .. })
    ));
}

#[test]
fn stat_reports_size_and_metadata() {
    let fixture = Fixture::new();
    let metadata = FileMetadata {
        mtime: Some(1_770_000_000),
        tags: vec!["work".into()],
        ..Default::default()
    };

    let mut file = fixture
        .vault
        .create_file(fixture.root, "f.txt", metadata)
        .unwrap();
    file.write_at(0, b"1234567890").unwrap();
    file.flush().unwrap();

    let stat = fixture.vault.stat(fixture.root, "f.txt").unwrap();
    assert_eq!(stat.kind, EntryKind::File);
    assert_eq!(stat.size, 10);
    assert_eq!(stat.metadata.mtime, Some(1_770_000_000));
    assert_eq!(stat.metadata.tags, ["work"]);
}

// --- directories -----------------------------------------------------------

#[test]
fn directories_nest() {
    let fixture = Fixture::new();
    let documents = fixture.vault.create_dir(fixture.root, "Documents").unwrap();
    let year = fixture.vault.create_dir(documents, "2026").unwrap();

    write_file(&fixture.vault, year, "invoice.pdf", b"an invoice");

    assert_eq!(
        fixture.vault.read_dir(fixture.root).unwrap(),
        vec![DirEntry {
            name: "Documents".into(),
            kind: EntryKind::Directory
        }]
    );
    assert_eq!(
        read_file(&fixture.vault, year, "invoice.pdf"),
        b"an invoice"
    );

    // …and the whole path resolves again after reopening.
    let reopened = fixture.reopen();
    let documents = reopened
        .dir_id_of(reopened.root_dir(), "Documents")
        .unwrap();
    let year = reopened.dir_id_of(documents, "2026").unwrap();
    assert_eq!(read_file(&reopened, year, "invoice.pdf"), b"an invoice");
}

#[test]
fn a_new_directory_is_empty() {
    let fixture = Fixture::new();
    let child = fixture.vault.create_dir(fixture.root, "empty").unwrap();
    assert!(fixture.vault.read_dir(child).unwrap().is_empty());
}

#[test]
fn a_file_and_a_directory_cannot_share_a_name() {
    let fixture = Fixture::new();
    fixture.vault.create_dir(fixture.root, "thing").unwrap();

    assert!(matches!(
        fixture
            .vault
            .create_file(fixture.root, "thing", FileMetadata::default()),
        Err(VaultError::AlreadyExists { .. })
    ));
}

#[test]
fn asking_for_a_file_as_a_directory_is_refused() {
    let fixture = Fixture::new();
    write_file(&fixture.vault, fixture.root, "notes.txt", b"x");

    assert!(matches!(
        fixture.vault.dir_id_of(fixture.root, "notes.txt"),
        Err(VaultError::WrongKind { .. })
    ));
    assert!(matches!(
        fixture
            .vault
            .open_file(fixture.root, "notes.txt", false)
            .map(|_| ()),
        Ok(())
    ));
}

/// The same name in two directories must be a different file, or the whole
/// directory structure would be an illusion.
#[test]
fn the_same_name_in_two_directories_is_two_files() {
    let fixture = Fixture::new();
    let a = fixture.vault.create_dir(fixture.root, "a").unwrap();
    let b = fixture.vault.create_dir(fixture.root, "b").unwrap();

    write_file(&fixture.vault, a, "same.txt", b"in a");
    write_file(&fixture.vault, b, "same.txt", b"in b");

    assert_eq!(read_file(&fixture.vault, a, "same.txt"), b"in a");
    assert_eq!(read_file(&fixture.vault, b, "same.txt"), b"in b");
}

// --- removing and renaming -------------------------------------------------

#[test]
fn removing_a_file_removes_it() {
    let fixture = Fixture::new();
    write_file(&fixture.vault, fixture.root, "notes.txt", b"x");

    fixture.vault.remove(fixture.root, "notes.txt").unwrap();

    assert!(fixture.vault.read_dir(fixture.root).unwrap().is_empty());
    assert!(matches!(
        fixture.vault.remove(fixture.root, "notes.txt"),
        Err(VaultError::NotFound { .. })
    ));
}

/// Removing a populated directory would leave its contents on disk with nothing
/// pointing at them — space leaked, and file count leaked with it.
#[test]
fn removing_a_populated_directory_is_refused() {
    let fixture = Fixture::new();
    let child = fixture.vault.create_dir(fixture.root, "full").unwrap();
    write_file(&fixture.vault, child, "inside.txt", b"x");

    assert!(matches!(
        fixture.vault.remove(fixture.root, "full"),
        Err(VaultError::NotEmpty { .. })
    ));

    fixture.vault.remove(child, "inside.txt").unwrap();
    fixture.vault.remove(fixture.root, "full").unwrap();
    assert!(fixture.vault.read_dir(fixture.root).unwrap().is_empty());
}

#[test]
fn renaming_a_file_keeps_its_contents() {
    let fixture = Fixture::new();
    write_file(&fixture.vault, fixture.root, "before.txt", b"unchanged");

    fixture
        .vault
        .rename(fixture.root, "before.txt", fixture.root, "after.txt")
        .unwrap();

    assert_eq!(
        read_file(&fixture.vault, fixture.root, "after.txt"),
        b"unchanged"
    );
    assert!(
        fixture
            .vault
            .lookup(fixture.root, "before.txt")
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_file_can_be_moved_between_directories() {
    let fixture = Fixture::new();
    let target = fixture.vault.create_dir(fixture.root, "target").unwrap();
    write_file(&fixture.vault, fixture.root, "moving.txt", b"contents");

    fixture
        .vault
        .rename(fixture.root, "moving.txt", target, "moved.txt")
        .unwrap();

    assert!(
        fixture
            .vault
            .lookup(fixture.root, "moving.txt")
            .unwrap()
            .is_none()
    );
    assert_eq!(read_file(&fixture.vault, target, "moved.txt"), b"contents");
}

/// The claim the flat layout is built on: renaming a directory rewrites one
/// file, whatever is inside it, because its location comes from an identifier.
#[test]
fn renaming_a_directory_does_not_disturb_its_contents() {
    let fixture = Fixture::new();
    let child = fixture.vault.create_dir(fixture.root, "before").unwrap();
    for i in 0..20 {
        write_file(
            &fixture.vault,
            child,
            &format!("file{i}.txt"),
            format!("body {i}").as_bytes(),
        );
    }

    fixture
        .vault
        .rename(fixture.root, "before", fixture.root, "after")
        .unwrap();

    let renamed = fixture.vault.dir_id_of(fixture.root, "after").unwrap();
    assert_eq!(renamed, child, "the directory identifier changed");
    assert_eq!(fixture.vault.read_dir(renamed).unwrap().len(), 20);
    assert_eq!(read_file(&fixture.vault, renamed, "file7.txt"), b"body 7");
}

#[test]
fn renaming_onto_an_existing_name_is_refused() {
    let fixture = Fixture::new();
    write_file(&fixture.vault, fixture.root, "a.txt", b"a");
    write_file(&fixture.vault, fixture.root, "b.txt", b"b");

    assert!(matches!(
        fixture
            .vault
            .rename(fixture.root, "a.txt", fixture.root, "b.txt"),
        Err(VaultError::AlreadyExists { .. })
    ));
    assert_eq!(read_file(&fixture.vault, fixture.root, "a.txt"), b"a");
    assert_eq!(read_file(&fixture.vault, fixture.root, "b.txt"), b"b");
}

// --- names -----------------------------------------------------------------

/// The feature that falls out of encrypting names: a vault is not bound by the
/// host filesystem's rules, on any platform.
#[test]
fn names_the_host_filesystem_would_refuse_work_in_a_vault() {
    let fixture = Fixture::new();
    let awkward = [
        "CON",
        "NUL",
        "report: Q1*.txt",
        "why?.md",
        "trailing space ",
        "trailing dot.",
        "emoji 🔐 name",
        "ファイル.txt",
    ];

    for name in awkward {
        write_file(&fixture.vault, fixture.root, name, name.as_bytes());
    }

    let listed: Vec<String> = fixture
        .vault
        .read_dir(fixture.root)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    for name in awkward {
        assert!(
            listed.contains(&name.to_owned()),
            "{name:?} did not come back"
        );
        assert_eq!(
            read_file(&fixture.vault, fixture.root, name),
            name.as_bytes()
        );
    }
}

/// A long name spills into a companion file. That companion must not appear as
/// an entry of its own, and the name must still come back whole.
#[test]
fn a_very_long_name_round_trips_without_showing_its_companion() {
    let fixture = Fixture::new();
    let long = "a-rather-long-name-".repeat(20);

    write_file(&fixture.vault, fixture.root, &long, b"contents");

    let listing = fixture.vault.read_dir(fixture.root).unwrap();
    assert_eq!(
        listing.len(),
        1,
        "the companion was listed as an entry: {listing:?}"
    );
    assert_eq!(listing[0].name, long);
    assert_eq!(read_file(&fixture.vault, fixture.root, &long), b"contents");
}

#[test]
fn removing_a_long_named_file_removes_its_companion_too() {
    let fixture = Fixture::new();
    let long = "another-long-name-".repeat(20);
    write_file(&fixture.vault, fixture.root, &long, b"x");

    fixture.vault.remove(fixture.root, &long).unwrap();

    let dir_path = fixture.vault.dir_disk_path(fixture.root);
    let leftovers: Vec<String> = fs::read_dir(&dir_path)
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert!(leftovers.is_empty(), "left behind: {leftovers:?}");
}

// --- what reaches the disk -------------------------------------------------

/// The point of the whole exercise. Nothing the user typed may be readable in
/// the vault directory.
#[test]
fn neither_names_nor_contents_are_readable_on_disk() {
    let fixture = Fixture::new();
    let child = fixture
        .vault
        .create_dir(fixture.root, "SECRETFOLDER")
        .unwrap();
    write_file(&fixture.vault, child, "SECRETNAME.txt", b"SECRETCONTENTS");

    let mut found = Vec::new();
    walk(&fixture.path(), &mut found);

    for (path, bytes) in &found {
        let name = path.to_string_lossy();
        for needle in ["SECRETFOLDER", "SECRETNAME", "SECRETCONTENTS"] {
            assert!(
                !name.contains(needle),
                "{needle} appears in the path {name}"
            );
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{needle} appears inside {name}"
            );
        }
    }

    assert!(
        found.len() > 2,
        "the walk found almost nothing: {}",
        found.len()
    );
}

/// Every directory sits at the same depth below `d/`, so how deeply the user
/// nests their folders is not visible.
#[test]
fn nesting_depth_is_not_visible_on_disk() {
    let fixture = Fixture::new();
    let mut dir = fixture.root;
    for level in 0..6 {
        dir = fixture
            .vault
            .create_dir(dir, &format!("level{level}"))
            .unwrap();
    }
    write_file(&fixture.vault, dir, "deep.txt", b"x");

    let content_root = fixture.path().join("d");
    let depths: Vec<usize> = fs::read_dir(&content_root)
        .unwrap()
        .filter_map(Result::ok)
        .flat_map(|shard| fs::read_dir(shard.path()).unwrap().filter_map(Result::ok))
        .map(|dir| dir.path().components().count())
        .collect();

    assert!(
        depths.len() >= 7,
        "expected a directory per level, found {}",
        depths.len()
    );
    assert!(
        depths.windows(2).all(|w| w[0] == w[1]),
        "directories are at differing depths: {depths:?}"
    );
}

// --- scale -----------------------------------------------------------------

/// A directory with many entries. Not a benchmark — it is here because the
/// sharding, the listing and the name encoding all have to keep working when a
/// directory stops being small, and "many files in one folder" is the shape
/// that breaks naive designs.
///
/// Five hundred rather than fifty thousand: enough to exercise the sharding and
/// the listing path, fast enough that nobody starts skipping the test suite.
/// The full scale benchmarks, with thresholds in CI, are their own piece of work.
#[test]
fn a_directory_with_many_entries_still_works() {
    let fixture = Fixture::new();
    let count = 500;

    for i in 0..count {
        write_file(
            &fixture.vault,
            fixture.root,
            &format!("file-{i:04}.txt"),
            format!("contents of {i}").as_bytes(),
        );
    }

    let listing = fixture.vault.read_dir(fixture.root).unwrap();
    assert_eq!(listing.len(), count);
    assert_eq!(listing[0].name, "file-0000.txt");
    assert_eq!(listing[count - 1].name, "file-0499.txt");

    // Lookups stay direct: no scan is needed to find one of five hundred.
    assert_eq!(
        read_file(&fixture.vault, fixture.root, "file-0250.txt"),
        b"contents of 250"
    );
}

/// Many directories must spread across the shards rather than piling into one,
/// which is the whole reason the shard exists.
#[test]
fn many_directories_spread_across_the_shards() {
    let fixture = Fixture::new();
    for i in 0..200 {
        fixture
            .vault
            .create_dir(fixture.root, &format!("dir-{i:03}"))
            .unwrap();
    }

    let shards = fs::read_dir(fixture.path().join("d")).unwrap().count();
    assert!(
        shards > 100,
        "200 directories landed in only {shards} shards"
    );
}

fn walk(path: &Path, found: &mut Vec<(PathBuf, Vec<u8>)>) {
    let Ok(listing) = fs::read_dir(path) else {
        return;
    };
    for entry in listing.filter_map(Result::ok) {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, found);
        } else if let Ok(bytes) = fs::read(&path) {
            found.push((path, bytes));
        }
    }
}
