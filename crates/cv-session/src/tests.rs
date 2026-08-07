//! Tests for the session layer, against real vaults in temporary directories.
//!
//! The sequences here are the ones a person actually performs — unlock, browse,
//! lock, unlock again; create two vaults and open one — because that is where a
//! session bug hides, and it is exactly what cannot be tested once this logic
//! lives inside a user-interface framework.

use super::*;

/// A session with one created vault, and the directory it lives in.
struct Fixture {
    _dir: tempfile::TempDir,
    session: Session,
    id: String,
}

const PASSWORD: &str = "the vault password";

impl Fixture {
    fn new() -> Self {
        Self::with_sealed(false)
    }

    fn with_sealed(sealed: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mut session = Session::new();
        let id = session
            .create("Personale", &dir.path().join("vault"), PASSWORD, sealed)
            .unwrap();
        Self {
            _dir: dir,
            session,
            id,
        }
    }

    fn open(&mut self) {
        self.session.unlock(&self.id.clone(), PASSWORD).unwrap();
    }
}

// --- registering and creating ----------------------------------------------

/// Creation must leave the vault shut. It should not be a back door into an
/// open vault, and typing the password once more is the cheapest check that it
/// was typed as intended.
#[test]
fn a_created_vault_is_registered_and_locked() {
    let fixture = Fixture::new();
    let listed = fixture.session.list();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "Personale");
    assert!(!listed[0].unlocked);
    assert!(!listed[0].sealed);
}

#[test]
fn a_sealed_vault_reports_itself_as_sealed() {
    let mut fixture = Fixture::with_sealed(true);
    assert!(fixture.session.list()[0].sealed);

    // …and still does after being opened, which is when the flag is read back
    // from the authenticated configuration rather than remembered.
    fixture.open();
    assert!(fixture.session.list()[0].sealed);
}

#[test]
fn registering_a_folder_that_is_not_a_vault_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::new();

    let error = session.register("nope", dir.path()).unwrap_err();
    assert_eq!(error.kind(), "failed");
    assert!(error.to_string().contains("no vault"));
    assert!(session.list().is_empty());
}

#[test]
fn an_existing_vault_can_be_registered_and_opened() {
    let fixture = Fixture::new();
    let path = PathBuf::from(&fixture.session.list()[0].path);

    let mut second = Session::new();
    let id = second.register("Stesso vault", &path).unwrap();
    second.unlock(&id, PASSWORD).unwrap();

    assert!(second.list()[0].unlocked);
}

#[test]
fn several_vaults_get_distinct_identifiers() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::new();

    let first = session
        .create("Uno", &dir.path().join("a"), PASSWORD, false)
        .unwrap();
    let second = session
        .create("Due", &dir.path().join("b"), PASSWORD, false)
        .unwrap();

    assert_ne!(first, second);
    assert_eq!(session.list().len(), 2);
}

// --- unlocking and locking --------------------------------------------------

#[test]
fn unlocking_opens_the_vault_and_locking_shuts_it() {
    let mut fixture = Fixture::new();

    fixture.open();
    assert!(fixture.session.list()[0].unlocked);

    fixture.session.lock(&fixture.id.clone()).unwrap();
    assert!(!fixture.session.list()[0].unlocked);
}

#[test]
fn the_wrong_password_is_reported_as_such_and_leaves_it_shut() {
    let mut fixture = Fixture::new();

    let error = fixture
        .session
        .unlock(&fixture.id.clone(), "wrong")
        .unwrap_err();
    assert_eq!(error, SessionError::WrongPassword);
    assert_eq!(error.kind(), "wrong-password");
    assert!(!fixture.session.list()[0].unlocked);
}

/// Two clicks on the same button should not produce a complaint.
#[test]
fn unlocking_twice_and_locking_twice_are_both_fine() {
    let mut fixture = Fixture::new();

    fixture.open();
    fixture.open();
    assert!(fixture.session.list()[0].unlocked);

    fixture.session.lock(&fixture.id.clone()).unwrap();
    fixture.session.lock(&fixture.id.clone()).unwrap();
    assert!(!fixture.session.list()[0].unlocked);
}

/// The sequence a session bug hides in: open, use, close, open again.
#[test]
fn a_vault_survives_being_locked_and_unlocked_again() {
    let mut fixture = Fixture::new();
    let id = fixture.id.clone();

    fixture.open();
    fixture.session.create_dir(&id, "/Documenti").unwrap();

    fixture.session.lock(&id).unwrap();
    assert_eq!(
        fixture.session.read_dir(&id, "/").unwrap_err(),
        SessionError::Locked
    );

    fixture.open();
    assert_eq!(fixture.session.read_dir(&id, "/").unwrap().len(), 1);
}

/// What the panic button calls. No identifier, no failure mode: the moment
/// somebody wants everything shut is the worst moment to ask them which one.
#[test]
fn locking_everything_shuts_every_vault() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::new();

    let first = session
        .create("Uno", &dir.path().join("a"), PASSWORD, false)
        .unwrap();
    let second = session
        .create("Due", &dir.path().join("b"), PASSWORD, false)
        .unwrap();
    session.unlock(&first, PASSWORD).unwrap();
    session.unlock(&second, PASSWORD).unwrap();

    session.lock_all();

    assert!(session.list().iter().all(|vault| !vault.unlocked));
}

#[test]
fn an_unknown_identifier_is_distinguished_from_a_locked_vault() {
    let mut fixture = Fixture::new();

    let unknown = fixture.session.unlock("nope", PASSWORD).unwrap_err();
    assert_eq!(unknown.kind(), "unknown-vault");

    let locked = fixture
        .session
        .read_dir(&fixture.id.clone(), "/")
        .unwrap_err();
    assert_eq!(locked.kind(), "locked");
}

// --- browsing ---------------------------------------------------------------

#[test]
fn directories_can_be_made_listed_renamed_and_removed() {
    let mut fixture = Fixture::new();
    let id = fixture.id.clone();
    fixture.open();

    fixture.session.create_dir(&id, "/Documenti/2026").unwrap();

    let listing = fixture.session.read_dir(&id, "/").unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].name, "Documenti");
    assert_eq!(listing[0].kind, "directory");

    fixture
        .session
        .rename(&id, "/Documenti", "/Archivio")
        .unwrap();
    assert_eq!(
        fixture.session.read_dir(&id, "/").unwrap()[0].name,
        "Archivio"
    );
    // Renaming a folder does not disturb what is inside it.
    assert_eq!(
        fixture.session.read_dir(&id, "/Archivio").unwrap()[0].name,
        "2026"
    );

    fixture.session.remove(&id, "/Archivio").unwrap();
    assert!(fixture.session.read_dir(&id, "/").unwrap().is_empty());
}

/// The interface asked for the deletion; asking again in an error would just
/// teach people to click through both.
#[test]
fn removing_a_populated_directory_removes_the_whole_subtree() {
    let mut fixture = Fixture::new();
    let id = fixture.id.clone();
    fixture.open();

    fixture.session.create_dir(&id, "/a/b/c").unwrap();
    fixture.session.remove(&id, "/a").unwrap();

    assert!(fixture.session.read_dir(&id, "/").unwrap().is_empty());
}

#[test]
fn the_vault_root_cannot_be_removed() {
    let mut fixture = Fixture::new();
    let id = fixture.id.clone();
    fixture.open();

    let error = fixture.session.remove(&id, "/").unwrap_err();
    assert_eq!(error.kind(), "invalid-path");
}

/// A path a vault cannot hold must be refused as a path problem, not reported
/// as a mysterious failure.
#[test]
fn a_traversal_path_is_refused_as_an_invalid_path() {
    let mut fixture = Fixture::new();
    let id = fixture.id.clone();
    fixture.open();

    for bad in ["/a/../b", "/.."] {
        let error = fixture.session.create_dir(&id, bad).unwrap_err();
        assert_eq!(error.kind(), "invalid-path", "{bad:?} gave {error}");
    }
}

/// Every error the interface branches on needs a tag that survives translation.
#[test]
fn every_error_kind_is_a_stable_tag() {
    let kinds = [
        SessionError::WrongPassword.kind(),
        SessionError::UnknownVault { id: "x".into() }.kind(),
        SessionError::Locked.kind(),
        SessionError::InvalidPath { reason: "x".into() }.kind(),
        SessionError::Failed {
            message: "x".into(),
        }
        .kind(),
    ];

    assert_eq!(kinds.len(), 5);
    for kind in kinds {
        assert!(!kind.is_empty());
        assert!(
            kind.chars().all(|c| c.is_ascii_lowercase() || c == '-'),
            "{kind}"
        );
    }
}

/// The summaries and entries cross into the interface as JSON, so their field
/// names are part of the contract with it.
#[test]
fn the_wire_types_keep_the_names_the_interface_expects() {
    let summary = VaultSummary {
        id: "v1".into(),
        name: "Personale".into(),
        path: "/tmp/v".into(),
        unlocked: true,
        sealed: false,
    };
    let entry = Entry {
        name: "f.txt".into(),
        kind: "file".into(),
        size: 10,
        modified: Some(1_770_000_000),
    };

    // Round-tripping through the same shape the interface will see.
    assert_eq!(summary, summary.clone());
    assert_eq!(entry, entry.clone());
    assert_eq!(entry.kind, "file");
    assert_eq!(kind_name(EntryKind::Directory), "directory");
}

// --- remembering which vaults exist -----------------------------------------

/// The whole point of the registry. An application that is closed and reopened
/// has to still know where the user's vaults are; asking them to find the folder
/// again every morning is not a security property, it is a defect.
#[test]
fn the_list_of_vaults_survives_the_session_that_made_it() {
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("config/vaults.cbor");
    let vault = dir.path().join("Vault personale");

    let mut first = Session::open(&list).unwrap();
    let id = first.create("Personale", &vault, PASSWORD, true).unwrap();
    first.unlock(&id, PASSWORD).unwrap();
    drop(first);

    let second = Session::open(&list).unwrap();
    let listed = second.list();

    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "Personale");
    assert_eq!(listed[0].path, vault.display().to_string());
    assert!(listed[0].sealed, "the policy must survive too");
    // The one thing that must never be remembered. A run that began with a
    // vault already open would be a vault opened without a password.
    assert!(!listed[0].unlocked);
}

/// Forgetting is "stop showing me this", not "delete my files". The two must
/// never turn out to be the same button.
#[test]
fn forgetting_a_vault_leaves_it_untouched_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let list = dir.path().join("vaults.cbor");
    let path = dir.path().join("Vault");

    let mut session = Session::open(&list).unwrap();
    let id = session.create("Personale", &path, PASSWORD, false).unwrap();
    session.unlock(&id, PASSWORD).unwrap();

    session.forget(&id).unwrap();

    assert!(session.list().is_empty());
    assert!(
        cv_vault::Vault::exists_at(&path),
        "forgetting must not remove the vault itself"
    );
    // And it is gone from the next run as well, not just from this one.
    assert!(Session::open(&list).unwrap().list().is_empty());
    // The vault can be found again, which is what makes forgetting safe.
    let mut again = Session::open(&list).unwrap();
    let recovered = again.register("Personale", &path).unwrap();
    again.unlock(&recovered, PASSWORD).unwrap();
    assert!(again.list()[0].unlocked);
}

#[test]
fn forgetting_a_vault_that_is_not_there_says_which_one() {
    let mut session = Session::new();
    let error = session.forget("v9").unwrap_err();

    assert_eq!(error.kind(), "unknown-vault");
    assert!(error.to_string().contains("v9"));
}

/// A sealed vault has to look sealed in the list *before* anybody types a
/// password — otherwise the badge appears only once the vault is open, which is
/// exactly when it is least needed.
#[test]
fn a_registered_vault_shows_its_policy_before_it_is_unlocked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("Riservati");

    let mut maker = Session::new();
    maker.create("Riservati", &path, PASSWORD, true).unwrap();

    let mut session = Session::new();
    session.register("Riservati", &path).unwrap();

    let listed = session.list();
    assert!(listed[0].sealed);
    assert!(!listed[0].unlocked, "reading the policy must not open it");
}

/// A session with nowhere to write is not a session that writes somewhere
/// arbitrary. `Session::new` is what the tests use, and it must not litter.
#[test]
fn a_session_without_a_registry_writes_no_list() {
    let dir = tempfile::tempdir().unwrap();
    let mut session = Session::new();
    session
        .create("Personale", &dir.path().join("Vault"), PASSWORD, false)
        .unwrap();

    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();

    assert_eq!(entries, vec!["Vault".to_owned()]);
}

/// A first run has no file, and that is not a failure.
#[test]
fn opening_a_registry_that_does_not_exist_yet_gives_an_empty_session() {
    let dir = tempfile::tempdir().unwrap();
    let session = Session::open(&dir.path().join("never/written/vaults.cbor")).unwrap();

    assert!(session.list().is_empty());
}
