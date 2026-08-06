//! Paths *inside* a vault.
//!
//! A [`VPath`] is a validated, absolute, already-normalised path in the vault's
//! own namespace, such as `/Documents/2026/invoice.pdf`. It is deliberately a
//! different type from [`std::path::Path`]: a vault path never reaches the host
//! filesystem, and confusing the two is precisely the mistake that turns a
//! filename into a directory traversal.
//!
//! # Why traversal is impossible here
//!
//! Two independent defences, because one is never enough for this class of bug:
//!
//! 1. A decrypted name is **never** concatenated onto a host path. The location
//!    of a directory on disk is derived from the HMAC of its identifier, so even
//!    a name that literally reads `../../etc/passwd` would address nothing.
//! 2. Parsing rejects `.`, `..`, separators and NUL outright, so such a name
//!    cannot enter the vault in the first place.
//!
//! # A pleasant side effect of encrypting names
//!
//! Because what lands on disk is base64url of a ciphertext, the host
//! filesystem's naming rules do not apply to the user's names. Characters
//! Windows forbids (`:`, `*`, `?`, `"`, `<`, `>`, `|`), reserved device names
//! like `CON` and `NUL`, trailing dots and trailing spaces are all perfectly
//! storable in a vault, on every platform. The only rules are the ones below,
//! and they exist for the vault's own consistency rather than to appease an
//! operating system.

use crate::VfsError;
use std::fmt;

/// Maximum length of one cleartext path component, in bytes.
///
/// The limit is about the encrypted form, not this one: a name is padded and
/// encrypted before being base64url-encoded, and the result has to stay inside
/// a filesystem path component. Names longer than this are legal in the vault
/// but spill into a companion file, which costs an extra read.
pub const MAX_COMPONENT_LEN: usize = 255;

/// An absolute, validated path inside a vault.
///
/// The root is the empty component list. Values of this type are always valid:
/// there is no way to construct one that is not, so code downstream never has to
/// re-check.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct VPath {
    components: Vec<String>,
}

impl VPath {
    /// The vault root, `/`.
    #[must_use]
    pub fn root() -> Self {
        Self {
            components: Vec::new(),
        }
    }

    /// Parses and validates a vault path.
    ///
    /// Leading, trailing and repeated separators are ignored, so `/a/b`, `a/b`
    /// and `//a//b//` all denote the same path. Only `/` separates: a backslash
    /// is an ordinary character in a name, because on a Mac it legitimately can
    /// be part of one.
    ///
    /// # Errors
    ///
    /// Returns [`VfsError::InvalidComponent`] for `.`, `..`, an embedded NUL or
    /// an embedded separator, and [`VfsError::ComponentTooLong`] for a component
    /// over [`MAX_COMPONENT_LEN`] bytes.
    pub fn parse(input: &str) -> Result<Self, VfsError> {
        let mut components = Vec::new();
        for raw in input.split('/') {
            if raw.is_empty() {
                continue; // collapses "//" and ignores leading/trailing slashes
            }
            components.push(validate_component(raw)?.to_owned());
        }
        Ok(Self { components })
    }

    /// Whether this path is the vault root.
    #[must_use]
    pub fn is_root(&self) -> bool {
        self.components.is_empty()
    }

    /// The path components, from the root downwards.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// How deep the path is; the root has depth zero.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.components.len()
    }

    /// The final component, or [`None`] at the root.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        self.components.last().map(String::as_str)
    }

    /// The containing directory, or [`None`] at the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let mut components = self.components.clone();
        components.pop();
        Some(Self { components })
    }

    /// Appends one component.
    ///
    /// # Errors
    ///
    /// Same conditions as [`VPath::parse`], applied to `name`. A `name` that
    /// contains a separator is rejected rather than split, because a caller
    /// asking to append a single component and silently getting two is how
    /// confused-deputy bugs start.
    pub fn join(&self, name: &str) -> Result<Self, VfsError> {
        let validated = validate_component(name)?;
        let mut components = self.components.clone();
        components.push(validated.to_owned());
        Ok(Self { components })
    }

    /// Whether `self` is `other` or lies underneath it.
    ///
    /// Used to refuse operations such as moving a directory into its own
    /// subtree.
    #[must_use]
    pub fn starts_with(&self, other: &Self) -> bool {
        other.components.len() <= self.components.len()
            && self.components[..other.components.len()] == other.components[..]
    }
}

impl fmt::Display for VPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_root() {
            return f.write_str("/");
        }
        for component in &self.components {
            write!(f, "/{component}")?;
        }
        Ok(())
    }
}

/// Validates a single path component, returning it unchanged when acceptable.
fn validate_component(component: &str) -> Result<&str, VfsError> {
    let reject = |reason: &'static str| VfsError::InvalidComponent {
        component: component.to_owned(),
        reason,
    };

    if component.is_empty() {
        return Err(reject("a component cannot be empty"));
    }
    if component == "." || component == ".." {
        return Err(reject(
            "relative components are not allowed in a vault path",
        ));
    }
    if component.contains('/') {
        return Err(reject("a component cannot contain a path separator"));
    }
    if component.contains('\0') {
        return Err(reject("a component cannot contain a NUL byte"));
    }
    if component.len() > MAX_COMPONENT_LEN {
        return Err(VfsError::ComponentTooLong {
            len: component.len(),
            max: MAX_COMPONENT_LEN,
        });
    }
    Ok(component)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_is_the_empty_path() {
        let root = VPath::root();
        assert!(root.is_root());
        assert_eq!(root.depth(), 0);
        assert_eq!(root.to_string(), "/");
        assert_eq!(root.file_name(), None);
        assert_eq!(root.parent(), None);
    }

    #[test]
    fn parsing_is_insensitive_to_redundant_separators() {
        let expected = VPath::parse("/a/b").unwrap();
        for input in ["a/b", "/a/b", "a/b/", "//a//b//", "/a/b/"] {
            assert_eq!(
                VPath::parse(input).unwrap(),
                expected,
                "failed for {input:?}"
            );
        }
        assert_eq!(expected.to_string(), "/a/b");
    }

    #[test]
    fn an_empty_string_parses_to_the_root() {
        assert!(VPath::parse("").unwrap().is_root());
        assert!(VPath::parse("/").unwrap().is_root());
    }

    #[test]
    fn components_are_reported_in_order() {
        let p = VPath::parse("/Documents/2026/invoice.pdf").unwrap();
        assert_eq!(p.components(), ["Documents", "2026", "invoice.pdf"]);
        assert_eq!(p.depth(), 3);
        assert_eq!(p.file_name(), Some("invoice.pdf"));
        assert_eq!(p.parent().unwrap().to_string(), "/Documents/2026");
    }

    #[test]
    fn traversal_components_are_refused() {
        for input in ["..", "/..", "a/../b", "./a", "/a/./b", "/a/.."] {
            assert!(
                VPath::parse(input).is_err(),
                "{input:?} should have been rejected"
            );
        }
    }

    #[test]
    fn a_nul_byte_is_refused() {
        assert!(VPath::parse("a\0b").is_err());
    }

    #[test]
    fn join_refuses_a_name_containing_a_separator() {
        let base = VPath::parse("/a").unwrap();
        assert!(base.join("b/c").is_err());
        assert!(base.join("..").is_err());
        assert!(base.join("").is_err());
    }

    #[test]
    fn join_appends_exactly_one_component() {
        let p = VPath::root().join("a").unwrap().join("b").unwrap();
        assert_eq!(p.to_string(), "/a/b");
        assert_eq!(p.depth(), 2);
    }

    #[test]
    fn component_length_is_bounded() {
        let ok = "x".repeat(MAX_COMPONENT_LEN);
        assert!(VPath::root().join(&ok).is_ok());

        let too_long = "x".repeat(MAX_COMPONENT_LEN + 1);
        assert_eq!(
            VPath::root().join(&too_long),
            Err(VfsError::ComponentTooLong {
                len: MAX_COMPONENT_LEN + 1,
                max: MAX_COMPONENT_LEN
            })
        );
    }

    /// Encrypted names free the vault from the host filesystem's rules. These
    /// all have to work, on every platform, including Windows.
    #[test]
    fn names_forbidden_by_the_host_filesystem_are_fine_in_a_vault() {
        for name in [
            "CON",
            "NUL",
            "COM1",
            "LPT1", // reserved on Windows
            "report: Q1*.txt",
            "a<b>c",
            "why?.md", // forbidden characters
            "trailing space ",
            "trailing dot.", // awkward endings
            "back\\slash",   // a backslash is just a character
            "emoji 🔐 name",
            "ファイル.txt", // non-ASCII
        ] {
            assert!(
                VPath::root().join(name).is_ok(),
                "{name:?} should be storable"
            );
        }
    }

    #[test]
    fn starts_with_recognises_a_subtree() {
        let parent = VPath::parse("/a/b").unwrap();
        let child = VPath::parse("/a/b/c").unwrap();
        let sibling = VPath::parse("/a/bb").unwrap();

        assert!(child.starts_with(&parent));
        assert!(parent.starts_with(&parent));
        assert!(parent.starts_with(&VPath::root()));
        assert!(!parent.starts_with(&child));
        // A prefix in string terms is not a prefix in path terms.
        assert!(!sibling.starts_with(&parent));
    }

    #[test]
    fn display_round_trips_through_parse() {
        for input in ["/", "/a", "/a/b/c", "/emoji 🔐/x.txt"] {
            let parsed = VPath::parse(input).unwrap();
            assert_eq!(VPath::parse(&parsed.to_string()).unwrap(), parsed);
        }
    }
}
