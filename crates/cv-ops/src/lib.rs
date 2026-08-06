//! Long-running operations on a vault.
//!
//! Importing a folder, exporting a subtree, opening a file in an external
//! application, indexing names for search, taking a backup: everything that
//! takes long enough for the user to notice, and therefore everything that needs
//! progress reporting, pausing and cancellation.
//!
//! This is the highest crate that knows nothing about the user interface. The
//! Tauri backend and the CLI both sit on top of it and are interchangeable from
//! here; nothing below this line may assume a window exists.
//!
//! # Status
//!
//! Milestone M0 defines progress reporting. The jobs themselves arrive from M2
//! onwards.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use thiserror::Error;

/// Progress of a long-running operation, in bytes.
///
/// Bytes rather than a file count, because a folder of one 4 GiB video and nine
/// hundred small documents makes a file counter jump to 99% and then sit there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Progress {
    done: u64,
    total: u64,
}

impl Progress {
    /// Creates a progress value.
    ///
    /// `done` is clamped to `total`: a rounding slip or a file that grew while
    /// being read must not produce 103%, which looks to a user exactly like a
    /// bug even when nothing is wrong.
    #[must_use]
    pub fn new(done: u64, total: u64) -> Self {
        Self {
            done: done.min(total),
            total,
        }
    }

    /// Bytes processed so far.
    #[must_use]
    pub const fn done(self) -> u64 {
        self.done
    }

    /// Total bytes to process.
    #[must_use]
    pub const fn total(self) -> u64 {
        self.total
    }

    /// Completion as a fraction between `0.0` and `1.0`.
    ///
    /// An empty job is complete, not undefined: a folder containing nothing has
    /// been fully imported the moment it is asked for.
    #[must_use]
    pub fn fraction(self) -> f64 {
        if self.total == 0 {
            return 1.0;
        }
        #[allow(
            clippy::cast_precision_loss,
            reason = "a progress bar needs three digits, not fifteen"
        )]
        let fraction = self.done as f64 / self.total as f64;
        fraction
    }

    /// Whether every byte has been processed.
    #[must_use]
    pub const fn is_complete(self) -> bool {
        self.done >= self.total
    }
}

/// Errors produced by long-running operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OpsError {
    /// The user cancelled the operation.
    ///
    /// Cancellation is an ordinary outcome, not a failure: it is reported so the
    /// caller can roll back cleanly and tell the user what did and did not get
    /// done.
    #[error("operation cancelled")]
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_job_is_already_complete() {
        let p = Progress::new(0, 0);
        assert!(p.is_complete());
        assert!((p.fraction() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn fraction_tracks_the_bytes_done() {
        let p = Progress::new(25, 100);
        assert!((p.fraction() - 0.25).abs() < 1e-12);
        assert!(!p.is_complete());
    }

    #[test]
    fn progress_never_exceeds_one_hundred_percent() {
        let p = Progress::new(150, 100);
        assert_eq!(p.done(), 100);
        assert_eq!(p.total(), 100);
        assert!((p.fraction() - 1.0).abs() < f64::EPSILON);
        assert!(p.is_complete());
    }

    #[test]
    fn a_very_large_job_still_reports_sensibly() {
        let ten_tib = 10 * 1024 * 1024 * 1024 * 1024_u64;
        let p = Progress::new(ten_tib / 2, ten_tib);
        assert!((p.fraction() - 0.5).abs() < 1e-9);
    }

    #[test]
    fn default_progress_is_an_empty_completed_job() {
        assert_eq!(Progress::default(), Progress::new(0, 0));
    }
}
