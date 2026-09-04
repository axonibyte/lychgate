//! A temporary directory that removes itself, however the test ends.
//!
//! A remove_dir_all at the end of a test body does not run when the test
//! panics, and tests panic — that is what they are for. Drop runs either
//! way. (Reaper's harnesses leaked nearly a thousand scratch directories
//! before this shape was adopted; the counter keeps parallel test threads
//! and concurrent cargo test runs from colliding.)

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) struct Scratch(PathBuf);

impl Scratch {
    pub(crate) fn new(label: &str) -> Scratch {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "lychgated-test-{}-{}-{label}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst),
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn scratch_dir(label: &str) -> Scratch {
    Scratch::new(label)
}
