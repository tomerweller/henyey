//! Filesystem utilities for crash-safe operations.
//!
//! This module provides durable filesystem operations that match stellar-core's
//! crash-safety semantics, ensuring data survives both application crashes and
//! OS/power-loss crashes.
//!
//! # Durability Guarantees
//!
//! - [`durable_rename`] performs a rename followed by an `fsync` on the parent
//!   directory, ensuring the directory entry update is persisted to stable storage.
//!   This matches stellar-core's `durableRename()` in `Fs.cpp`.

use std::fs;
use std::io;
use std::path::Path;

/// Atomically rename a file and fsync the parent directory.
///
/// This ensures the rename is durable even in the face of an OS crash or
/// power loss. Without the directory fsync, the rename could be lost even
/// though `rename()` is atomic at the filesystem level — the directory entry
/// update may only be in the kernel's page cache.
///
/// Matches stellar-core's `durableRename()` in `Fs.cpp`.
///
/// # Errors
///
/// Returns an error if:
/// - The rename fails (e.g., source doesn't exist, permission denied)
/// - The parent directory cannot be opened or fsynced
pub fn durable_rename(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)?;

    // Fsync the parent directory to ensure the rename is durable.
    // On POSIX systems, rename is atomic but the directory entry update
    // may not be flushed to disk until the directory is fsynced.
    if let Some(parent) = to.parent() {
        let dir = fs::File::open(parent)?;
        dir.sync_all()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_durable_rename_basic() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("source.txt");
        let dst = dir.path().join("dest.txt");

        fs::write(&src, b"hello").unwrap();
        assert!(src.exists());
        assert!(!dst.exists());

        durable_rename(&src, &dst).unwrap();

        assert!(!src.exists());
        assert!(dst.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"hello");
    }

    #[test]
    fn test_durable_rename_overwrite() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("source.txt");
        let dst = dir.path().join("dest.txt");

        fs::write(&src, b"new content").unwrap();
        fs::write(&dst, b"old content").unwrap();

        durable_rename(&src, &dst).unwrap();

        assert!(!src.exists());
        assert_eq!(fs::read(&dst).unwrap(), b"new content");
    }

    #[test]
    fn test_durable_rename_nonexistent_source() {
        let dir = TempDir::new().unwrap();
        let src = dir.path().join("nonexistent.txt");
        let dst = dir.path().join("dest.txt");

        let result = durable_rename(&src, &dst);
        assert!(result.is_err());
    }
}
