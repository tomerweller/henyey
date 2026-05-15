//! Archive upload with ordering guarantees.
//!
//! When publishing a checkpoint to a remote history archive, the upload order
//! matters for atomicity: data files (buckets, ledgers, transactions, results,
//! SCP) must be uploaded **before** any History Archive State (HAS) files, and
//! the root HAS at `.well-known/stellar-history.json` must be uploaded **last**.
//!
//! This mirrors stellar-core's `PutSnapshotFilesWork` → `PutHistoryArchiveStateWork`
//! sequencing (see `PutSnapshotFilesWork.cpp:57-70`).
//!
//! # Upload Ordering
//!
//! Files are classified into three kinds and uploaded in this order:
//!
//! 1. **Data** — bucket files, ledger headers, transactions, results, SCP messages
//! 2. **CheckpointHas** — permanent HAS at `history/XX/YY/ZZ/history-{hex}.json`
//! 3. **RootHas** — `.well-known/stellar-history.json` (the commit point)
//!
//! Within each kind, files are sorted by remote path for deterministic ordering.
//!
//! # Failure Semantics
//!
//! If any Data or CheckpointHas upload fails, execution stops immediately and
//! the RootHas is never attempted. This prevents clients from seeing a HAS
//! that references files not yet present on the archive.

use crate::{paths, HistoryError, Result};
use std::path::{Path, PathBuf};

/// Classification of a file for upload ordering.
///
/// The `Ord` derivation encodes the upload order: `Data < CheckpointHas < RootHas`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum UploadFileKind {
    /// Bucket files, ledger headers, transactions, results, SCP messages.
    /// Uploaded first.
    Data,
    /// Permanent HAS at `history/XX/YY/ZZ/history-{hex}.json`.
    /// Uploaded after all data files.
    CheckpointHas,
    /// Root HAS at `.well-known/stellar-history.json`.
    /// The commit point — uploaded last.
    RootHas,
}

impl UploadFileKind {
    /// Classify a file by its relative path within the staging directory.
    ///
    /// The path must be a normalized relative path (no leading `/` or `.`).
    pub fn classify(relative_path: &Path) -> Self {
        let path_str = path_to_unix_string(relative_path);

        // Exact match for root HAS (the commit point).
        if path_str == paths::root_has_path() {
            return Self::RootHas;
        }

        // Permanent HAS: history/XX/YY/ZZ/history-{hex}.json
        if let Some(file_name) = relative_path.file_name().and_then(|n| n.to_str()) {
            if file_name.starts_with("history-") && file_name.ends_with(".json") {
                if relative_path.starts_with("history") {
                    return Self::CheckpointHas;
                }
            }
        }

        // Everything else is data (including unexpected files — conservative choice).
        Self::Data
    }
}

/// A single file entry in an upload plan.
#[derive(Debug)]
pub struct UploadEntry {
    /// Absolute path to the local file.
    pub local_path: PathBuf,
    /// Relative path used as the remote destination.
    pub remote_path: String,
    /// Classification determining upload order.
    pub kind: UploadFileKind,
}

/// An ordered upload plan for a checkpoint staging directory.
///
/// Entries are sorted by `(kind, remote_path)` to guarantee:
/// - All `Data` files upload before any `CheckpointHas` files
/// - All `CheckpointHas` files upload before `RootHas`
/// - Within each kind, files are in deterministic alphabetical order
///
/// # Testing
///
/// Use [`entries()`](UploadPlan::entries) to inspect the plan without executing
/// any shell commands.
pub struct UploadPlan {
    entries: Vec<UploadEntry>,
}

impl UploadPlan {
    /// Build an upload plan by scanning a staging directory.
    ///
    /// All files under `publish_dir` are collected, classified, and sorted
    /// into upload order.
    pub fn from_staging_dir(publish_dir: &Path) -> Result<Self> {
        let files = collect_files(publish_dir)?;

        let mut entries: Vec<UploadEntry> = files
            .into_iter()
            .map(|local_path| {
                let rel = local_path
                    .strip_prefix(publish_dir)
                    .expect("collected file must be under publish_dir");
                let remote_path = path_to_unix_string(rel);
                let kind = UploadFileKind::classify(rel);
                UploadEntry {
                    local_path,
                    remote_path,
                    kind,
                }
            })
            .collect();

        // Sort by (kind, remote_path) for deterministic, correctly-ordered upload.
        entries.sort_by(|a, b| {
            a.kind
                .cmp(&b.kind)
                .then_with(|| a.remote_path.cmp(&b.remote_path))
        });

        Ok(Self { entries })
    }

    /// Access the ordered entries for inspection or testing.
    pub fn entries(&self) -> &[UploadEntry] {
        &self.entries
    }

    /// Execute the upload plan via shell commands.
    ///
    /// For each entry, creates the remote parent directory (if `mkdir_cmd` is
    /// provided) and uploads the file using `put_cmd`.
    ///
    /// Command templates use positional placeholders:
    /// - `put_cmd`: `{0}` = local path, `{1}` = remote path
    /// - `mkdir_cmd`: `{0}` = remote directory
    ///
    /// If any upload fails, execution stops immediately. Because entries are
    /// sorted with `RootHas` last, a failure in any earlier file guarantees
    /// the root HAS is never uploaded.
    pub fn execute(&self, put_cmd: &str, mkdir_cmd: Option<&str>) -> Result<()> {
        use std::collections::HashSet;
        let mut created_dirs = HashSet::new();

        for entry in &self.entries {
            // Create remote parent directory if needed.
            if let Some(mkdir) = mkdir_cmd {
                if let Some(parent) = Path::new(&entry.remote_path).parent() {
                    let parent_str = path_to_unix_string(parent);
                    if !parent_str.is_empty() && created_dirs.insert(parent_str.clone()) {
                        let cmd = mkdir.replace("{0}", &parent_str);
                        run_shell_command(&cmd)?;
                    }
                }
            }

            // Upload the file.
            let cmd = put_cmd
                .replace("{0}", entry.local_path.to_string_lossy().as_ref())
                .replace("{1}", &entry.remote_path);
            run_shell_command(&cmd)?;
        }

        Ok(())
    }
}

/// Convert a path to a Unix-style string with forward slashes.
pub fn path_to_unix_string(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Recursively collect all files under a directory.
pub fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    Ok(files)
}

/// Execute a shell command and return an error if it fails.
fn run_shell_command(cmd: &str) -> Result<()> {
    use std::process::Command;

    let output = Command::new("sh").arg("-c").arg(cmd).output()?;
    if output.status.success() {
        Ok(())
    } else {
        Err(HistoryError::RemoteCommandFailed {
            command: cmd.to_string(),
            exit_code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Create a staging directory with representative checkpoint files.
    fn create_staging_dir(dir: &Path) {
        // Data files
        let files = [
            "bucket/aa/bb/cc/bucket-aabbccdd.xdr.gz",
            "bucket/11/22/33/bucket-11223344.xdr.gz",
            "ledger/00/00/00/ledger-0000003f.xdr.gz",
            "transactions/00/00/00/transactions-0000003f.xdr.gz",
            "results/00/00/00/results-0000003f.xdr.gz",
            "scp/00/00/00/scp-0000003f.xdr.gz",
            // Permanent HAS
            "history/00/00/00/history-0000003f.json",
            // Root HAS (commit point)
            ".well-known/stellar-history.json",
        ];
        for f in &files {
            let path = dir.join(f);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, format!("content of {f}")).unwrap();
        }
    }

    #[test]
    fn classify_root_has() {
        let p = Path::new(".well-known/stellar-history.json");
        assert_eq!(UploadFileKind::classify(p), UploadFileKind::RootHas);
    }

    #[test]
    fn classify_checkpoint_has() {
        let p = Path::new("history/00/00/00/history-0000003f.json");
        assert_eq!(UploadFileKind::classify(p), UploadFileKind::CheckpointHas);
    }

    #[test]
    fn classify_data_files() {
        for path in [
            "bucket/aa/bb/cc/bucket-aabbccdd.xdr.gz",
            "ledger/00/00/00/ledger-0000003f.xdr.gz",
            "transactions/00/00/00/transactions-0000003f.xdr.gz",
            "results/00/00/00/results-0000003f.xdr.gz",
            "scp/00/00/00/scp-0000003f.xdr.gz",
        ] {
            assert_eq!(
                UploadFileKind::classify(Path::new(path)),
                UploadFileKind::Data,
                "expected Data for {path}"
            );
        }
    }

    #[test]
    fn classify_unexpected_file_as_data() {
        let p = Path::new("some/unexpected/file.txt");
        assert_eq!(UploadFileKind::classify(p), UploadFileKind::Data);
    }

    #[test]
    fn classify_history_file_not_under_history_dir() {
        // A file named history-*.json but not under history/ should be Data
        let p = Path::new("other/history-0000003f.json");
        assert_eq!(UploadFileKind::classify(p), UploadFileKind::Data);
    }

    #[test]
    fn plan_ordering_data_before_has_before_root() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());

        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();
        let entries = plan.entries();

        // Verify all Data entries come first, then CheckpointHas, then RootHas
        let kinds: Vec<_> = entries.iter().map(|e| e.kind).collect();

        let last_data = kinds.iter().rposition(|k| *k == UploadFileKind::Data);
        let first_checkpoint_has = kinds
            .iter()
            .position(|k| *k == UploadFileKind::CheckpointHas);
        let first_root_has = kinds.iter().position(|k| *k == UploadFileKind::RootHas);

        if let (Some(ld), Some(fch)) = (last_data, first_checkpoint_has) {
            assert!(
                ld < fch,
                "last Data entry (index {ld}) must come before first CheckpointHas (index {fch})"
            );
        }
        if let (Some(fch), Some(frh)) = (first_checkpoint_has, first_root_has) {
            assert!(
                fch < frh,
                "first CheckpointHas (index {fch}) must come before first RootHas (index {frh})"
            );
        }

        // RootHas must be the very last entry
        assert_eq!(
            entries.last().unwrap().kind,
            UploadFileKind::RootHas,
            "root HAS must be the last entry"
        );
        assert_eq!(
            entries.last().unwrap().remote_path,
            ".well-known/stellar-history.json"
        );
    }

    #[test]
    fn plan_deterministic_within_kind() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());

        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();
        let data_paths: Vec<_> = plan
            .entries()
            .iter()
            .filter(|e| e.kind == UploadFileKind::Data)
            .map(|e| e.remote_path.as_str())
            .collect();

        // Must be sorted
        let mut sorted = data_paths.clone();
        sorted.sort();
        assert_eq!(
            data_paths, sorted,
            "Data entries must be sorted by remote_path"
        );
    }

    #[test]
    fn execute_uploads_in_correct_order() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());
        let log_file = dir.path().join("upload-order.log");

        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();

        // put command that logs the remote path
        let put_cmd = format!("echo {{1}} >> {}", log_file.display());
        plan.execute(&put_cmd, None).unwrap();

        let log = fs::read_to_string(&log_file).unwrap();
        let uploaded: Vec<&str> = log.lines().collect();

        // Find indices
        let root_has_idx = uploaded
            .iter()
            .position(|p| *p == ".well-known/stellar-history.json")
            .expect("root HAS must be uploaded");
        let checkpoint_has_idx = uploaded
            .iter()
            .position(|p| p.starts_with("history/") && p.contains("history-"))
            .expect("checkpoint HAS must be uploaded");

        // All data files must come before checkpoint HAS
        for (i, path) in uploaded.iter().enumerate() {
            if *path != ".well-known/stellar-history.json"
                && !(path.starts_with("history/") && path.contains("history-"))
            {
                assert!(
                    i < checkpoint_has_idx,
                    "data file {path} (index {i}) must come before checkpoint HAS (index {checkpoint_has_idx})"
                );
            }
        }

        // Root HAS must be last
        assert_eq!(
            root_has_idx,
            uploaded.len() - 1,
            "root HAS must be the last uploaded file"
        );
    }

    #[test]
    fn execute_failure_prevents_root_has_upload() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());
        let log_file = dir.path().join("upload-order.log");

        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();

        // Find a data file to fail on
        let fail_path = plan
            .entries()
            .iter()
            .find(|e| e.kind == UploadFileKind::Data)
            .map(|e| e.remote_path.clone())
            .unwrap();

        // put command that fails on the specific file, logs otherwise
        let put_cmd = format!(
            "if [ \"{{1}}\" = \"{}\" ]; then exit 1; fi; echo {{1}} >> {}",
            fail_path,
            log_file.display()
        );

        let result = plan.execute(&put_cmd, None);
        assert!(result.is_err(), "upload should fail");

        // Root HAS must not have been attempted
        if log_file.exists() {
            let log = fs::read_to_string(&log_file).unwrap();
            assert!(
                !log.contains(".well-known/stellar-history.json"),
                "root HAS must not be uploaded after a data file failure"
            );
        }
    }

    #[test]
    fn execute_creates_directories_before_upload() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());
        let log_file = dir.path().join("cmd-order.log");

        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();

        let put_cmd = format!("echo PUT {{1}} >> {}", log_file.display());
        let mkdir_cmd = format!("echo MKDIR {{0}} >> {}", log_file.display());

        plan.execute(&put_cmd, Some(&mkdir_cmd)).unwrap();

        let log = fs::read_to_string(&log_file).unwrap();
        let lines: Vec<&str> = log.lines().collect();

        // For each PUT, verify its parent MKDIR came before it
        for (i, line) in lines.iter().enumerate() {
            if let Some(remote_path) = line.strip_prefix("PUT ") {
                if let Some(parent) = Path::new(remote_path).parent() {
                    let parent_str = path_to_unix_string(parent);
                    if !parent_str.is_empty() {
                        let mkdir_line = format!("MKDIR {parent_str}");
                        let mkdir_idx = lines
                            .iter()
                            .position(|l| *l == mkdir_line)
                            .unwrap_or_else(|| panic!("MKDIR for {parent_str} not found"));
                        assert!(
                            mkdir_idx < i,
                            "MKDIR {parent_str} (index {mkdir_idx}) must come before PUT {remote_path} (index {i})"
                        );
                    }
                }
            }
        }
    }
}
