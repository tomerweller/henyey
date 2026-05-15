//! Archive upload with ordering guarantees and differential filtering.
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
//! Files are classified into four kinds and uploaded in this order:
//!
//! 1. **Bucket** / **CheckpointData** — bucket files (with hash identity) and
//!    non-bucket data (ledger headers, transactions, results, SCP messages).
//!    Both share upload priority 0.
//! 2. **CheckpointHas** — permanent HAS at `history/XX/YY/ZZ/history-{hex}.json`
//! 3. **RootHas** — `.well-known/stellar-history.json` (the commit point)
//!
//! Within each priority tier, files are sorted by remote path for deterministic
//! ordering.
//!
//! # Differential Upload
//!
//! [`UploadPlan::with_differential_filter`] compares the local HAS against a
//! remote archive's HAS and removes bucket files the remote already has. This
//! mirrors stellar-core's `StateSnapshot::differingHASFiles()` (StateSnapshot.cpp:110).
//!
//! # Failure Semantics
//!
//! If any data or CheckpointHas upload fails, execution stops immediately and
//! the RootHas is never attempted. This prevents clients from seeing a HAS
//! that references files not yet present on the archive.

use crate::archive_state::HistoryArchiveState;
use crate::{paths, HistoryError, Result};
use henyey_common::Hash256;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

/// Classification of a file for upload ordering and differential filtering.
///
/// `Bucket` and `CheckpointData` share upload priority 0 (both are data files
/// that must precede HAS uploads). `Bucket` entries carry a [`Hash256`] for
/// differential filtering — only differing buckets need uploading when the
/// remote archive already has some.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadFileKind {
    /// Bucket data file with its hash for differential filtering.
    /// Uploaded in priority tier 0 (same as `CheckpointData`).
    Bucket(Hash256),
    /// Non-bucket data: ledger headers, transactions, results, SCP messages.
    /// Uploaded in priority tier 0 (same as `Bucket`).
    CheckpointData,
    /// Permanent HAS at `history/XX/YY/ZZ/history-{hex}.json`.
    /// Uploaded after all data files (priority tier 1).
    CheckpointHas,
    /// Root HAS at `.well-known/stellar-history.json`.
    /// The commit point — uploaded last (priority tier 2).
    RootHas,
}

impl UploadFileKind {
    /// Sort priority for upload ordering. Lower values upload first.
    /// `Bucket` and `CheckpointData` share priority 0.
    pub fn sort_priority(&self) -> u8 {
        match self {
            Self::Bucket(_) | Self::CheckpointData => 0,
            Self::CheckpointHas => 1,
            Self::RootHas => 2,
        }
    }

    /// Returns `true` if this is a data file (bucket or checkpoint data).
    pub fn is_data(&self) -> bool {
        self.sort_priority() == 0
    }

    /// Classify a file by its relative path within the staging directory.
    ///
    /// The path must be a normalized relative path (no leading `/` or `.`).
    /// Bucket files matching `bucket/XX/YY/ZZ/bucket-{64hex}.xdr.gz` are
    /// classified as `Bucket(hash)`; all other data files are `CheckpointData`.
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

        // Bucket files: bucket/XX/YY/ZZ/bucket-{64hex}.xdr.gz
        if let Some(hash) = extract_bucket_hash(&path_str) {
            return Self::Bucket(hash);
        }

        // Everything else is non-bucket data.
        Self::CheckpointData
    }
}

/// Extract a bucket hash from a path like `bucket/XX/YY/ZZ/bucket-{64hex}.xdr.gz`.
/// Returns `None` if the path doesn't match the bucket pattern.
fn extract_bucket_hash(path: &str) -> Option<Hash256> {
    // Must start with "bucket/" and contain "/bucket-"
    if !path.starts_with("bucket/") {
        return None;
    }
    let file_name = path.rsplit('/').next()?;
    let hex = file_name.strip_prefix("bucket-")?.strip_suffix(".xdr.gz")?;
    if hex.len() != 64 {
        return None;
    }
    Hash256::from_hex(hex).ok()
}

/// A single file entry in an upload plan.
#[derive(Debug, Clone)]
pub struct UploadEntry {
    /// Absolute path to the local file.
    pub local_path: PathBuf,
    /// Relative path used as the remote destination.
    pub remote_path: String,
    /// Classification determining upload order and differential filtering.
    pub kind: UploadFileKind,
}

/// An ordered upload plan for a checkpoint staging directory.
///
/// Entries are sorted by `(kind.sort_priority(), remote_path)` to guarantee:
/// - All `Bucket` and `CheckpointData` files upload before any `CheckpointHas`
/// - All `CheckpointHas` files upload before `RootHas`
/// - Within each priority tier, files are in deterministic alphabetical order
///
/// # Differential Upload
///
/// Use [`with_differential_filter`](UploadPlan::with_differential_filter) to
/// create a filtered plan that skips bucket files already present on the remote
/// archive.
///
/// # Testing
///
/// Use [`entries()`](UploadPlan::entries) to inspect the plan without executing
/// any shell commands.
#[derive(Clone)]
pub struct UploadPlan {
    entries: Vec<UploadEntry>,
}

/// Sort key for upload entries: `(sort_priority, remote_path)`.
fn entry_sort_key(entry: &UploadEntry) -> (u8, &str) {
    (entry.kind.sort_priority(), &entry.remote_path)
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

        entries.sort_by(|a, b| entry_sort_key(a).cmp(&entry_sort_key(b)));

        Ok(Self { entries })
    }

    /// Create a filtered upload plan that only includes bucket files the remote
    /// archive is missing, plus all non-bucket files unconditionally.
    ///
    /// Computes `local_has.all_differing_bucket_hashes(remote_has)` to find
    /// which buckets the local state has that the remote does not, then keeps
    /// only those `Bucket` entries. All `CheckpointData`, `CheckpointHas`, and
    /// `RootHas` entries pass through unchanged.
    ///
    /// This mirrors stellar-core's `StateSnapshot::differingHASFiles()`
    /// (StateSnapshot.cpp:110-145) which computes per-archive differential
    /// uploads in `PutFilesWork`.
    pub fn with_differential_filter(
        &self,
        local_has: &HistoryArchiveState,
        remote_has: &HistoryArchiveState,
    ) -> Self {
        let needed: HashSet<Hash256> = local_has
            .all_differing_bucket_hashes(remote_has)
            .into_iter()
            .collect();

        let entries = self
            .entries
            .iter()
            .filter(|e| match &e.kind {
                UploadFileKind::Bucket(hash) => needed.contains(hash),
                _ => true,
            })
            .cloned()
            .collect();

        Self { entries }
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

    // Full 64-hex hashes for bucket test files.
    const BUCKET_HASH_A: &str = "aabbccdd00000000000000000000000000000000000000000000000000000000";
    const BUCKET_HASH_B: &str = "1122334400000000000000000000000000000000000000000000000000000000";

    /// Create a staging directory with representative checkpoint files.
    fn create_staging_dir(dir: &Path) {
        let files = [
            format!("bucket/aa/bb/cc/bucket-{BUCKET_HASH_A}.xdr.gz"),
            format!("bucket/11/22/33/bucket-{BUCKET_HASH_B}.xdr.gz"),
            "ledger/00/00/00/ledger-0000003f.xdr.gz".to_string(),
            "transactions/00/00/00/transactions-0000003f.xdr.gz".to_string(),
            "results/00/00/00/results-0000003f.xdr.gz".to_string(),
            "scp/00/00/00/scp-0000003f.xdr.gz".to_string(),
            // Permanent HAS
            "history/00/00/00/history-0000003f.json".to_string(),
            // Root HAS (commit point)
            ".well-known/stellar-history.json".to_string(),
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
    fn classify_bucket_extracts_hash() {
        let path_str = format!("bucket/aa/bb/cc/bucket-{BUCKET_HASH_A}.xdr.gz");
        let kind = UploadFileKind::classify(Path::new(&path_str));
        let expected_hash = Hash256::from_hex(BUCKET_HASH_A).unwrap();
        assert_eq!(kind, UploadFileKind::Bucket(expected_hash));
    }

    #[test]
    fn classify_non_bucket_data() {
        for path in [
            "ledger/00/00/00/ledger-0000003f.xdr.gz",
            "transactions/00/00/00/transactions-0000003f.xdr.gz",
            "results/00/00/00/results-0000003f.xdr.gz",
            "scp/00/00/00/scp-0000003f.xdr.gz",
        ] {
            assert_eq!(
                UploadFileKind::classify(Path::new(path)),
                UploadFileKind::CheckpointData,
                "expected CheckpointData for {path}"
            );
        }
    }

    #[test]
    fn classify_unexpected_file_as_checkpoint_data() {
        let p = Path::new("some/unexpected/file.txt");
        assert_eq!(UploadFileKind::classify(p), UploadFileKind::CheckpointData);
    }

    #[test]
    fn classify_history_file_not_under_history_dir() {
        // A file named history-*.json but not under history/ should be CheckpointData
        let p = Path::new("other/history-0000003f.json");
        assert_eq!(UploadFileKind::classify(p), UploadFileKind::CheckpointData);
    }

    #[test]
    fn classify_bucket_short_hash_is_checkpoint_data() {
        // Bucket path with too-short hash should not be Bucket
        let p = Path::new("bucket/aa/bb/cc/bucket-aabbccdd.xdr.gz");
        assert_eq!(UploadFileKind::classify(p), UploadFileKind::CheckpointData);
    }

    #[test]
    fn extract_bucket_hash_valid() {
        let path = format!("bucket/aa/bb/cc/bucket-{BUCKET_HASH_A}.xdr.gz");
        let hash = extract_bucket_hash(&path).unwrap();
        assert_eq!(hash, Hash256::from_hex(BUCKET_HASH_A).unwrap());
    }

    #[test]
    fn extract_bucket_hash_non_bucket() {
        assert!(extract_bucket_hash("ledger/00/00/00/ledger-0000003f.xdr.gz").is_none());
    }

    #[test]
    fn extract_bucket_hash_short_hex() {
        assert!(extract_bucket_hash("bucket/aa/bb/cc/bucket-aabbccdd.xdr.gz").is_none());
    }

    #[test]
    fn plan_ordering_data_before_has_before_root() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());

        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();
        let entries = plan.entries();

        // Verify all data entries come first, then CheckpointHas, then RootHas
        let priorities: Vec<_> = entries.iter().map(|e| e.kind.sort_priority()).collect();

        let last_data = priorities.iter().rposition(|p| *p == 0);
        let first_checkpoint_has = priorities.iter().position(|p| *p == 1);
        let first_root_has = priorities.iter().position(|p| *p == 2);

        if let (Some(ld), Some(fch)) = (last_data, first_checkpoint_has) {
            assert!(
                ld < fch,
                "last data entry (index {ld}) must come before first CheckpointHas (index {fch})"
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
    }

    #[test]
    fn plan_deterministic_within_priority() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());

        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();
        let data_paths: Vec<_> = plan
            .entries()
            .iter()
            .filter(|e| e.kind.is_data())
            .map(|e| e.remote_path.as_str())
            .collect();

        let mut sorted = data_paths.clone();
        sorted.sort();
        assert_eq!(
            data_paths, sorted,
            "Data entries must be sorted by remote_path"
        );
    }

    #[test]
    fn differential_filter_removes_present_buckets() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());
        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();

        // Count bucket entries in base plan
        let bucket_count = plan
            .entries()
            .iter()
            .filter(|e| matches!(e.kind, UploadFileKind::Bucket(_)))
            .count();
        assert_eq!(bucket_count, 2);

        // Create a local HAS with only bucket A and a remote HAS with bucket A
        // → differential should yield 0 needed buckets if both have the same
        // But here we test: remote has all buckets → filtered plan has 0 buckets
        let hash_a = Hash256::from_hex(BUCKET_HASH_A).unwrap();
        let hash_b = Hash256::from_hex(BUCKET_HASH_B).unwrap();

        // Build HAS where local has A+B, remote has A+B (identical)
        let local_has = test_has_with_buckets(&[hash_a, hash_b]);
        let remote_has = test_has_with_buckets(&[hash_a, hash_b]);

        let filtered = plan.with_differential_filter(&local_has, &remote_has);
        let filtered_bucket_count = filtered
            .entries()
            .iter()
            .filter(|e| matches!(e.kind, UploadFileKind::Bucket(_)))
            .count();
        assert_eq!(
            filtered_bucket_count, 0,
            "identical states should yield no bucket uploads"
        );

        // Non-bucket entries should all be present
        let non_bucket_base = plan
            .entries()
            .iter()
            .filter(|e| !matches!(e.kind, UploadFileKind::Bucket(_)))
            .count();
        let non_bucket_filtered = filtered
            .entries()
            .iter()
            .filter(|e| !matches!(e.kind, UploadFileKind::Bucket(_)))
            .count();
        assert_eq!(non_bucket_base, non_bucket_filtered);
    }

    #[test]
    fn differential_filter_keeps_needed_buckets() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());
        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();

        let hash_a = Hash256::from_hex(BUCKET_HASH_A).unwrap();
        let hash_b = Hash256::from_hex(BUCKET_HASH_B).unwrap();

        // Local has A+B, remote has only A → B is needed
        let local_has = test_has_with_buckets(&[hash_a, hash_b]);
        let remote_has = test_has_with_buckets(&[hash_a]);

        let filtered = plan.with_differential_filter(&local_has, &remote_has);
        let filtered_buckets: Vec<_> = filtered
            .entries()
            .iter()
            .filter_map(|e| match &e.kind {
                UploadFileKind::Bucket(h) => Some(*h),
                _ => None,
            })
            .collect();
        assert_eq!(filtered_buckets.len(), 1);
        assert_eq!(filtered_buckets[0], hash_b);
    }

    #[test]
    fn differential_filter_empty_remote_keeps_all() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());
        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();

        let hash_a = Hash256::from_hex(BUCKET_HASH_A).unwrap();
        let hash_b = Hash256::from_hex(BUCKET_HASH_B).unwrap();

        // Local has A+B, remote is empty → all needed
        let local_has = test_has_with_buckets(&[hash_a, hash_b]);
        let remote_has = test_has_with_buckets(&[]);

        let filtered = plan.with_differential_filter(&local_has, &remote_has);
        assert_eq!(filtered.entries().len(), plan.entries().len());
    }

    /// Build a minimal HAS with specific bucket hashes for testing differential logic.
    fn test_has_with_buckets(hashes: &[Hash256]) -> HistoryArchiveState {
        use crate::archive_state::HASBucketLevel;
        let zero = Hash256::ZERO.to_hex();
        let mut levels = Vec::new();
        for (i, chunk) in hashes.chunks(2).enumerate() {
            let curr = if !chunk.is_empty() {
                chunk[0].to_hex()
            } else {
                zero.clone()
            };
            let snap = if chunk.len() > 1 {
                chunk[1].to_hex()
            } else {
                zero.clone()
            };
            levels.push(HASBucketLevel::new_from_hashes(curr, snap));
            let _ = i;
        }
        // Pad to 11 levels (standard bucket list depth)
        while levels.len() < 11 {
            levels.push(HASBucketLevel::new_from_hashes(zero.clone(), zero.clone()));
        }
        HistoryArchiveState::new_for_testing(63, levels)
    }

    #[test]
    fn execute_uploads_in_correct_order() {
        let dir = tempfile::tempdir().unwrap();
        create_staging_dir(dir.path());
        let log_file = dir.path().join("upload-order.log");

        let plan = UploadPlan::from_staging_dir(dir.path()).unwrap();

        let put_cmd = format!("echo {{1}} >> {}", log_file.display());
        plan.execute(&put_cmd, None).unwrap();

        let log = fs::read_to_string(&log_file).unwrap();
        let uploaded: Vec<&str> = log.lines().collect();

        let root_has_idx = uploaded
            .iter()
            .position(|p| *p == ".well-known/stellar-history.json")
            .expect("root HAS must be uploaded");
        let checkpoint_has_idx = uploaded
            .iter()
            .position(|p| p.starts_with("history/") && p.contains("history-"))
            .expect("checkpoint HAS must be uploaded");

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

        let fail_path = plan
            .entries()
            .iter()
            .find(|e| e.kind.is_data())
            .map(|e| e.remote_path.clone())
            .unwrap();

        let put_cmd = format!(
            "if [ \"{{1}}\" = \"{}\" ]; then exit 1; fi; echo {{1}} >> {}",
            fail_path,
            log_file.display()
        );

        let result = plan.execute(&put_cmd, None);
        assert!(result.is_err(), "upload should fail");

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
