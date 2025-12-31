//! URL path generation for history archive files.
//!
//! History archives use a hierarchical path structure with hex-encoded
//! ledger sequences for sharding across directories.

use stellar_core_common::Hash256;

/// Checkpoint frequency in ledgers.
pub const CHECKPOINT_FREQUENCY: u32 = 64;

/// Calculate the checkpoint ledger for a given sequence.
///
/// Checkpoint ledgers are of the form `(n * 64) + 63`, i.e., 63, 127, 191, etc.
/// This function rounds a ledger sequence to its corresponding checkpoint.
///
/// # Examples
///
/// ```
/// use stellar_core_history::paths::checkpoint_ledger;
///
/// assert_eq!(checkpoint_ledger(0), 63);
/// assert_eq!(checkpoint_ledger(63), 63);
/// assert_eq!(checkpoint_ledger(64), 127);
/// assert_eq!(checkpoint_ledger(127), 127);
/// assert_eq!(checkpoint_ledger(128), 191);
/// ```
#[inline]
pub fn checkpoint_ledger(seq: u32) -> u32 {
    (seq / CHECKPOINT_FREQUENCY) * CHECKPOINT_FREQUENCY + (CHECKPOINT_FREQUENCY - 1)
}

/// Check if a ledger sequence is a checkpoint ledger.
///
/// # Examples
///
/// ```
/// use stellar_core_history::paths::is_checkpoint_ledger;
///
/// assert!(is_checkpoint_ledger(63));
/// assert!(is_checkpoint_ledger(127));
/// assert!(!is_checkpoint_ledger(64));
/// assert!(!is_checkpoint_ledger(100));
/// ```
#[inline]
pub fn is_checkpoint_ledger(seq: u32) -> bool {
    (seq + 1) % CHECKPOINT_FREQUENCY == 0
}

/// Generate the path for a checkpoint file.
///
/// The path format is: `{category}/{xx}/{yy}/{zz}/{category}-{hex}.{ext}`
/// where `{xx}/{yy}/{zz}` are the first three bytes of the hex-encoded checkpoint ledger.
///
/// # Arguments
///
/// * `category` - The file category (e.g., "history", "ledger", "transactions", "results", "scp")
/// * `ledger` - The ledger sequence (will be rounded to checkpoint)
/// * `ext` - The file extension (e.g., "json", "xdr.gz")
///
/// # Examples
///
/// ```
/// use stellar_core_history::paths::checkpoint_path;
///
/// // Ledger 63 (first checkpoint)
/// assert_eq!(
///     checkpoint_path("ledger", 63, "xdr.gz"),
///     "ledger/00/00/00/ledger-0000003f.xdr.gz"
/// );
///
/// // Ledger 127 (second checkpoint)
/// assert_eq!(
///     checkpoint_path("history", 127, "json"),
///     "history/00/00/00/history-0000007f.json"
/// );
///
/// // Any ledger in a checkpoint gets rounded
/// assert_eq!(
///     checkpoint_path("transactions", 100, "xdr.gz"),
///     "transactions/00/00/00/transactions-0000007f.xdr.gz"
/// );
/// ```
pub fn checkpoint_path(category: &str, ledger: u32, ext: &str) -> String {
    let checkpoint = checkpoint_ledger(ledger);
    let hex = format!("{:08x}", checkpoint);

    format!(
        "{}/{}/{}/{}/{}-{}.{}",
        category,
        &hex[0..2],
        &hex[2..4],
        &hex[4..6],
        category,
        hex,
        ext
    )
}

/// Generate the path for a bucket file.
///
/// The path format is: `bucket/{xx}/{yy}/{zz}/bucket-{hash}.xdr.gz`
/// where `{xx}/{yy}/{zz}` are the first three bytes of the hex-encoded hash.
///
/// # Arguments
///
/// * `hash` - The bucket hash
///
/// # Examples
///
/// ```
/// use stellar_core_common::Hash256;
/// use stellar_core_history::paths::bucket_path;
///
/// let hash = Hash256::from_hex("e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd").unwrap();
/// assert_eq!(
///     bucket_path(&hash),
///     "bucket/e1/13/f8/bucket-e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd.xdr.gz"
/// );
/// ```
pub fn bucket_path(hash: &Hash256) -> String {
    let hex = hash.to_hex();

    format!(
        "bucket/{}/{}/{}/bucket-{}.xdr.gz",
        &hex[0..2],
        &hex[2..4],
        &hex[4..6],
        hex
    )
}

/// Generate the path for the root history archive state file.
pub fn root_has_path() -> &'static str {
    ".well-known/stellar-history.json"
}

/// Generate the directory path for ledger-related files at a checkpoint.
///
/// Returns: `ledger/{xx}/{yy}/{zz}`
pub fn ledger_dir(ledger: u32) -> String {
    let checkpoint = checkpoint_ledger(ledger);
    let hex = format!("{:08x}", checkpoint);

    format!("ledger/{}/{}/{}", &hex[0..2], &hex[2..4], &hex[4..6])
}

/// Generate the path for a checkpoint file without extension.
///
/// Returns: `{category}/{xx}/{yy}/{zz}/{category}-{hex}`
pub fn checkpoint_file_path(ledger: u32, file_type: &str) -> String {
    let checkpoint = checkpoint_ledger(ledger);
    let hex = format!("{:08x}", checkpoint);

    format!(
        "{}/{}/{}/{}/{}-{}",
        file_type,
        &hex[0..2],
        &hex[2..4],
        &hex[4..6],
        file_type,
        hex
    )
}

/// Generate the path for a History Archive State file.
///
/// Returns: `history/{xx}/{yy}/{zz}/history-{hex}.json`
pub fn has_path(ledger: u32) -> String {
    checkpoint_path("history", ledger, "json")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_ledger() {
        // First checkpoint
        assert_eq!(checkpoint_ledger(0), 63);
        assert_eq!(checkpoint_ledger(1), 63);
        assert_eq!(checkpoint_ledger(63), 63);

        // Second checkpoint
        assert_eq!(checkpoint_ledger(64), 127);
        assert_eq!(checkpoint_ledger(100), 127);
        assert_eq!(checkpoint_ledger(127), 127);

        // Third checkpoint
        assert_eq!(checkpoint_ledger(128), 191);
        assert_eq!(checkpoint_ledger(191), 191);

        // Large checkpoints
        assert_eq!(checkpoint_ledger(1000000), 1000063);
    }

    #[test]
    fn test_is_checkpoint_ledger() {
        assert!(is_checkpoint_ledger(63));
        assert!(is_checkpoint_ledger(127));
        assert!(is_checkpoint_ledger(191));
        assert!(is_checkpoint_ledger(1000063));

        assert!(!is_checkpoint_ledger(0));
        assert!(!is_checkpoint_ledger(64));
        assert!(!is_checkpoint_ledger(100));
        assert!(!is_checkpoint_ledger(1000000));
    }

    #[test]
    fn test_checkpoint_path() {
        // First checkpoint (ledger 63 = 0x3f)
        assert_eq!(
            checkpoint_path("ledger", 63, "xdr.gz"),
            "ledger/00/00/00/ledger-0000003f.xdr.gz"
        );

        // Second checkpoint (ledger 127 = 0x7f)
        assert_eq!(
            checkpoint_path("history", 127, "json"),
            "history/00/00/00/history-0000007f.json"
        );

        // Rounds to checkpoint
        assert_eq!(
            checkpoint_path("transactions", 100, "xdr.gz"),
            "transactions/00/00/00/transactions-0000007f.xdr.gz"
        );

        // Large checkpoint (ledger 16777215 = 0xffffff)
        assert_eq!(
            checkpoint_path("results", 16777215, "xdr.gz"),
            "results/00/ff/ff/results-00ffffff.xdr.gz"
        );

        // Very large checkpoint
        assert_eq!(
            checkpoint_path("scp", 0x12345678 + 63, "xdr.gz"),
            "scp/12/34/56/scp-123456bf.xdr.gz"
        );
    }

    #[test]
    fn test_bucket_path() {
        let hash = Hash256::from_hex(
            "e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd",
        )
        .unwrap();

        assert_eq!(
            bucket_path(&hash),
            "bucket/e1/13/f8/bucket-e113f8cc5468579cb57538e3204c8d3ecce59a0cdb47f6fa7e87ab4d9d8146fd.xdr.gz"
        );

        // Zero hash
        assert_eq!(
            bucket_path(&Hash256::ZERO),
            "bucket/00/00/00/bucket-0000000000000000000000000000000000000000000000000000000000000000.xdr.gz"
        );
    }

    #[test]
    fn test_root_has_path() {
        assert_eq!(root_has_path(), ".well-known/stellar-history.json");
    }
}
