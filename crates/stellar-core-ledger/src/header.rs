//! LedgerHeader utilities.
//!
//! This module provides utilities for working with ledger headers:
//! - Computing header hashes
//! - Computing and verifying skip lists
//! - Verifying header chain integrity

use crate::{LedgerError, Result};
use stellar_core_common::Hash256;
use stellar_xdr::curr::{Hash, LedgerHeader, Limits, WriteXdr};

/// Number of entries in the skip list.
pub const SKIP_LIST_SIZE: usize = 4;

/// Compute the hash of a ledger header.
///
/// This is the canonical hash used to identify ledgers.
pub fn compute_header_hash(header: &LedgerHeader) -> Result<Hash256> {
    let xdr_bytes = header.to_xdr(Limits::none())?;
    Ok(Hash256::hash(&xdr_bytes))
}

/// Compute the skip list for a new ledger header.
///
/// The skip list contains hashes of previous ledger headers at specific intervals,
/// enabling efficient backward traversal of the ledger chain.
///
/// The skip list entries point to:
/// - Entry 0: Previous ledger (seq - 1)
/// - Entry 1: Ledger at seq - (seq mod 2) - 2
/// - Entry 2: Ledger at seq - (seq mod 8) - 8
/// - Entry 3: Ledger at seq - (seq mod 64) - 64
///
/// Each entry skips back by larger powers of 2, enabling O(log n) traversal.
pub fn compute_skip_list(
    ledger_seq: u32,
    prev_hash: Hash256,
    prev_skip_list: &[Hash; SKIP_LIST_SIZE],
) -> [Hash; SKIP_LIST_SIZE] {
    let mut skip_list = std::array::from_fn(|_| Hash([0u8; 32]));

    if ledger_seq == 0 {
        return skip_list;
    }

    // Entry 0 is always the previous ledger hash
    skip_list[0] = prev_hash.into();

    // For entries 1-3, compute which previous skip list entry to use
    for i in 1..SKIP_LIST_SIZE {
        let mod_value = 1u32 << (2 * i); // 4, 16, 64 for i = 1, 2, 3
        if ledger_seq % mod_value == 0 {
            // We're at a boundary, use the prev_hash
            skip_list[i] = prev_hash.into();
        } else {
            // Copy from the previous skip list
            skip_list[i] = prev_skip_list[i].clone();
        }
    }

    skip_list
}

/// Get the ledger sequence that a skip list entry points to.
///
/// Returns `None` if the entry would point before genesis.
pub fn skip_list_target_seq(current_seq: u32, skip_index: usize) -> Option<u32> {
    if skip_index >= SKIP_LIST_SIZE {
        return None;
    }

    let delta = match skip_index {
        0 => 1, // Previous ledger
        1 => {
            // Points back by at most 4
            let rem = current_seq % 4;
            if rem == 0 {
                4
            } else {
                rem
            }
        }
        2 => {
            // Points back by at most 16
            let rem = current_seq % 16;
            if rem == 0 {
                16
            } else {
                rem
            }
        }
        3 => {
            // Points back by at most 64
            let rem = current_seq % 64;
            if rem == 0 {
                64
            } else {
                rem
            }
        }
        _ => return None,
    };

    if current_seq >= delta {
        Some(current_seq - delta)
    } else {
        None
    }
}

/// Verify that a ledger header correctly chains to a previous header.
///
/// Checks that:
/// - The sequence number is exactly one more than the previous
/// - The previous ledger hash matches the hash of the previous header
pub fn verify_header_chain(
    prev_header: &LedgerHeader,
    prev_header_hash: &Hash256,
    current_header: &LedgerHeader,
) -> Result<()> {
    // Check sequence numbers
    let expected_seq = prev_header.ledger_seq + 1;
    if current_header.ledger_seq != expected_seq {
        return Err(LedgerError::InvalidSequence {
            expected: expected_seq,
            actual: current_header.ledger_seq,
        });
    }

    // Check that previous hash matches
    let current_prev_hash = Hash256::from(current_header.previous_ledger_hash.0);
    if &current_prev_hash != prev_header_hash {
        return Err(LedgerError::HashMismatch {
            expected: prev_header_hash.to_hex(),
            actual: current_prev_hash.to_hex(),
        });
    }

    Ok(())
}

/// Verify the skip list of a header against previous headers.
///
/// This validates that each skip list entry correctly points to the
/// expected historical header.
pub fn verify_skip_list(
    header: &LedgerHeader,
    get_header_at_seq: impl Fn(u32) -> Option<Hash256>,
) -> Result<()> {
    for (i, skip_hash) in header.skip_list.iter().enumerate() {
        let skip_hash256 = Hash256::from(skip_hash.0);

        // Skip verification for zero hashes (genesis or very early ledgers)
        if skip_hash256.is_zero() {
            continue;
        }

        if let Some(target_seq) = skip_list_target_seq(header.ledger_seq, i) {
            if let Some(expected_hash) = get_header_at_seq(target_seq) {
                if skip_hash256 != expected_hash {
                    return Err(LedgerError::InvalidHeaderChain(format!(
                        "skip list entry {} mismatch at seq {}: expected {}, got {}",
                        i,
                        target_seq,
                        expected_hash.to_hex(),
                        skip_hash256.to_hex()
                    )));
                }
            }
        }
    }

    Ok(())
}

/// Create a new ledger header for the next ledger in the chain.
pub fn create_next_header(
    prev_header: &LedgerHeader,
    prev_header_hash: Hash256,
    close_time: u64,
    tx_set_hash: Hash256,
    bucket_list_hash: Hash256,
    tx_set_result_hash: Hash256,
    total_coins: i64,
    fee_pool: i64,
    inflation_seq: u32,
) -> LedgerHeader {
    let new_seq = prev_header.ledger_seq + 1;
    let skip_list = compute_skip_list(new_seq, prev_header_hash, &prev_header.skip_list);

    LedgerHeader {
        ledger_version: prev_header.ledger_version,
        previous_ledger_hash: prev_header_hash.into(),
        scp_value: stellar_xdr::curr::StellarValue {
            tx_set_hash: tx_set_hash.into(),
            close_time: stellar_xdr::curr::TimePoint(close_time),
            upgrades: stellar_xdr::curr::VecM::default(),
            ext: stellar_xdr::curr::StellarValueExt::Basic,
        },
        tx_set_result_hash: tx_set_result_hash.into(),
        bucket_list_hash: bucket_list_hash.into(),
        ledger_seq: new_seq,
        total_coins,
        fee_pool,
        inflation_seq,
        id_pool: prev_header.id_pool,
        base_fee: prev_header.base_fee,
        base_reserve: prev_header.base_reserve,
        max_tx_set_size: prev_header.max_tx_set_size,
        skip_list,
        ext: stellar_xdr::curr::LedgerHeaderExt::V0,
    }
}

/// Extract the ledger close time from a header.
pub fn close_time(header: &LedgerHeader) -> u64 {
    header.scp_value.close_time.0
}

/// Extract the protocol version from a header.
pub fn protocol_version(header: &LedgerHeader) -> u32 {
    header.ledger_version
}

/// Check if a header is from before a given protocol version.
pub fn is_before_protocol_version(header: &LedgerHeader, version: u32) -> bool {
    header.ledger_version < version
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_header(seq: u32) -> LedgerHeader {
        LedgerHeader {
            ledger_version: 20,
            previous_ledger_hash: Hash([0u8; 32]),
            scp_value: stellar_xdr::curr::StellarValue {
                tx_set_hash: Hash([0u8; 32]),
                close_time: stellar_xdr::curr::TimePoint(1000 + seq as u64),
                upgrades: stellar_xdr::curr::VecM::default(),
                ext: stellar_xdr::curr::StellarValueExt::Basic,
            },
            tx_set_result_hash: Hash([0u8; 32]),
            bucket_list_hash: Hash([0u8; 32]),
            ledger_seq: seq,
            total_coins: 100_000_000_000_000_000,
            fee_pool: 0,
            inflation_seq: 0,
            id_pool: 0,
            base_fee: 100,
            base_reserve: 5_000_000,
            max_tx_set_size: 1000,
            skip_list: std::array::from_fn(|_| Hash([0u8; 32])),
            ext: stellar_xdr::curr::LedgerHeaderExt::V0,
        }
    }

    #[test]
    fn test_compute_header_hash() {
        let header = create_test_header(1);
        let hash = compute_header_hash(&header).unwrap();
        assert!(!hash.is_zero());

        // Same header should produce same hash
        let hash2 = compute_header_hash(&header).unwrap();
        assert_eq!(hash, hash2);

        // Different header should produce different hash
        let header2 = create_test_header(2);
        let hash3 = compute_header_hash(&header2).unwrap();
        assert_ne!(hash, hash3);
    }

    #[test]
    fn test_skip_list_target_seq() {
        // Entry 0 always points to previous
        assert_eq!(skip_list_target_seq(10, 0), Some(9));
        assert_eq!(skip_list_target_seq(1, 0), Some(0));

        // Entry 1 points back by at most 4
        assert_eq!(skip_list_target_seq(8, 1), Some(4)); // 8 - 4 = 4
        assert_eq!(skip_list_target_seq(10, 1), Some(8)); // 10 - 2 = 8

        // Edge case: sequence 0
        assert_eq!(skip_list_target_seq(0, 0), None);
    }

    #[test]
    fn test_compute_skip_list() {
        let prev_hash = Hash256::hash(b"test");
        let prev_skip = std::array::from_fn(|_| Hash([0u8; 32]));

        let skip_list = compute_skip_list(1, prev_hash, &prev_skip);
        assert_eq!(Hash256::from(skip_list[0].0), prev_hash);
    }
}
