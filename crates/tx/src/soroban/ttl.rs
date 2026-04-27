//! Ledger sequence arithmetic for Soroban TTL targets.
//!
//! stellar-core uses unchecked `uint32_t` math for these expressions. Rust must use
//! [`u32::wrapping_add`] / [`u32::wrapping_sub`] for parity (see issue #1951).

/// Target live-until ledger for ExtendFootprintTtl (`ledgerSeq + extendTo`).
///
/// Matches stellar-core `ExtendFootprintTTLOpFrame.cpp`: `getLedgerSeq() + extendTo`.
#[must_use]
#[inline]
pub fn extend_ttl_target(ledger_seq: u32, extend_to: u32) -> u32 {
    ledger_seq.wrapping_add(extend_to)
}

/// Target live-until ledger for restore paths (`RestoreFootprint`, invoke archived restore).
///
/// Matches stellar-core `RestoreFootprintOpFrame.cpp`:
/// `restoredLiveUntilLedger = ledgerSeq + minPersistentTTL - 1`.
#[must_use]
#[inline]
pub fn restore_ttl_target(ledger_seq: u32, min_persistent_ttl: u32) -> u32 {
    ledger_seq.wrapping_add(min_persistent_ttl).wrapping_sub(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extend_ttl_target_overflow_matches_uint32_wrap() {
        assert_eq!(extend_ttl_target(u32::MAX - 5, 10), 4);
        assert_eq!(extend_ttl_target(u32::MAX, 1), 0);
    }

    #[test]
    fn restore_ttl_target_overflow_matches_uint32_wrap() {
        assert_eq!(restore_ttl_target(u32::MAX - 5, 10), 3);
    }

    #[test]
    fn extend_and_restore_normal_range() {
        assert_eq!(extend_ttl_target(100, 50), 150);
        assert_eq!(restore_ttl_target(100, 10), 109);
    }
}
