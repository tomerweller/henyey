//! Invariant framework for rs-stellar-core.

use stellar_core_common::Hash256;
use stellar_xdr::curr::{LedgerEntry, LedgerEntryData, LedgerHeader};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum InvariantError {
    #[error("invariant {name} failed: {details}")]
    Violated { name: String, details: String },
}

/// Context passed to invariants.
pub struct InvariantContext<'a> {
    pub prev_header: &'a LedgerHeader,
    pub curr_header: &'a LedgerHeader,
    pub bucket_list_hash: Hash256,
    pub fee_pool_delta: i64,
    pub total_coins_delta: i64,
    pub changed_entries: &'a [LedgerEntry],
}

pub trait Invariant: Send + Sync {
    fn name(&self) -> &str;
    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError>;
}

pub struct InvariantManager {
    invariants: Vec<Box<dyn Invariant>>,
}

impl InvariantManager {
    pub fn new() -> Self {
        Self { invariants: Vec::new() }
    }

    pub fn add<I: Invariant + 'static>(&mut self, invariant: I) {
        self.invariants.push(Box::new(invariant));
    }

    pub fn check_all(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        for inv in &self.invariants {
            inv.check(ctx)?;
        }
        Ok(())
    }
}

/// Invariant: ledger sequence increments by 1.
pub struct LedgerSeqIncrement;

impl Invariant for LedgerSeqIncrement {
    fn name(&self) -> &str {
        "LedgerSeqIncrement"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        if ctx.curr_header.ledger_seq != ctx.prev_header.ledger_seq + 1 {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: format!(
                    "expected seq {}, got {}",
                    ctx.prev_header.ledger_seq + 1,
                    ctx.curr_header.ledger_seq
                ),
            });
        }
        Ok(())
    }
}

/// Invariant: bucket list hash matches header field.
pub struct BucketListHashMatchesHeader;

impl Invariant for BucketListHashMatchesHeader {
    fn name(&self) -> &str {
        "BucketListHashMatchesHeader"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let header_hash = Hash256::from(ctx.curr_header.bucket_list_hash.0);
        if header_hash != ctx.bucket_list_hash {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: "bucket list hash mismatch".to_string(),
            });
        }
        Ok(())
    }
}

/// Invariant: ledger total coins and fee pool follow the recorded deltas.
pub struct ConservationOfLumens;

impl Invariant for ConservationOfLumens {
    fn name(&self) -> &str {
        "ConservationOfLumens"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let expected_total = ctx
            .prev_header
            .total_coins
            .checked_add(ctx.total_coins_delta)
            .ok_or_else(|| InvariantError::Violated {
                name: self.name().to_string(),
                details: "total coins overflow".to_string(),
            })?;
        if ctx.curr_header.total_coins != expected_total {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: format!(
                    "total_coins mismatch: expected {}, got {}",
                    expected_total, ctx.curr_header.total_coins
                ),
            });
        }

        let expected_fee_pool = ctx
            .prev_header
            .fee_pool
            .checked_add(ctx.fee_pool_delta)
            .ok_or_else(|| InvariantError::Violated {
                name: self.name().to_string(),
                details: "fee pool overflow".to_string(),
            })?;
        if ctx.curr_header.fee_pool != expected_fee_pool {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: format!(
                    "fee_pool mismatch: expected {}, got {}",
                    expected_fee_pool, ctx.curr_header.fee_pool
                ),
            });
        }

        Ok(())
    }
}

/// Invariant: basic ledger entry sanity checks.
pub struct LedgerEntryIsValid;

impl Invariant for LedgerEntryIsValid {
    fn name(&self) -> &str {
        "LedgerEntryIsValid"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        for entry in ctx.changed_entries {
            match &entry.data {
                LedgerEntryData::Account(account) => {
                    if account.balance < 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "account balance negative".to_string(),
                        });
                    }
                }
                LedgerEntryData::Trustline(trust) => {
                    if trust.balance < 0 || trust.balance > trust.limit {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "trustline balance out of range".to_string(),
                        });
                    }
                }
                LedgerEntryData::Offer(offer) => {
                    if offer.amount < 0 {
                        return Err(InvariantError::Violated {
                            name: self.name().to_string(),
                            details: "offer amount negative".to_string(),
                        });
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }
}

/// Invariant: ledger close time does not move backwards.
pub struct CloseTimeNondecreasing;

impl Invariant for CloseTimeNondecreasing {
    fn name(&self) -> &str {
        "CloseTimeNondecreasing"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let prev = ctx.prev_header.scp_value.close_time.0;
        let curr = ctx.curr_header.scp_value.close_time.0;
        if curr < prev {
            return Err(InvariantError::Violated {
                name: self.name().to_string(),
                details: format!("close_time decreased: {} -> {}", prev, curr),
            });
        }
        Ok(())
    }
}

/// Invariant: ledger entry last_modified_ledger_seq matches current header.
pub struct LastModifiedLedgerSeqMatchesHeader;

impl Invariant for LastModifiedLedgerSeqMatchesHeader {
    fn name(&self) -> &str {
        "LastModifiedLedgerSeqMatchesHeader"
    }

    fn check(&self, ctx: &InvariantContext) -> Result<(), InvariantError> {
        let expected = ctx.curr_header.ledger_seq;
        for entry in ctx.changed_entries {
            if entry.last_modified_ledger_seq != expected {
                return Err(InvariantError::Violated {
                    name: self.name().to_string(),
                    details: format!(
                        "last_modified_ledger_seq mismatch: expected {}, got {}",
                        expected, entry.last_modified_ledger_seq
                    ),
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stellar_xdr::curr::{Hash, LedgerHeaderExt, StellarValue, StellarValueExt, TimePoint, VecM};

    fn make_header(seq: u32, bucket_hash: Hash256) -> LedgerHeader {
        LedgerHeader {
            ledger_version: 25,
            previous_ledger_hash: Hash([0u8; 32]),
            scp_value: StellarValue {
                tx_set_hash: Hash([0u8; 32]),
                close_time: TimePoint(0),
                upgrades: VecM::default(),
                ext: StellarValueExt::Basic,
            },
            tx_set_result_hash: Hash([0u8; 32]),
            bucket_list_hash: Hash(*bucket_hash.as_bytes()),
            ledger_seq: seq,
            total_coins: 1,
            fee_pool: 0,
            inflation_seq: 0,
            id_pool: 0,
            base_fee: 100,
            base_reserve: 100,
            max_tx_set_size: 100,
            skip_list: [
                Hash([0u8; 32]),
                Hash([0u8; 32]),
                Hash([0u8; 32]),
                Hash([0u8; 32]),
            ],
            ext: LedgerHeaderExt::V0,
        }
    }

    #[test]
    fn test_invariant_manager() {
        let prev = make_header(1, Hash256::ZERO);
        let curr = make_header(2, Hash256::ZERO);
        let entries: Vec<LedgerEntry> = Vec::new();
        let ctx = InvariantContext {
            prev_header: &prev,
            curr_header: &curr,
            bucket_list_hash: Hash256::ZERO,
            fee_pool_delta: 0,
            total_coins_delta: 0,
            changed_entries: &entries,
        };

        let mut manager = InvariantManager::new();
        manager.add(LedgerSeqIncrement);
        manager.add(BucketListHashMatchesHeader);
        manager.add(ConservationOfLumens);
        manager.add(LedgerEntryIsValid);

        assert!(manager.check_all(&ctx).is_ok());
    }
}
