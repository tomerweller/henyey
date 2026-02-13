use super::*;

pub(super) fn sort_txs_by_hash(txs: &mut [TransactionEnvelope]) {
    txs.sort_by(|a, b| {
        let hash_a = Hash256::hash_xdr(a).unwrap_or_default();
        let hash_b = Hash256::hash_xdr(b).unwrap_or_default();
        hash_a.0.cmp(&hash_b.0)
    });
}

/// A set of transactions for a ledger.
#[derive(Debug, Clone)]
pub struct TransactionSet {
    /// Hash of this transaction set.
    pub hash: Hash256,
    /// Previous ledger hash.
    pub previous_ledger_hash: Hash256,
    /// Transactions in the set.
    pub transactions: Vec<TransactionEnvelope>,
    /// Generalized transaction set (protocol 20+), if available.
    pub generalized_tx_set: Option<GeneralizedTransactionSet>,
}

impl TransactionSet {
    /// Compute the legacy TransactionSet contents hash (non-generalized).
    pub fn compute_non_generalized_hash(
        previous_ledger_hash: Hash256,
        transactions: &[TransactionEnvelope],
    ) -> Option<Hash256> {
        let mut hasher = Sha256Hasher::new();
        hasher.update(&previous_ledger_hash.0);
        for tx in transactions {
            let bytes = tx.to_xdr(Limits::none()).ok()?;
            hasher.update(&bytes);
        }
        Some(hasher.finalize())
    }

    /// Create a new transaction set with computed hash (for legacy TransactionSet).
    pub fn new(previous_ledger_hash: Hash256, transactions: Vec<TransactionEnvelope>) -> Self {
        let mut transactions = transactions;
        sort_txs_by_hash(&mut transactions);
        let hash = Self::compute_non_generalized_hash(previous_ledger_hash, &transactions)
            .unwrap_or_default();

        Self {
            hash,
            previous_ledger_hash,
            transactions,
            generalized_tx_set: None,
        }
    }

    /// Create a transaction set with a pre-computed hash (for GeneralizedTransactionSet).
    /// The hash should be SHA-256 of the XDR-encoded GeneralizedTransactionSet.
    pub fn with_hash(
        previous_ledger_hash: Hash256,
        hash: Hash256,
        transactions: Vec<TransactionEnvelope>,
    ) -> Self {
        Self {
            hash,
            previous_ledger_hash,
            transactions,
            generalized_tx_set: None,
        }
    }

    pub fn with_generalized(
        previous_ledger_hash: Hash256,
        hash: Hash256,
        transactions: Vec<TransactionEnvelope>,
        generalized_tx_set: GeneralizedTransactionSet,
    ) -> Self {
        Self {
            hash,
            previous_ledger_hash,
            transactions,
            generalized_tx_set: Some(generalized_tx_set),
        }
    }

    /// Get the number of transactions.
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Recompute the transaction set hash from its contents.
    pub fn recompute_hash(&self) -> Option<Hash256> {
        if let Some(gen) = &self.generalized_tx_set {
            let bytes = gen.to_xdr(stellar_xdr::curr::Limits::none()).ok()?;
            return Some(Hash256::hash(&bytes));
        }
        Self::compute_non_generalized_hash(self.previous_ledger_hash, &self.transactions)
    }

    /// Summarize the transaction set for logging/debugging.
    pub fn summary(&self) -> String {
        if self.transactions.is_empty() {
            return "empty tx set".to_string();
        }

        if let Some(gen) = &self.generalized_tx_set {
            return summary_generalized_tx_set(gen);
        }

        let tx_count = self.transactions.len();
        let op_count: i64 = self.transactions.iter().map(tx_operation_count).sum();
        let base_fee = self
            .transactions
            .iter()
            .map(tx_inclusion_fee)
            .zip(self.transactions.iter().map(tx_operation_count))
            .filter(|(_, ops)| *ops > 0)
            .map(|(fee, ops)| fee / ops)
            .min()
            .unwrap_or(0);

        format!("txs:{}, ops:{}, base_fee:{}", tx_count, op_count, base_fee)
    }

    /// Convert to StoredTransactionSet XDR for persistence.
    ///
    /// Uses the generalized format (v1) if available, otherwise falls back to legacy (v0).
    pub fn to_xdr_stored_set(&self) -> stellar_xdr::curr::StoredTransactionSet {
        use stellar_xdr::curr::StoredTransactionSet;

        if let Some(ref gen) = self.generalized_tx_set {
            StoredTransactionSet::V1(gen.clone())
        } else {
            // Build legacy TransactionSet
            let legacy = stellar_xdr::curr::TransactionSet {
                previous_ledger_hash: stellar_xdr::curr::Hash(self.previous_ledger_hash.0),
                txs: self.transactions.clone().try_into().unwrap_or_default(),
            };
            StoredTransactionSet::V0(legacy)
        }
    }

    /// Create from StoredTransactionSet XDR.
    ///
    /// # Errors
    ///
    /// Returns an error description if the transaction set cannot be decoded.
    pub fn from_xdr_stored_set(
        stored: &stellar_xdr::curr::StoredTransactionSet,
    ) -> std::result::Result<Self, String> {
        use stellar_xdr::curr::StoredTransactionSet;

        match stored {
            StoredTransactionSet::V0(legacy) => {
                let previous_ledger_hash = Hash256::from_bytes(legacy.previous_ledger_hash.0);
                let transactions: Vec<TransactionEnvelope> = legacy.txs.to_vec();

                // Compute hash
                let hash = Self::compute_non_generalized_hash(previous_ledger_hash, &transactions)
                    .ok_or_else(|| "Failed to compute tx set hash".to_string())?;

                Ok(Self {
                    hash,
                    previous_ledger_hash,
                    transactions,
                    generalized_tx_set: None,
                })
            }
            StoredTransactionSet::V1(gen) => {
                let previous_ledger_hash = match gen {
                    GeneralizedTransactionSet::V1(v1) => {
                        Hash256::from_bytes(v1.previous_ledger_hash.0)
                    }
                };

                // Extract transactions from phases
                let transactions = extract_transactions_from_generalized(gen);

                // Compute hash from generalized format
                let hash = gen
                    .to_xdr(Limits::none())
                    .map(|bytes| Hash256::hash(&bytes))
                    .map_err(|e| format!("Failed to encode generalized tx set: {}", e))?;

                Ok(Self {
                    hash,
                    previous_ledger_hash,
                    transactions,
                    generalized_tx_set: Some(gen.clone()),
                })
            }
        }
    }

    /// Prepare a transaction set for ledger application.
    ///
    /// This corresponds to upstream `TxSetXDRFrame::prepareForApply()`. It validates
    /// the XDR structure of the generalized transaction set, deserializes transaction
    /// envelopes, validates that each transaction has a valid fee structure, checks
    /// that transactions are properly sorted within components/clusters, and verifies
    /// that classic and Soroban transactions are in the correct phases.
    ///
    /// For legacy (non-generalized) transaction sets, only basic fee validation and
    /// sort order checks are performed.
    pub fn prepare_for_apply(
        &self,
        network_id: NetworkId,
    ) -> std::result::Result<Self, String> {
        if let Some(ref gen) = self.generalized_tx_set {
            Self::prepare_generalized_for_apply(gen, network_id)
        } else {
            Self::prepare_legacy_for_apply(
                self.previous_ledger_hash,
                &self.transactions,
                network_id,
            )
        }
    }

    /// Validate and prepare a generalized transaction set for application.
    fn prepare_generalized_for_apply(
        gen: &GeneralizedTransactionSet,
        network_id: NetworkId,
    ) -> std::result::Result<Self, String> {
        validate_generalized_tx_set_xdr_structure(gen)?;

        let GeneralizedTransactionSet::V1(v1) = gen;
        let mut all_transactions = Vec::new();

        for (phase_id, phase) in v1.phases.iter().enumerate() {
            let expect_soroban = phase_id == 1;
            match phase {
                TransactionPhase::V0(components) => {
                    for component in components.iter() {
                        match component {
                            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                                validate_wire_txs(&comp.txs, network_id, expect_soroban)?;
                                all_transactions.extend(comp.txs.iter().cloned());
                            }
                        }
                    }
                }
                TransactionPhase::V1(parallel) => {
                    for stage in parallel.execution_stages.iter() {
                        for cluster in stage.iter() {
                            validate_wire_txs(
                                cluster.as_slice(),
                                network_id,
                                expect_soroban,
                            )?;
                            all_transactions.extend(cluster.iter().cloned());
                        }
                    }
                }
            }
        }

        let hash = gen
            .to_xdr(Limits::none())
            .map(|bytes| Hash256::hash(&bytes))
            .map_err(|e| format!("Failed to encode generalized tx set: {}", e))?;

        let previous_ledger_hash = Hash256::from_bytes(v1.previous_ledger_hash.0);

        Ok(Self {
            hash,
            previous_ledger_hash,
            transactions: all_transactions,
            generalized_tx_set: Some(gen.clone()),
        })
    }

    /// Validate and prepare a legacy (non-generalized) transaction set for application.
    fn prepare_legacy_for_apply(
        previous_ledger_hash: Hash256,
        transactions: &[TransactionEnvelope],
        network_id: NetworkId,
    ) -> std::result::Result<Self, String> {
        for env in transactions {
            validate_tx_fee(env)?;
            let frame =
                henyey_tx::TransactionFrame::with_network(env.clone(), network_id);
            if frame.is_soroban() {
                return Err(
                    "Legacy transaction set contains Soroban transaction".to_string(),
                );
            }
        }

        if !is_sorted_by_hash(transactions) {
            return Err(
                "Legacy transaction set transactions are not sorted correctly".to_string(),
            );
        }

        let hash =
            Self::compute_non_generalized_hash(previous_ledger_hash, transactions)
                .ok_or_else(|| "Failed to compute tx set hash".to_string())?;

        Ok(Self {
            hash,
            previous_ledger_hash,
            transactions: transactions.to_vec(),
            generalized_tx_set: None,
        })
    }
}


/// Maximum allowed Soroban resource fee (2^50), matching upstream MAX_RESOURCE_FEE.
const MAX_RESOURCE_FEE: i64 = 1i64 << 50;

/// Validate the XDR structure of a GeneralizedTransactionSet.
///
/// Mirrors upstream `validateTxSetXDRStructure`.
fn validate_generalized_tx_set_xdr_structure(
    gen: &GeneralizedTransactionSet,
) -> std::result::Result<(), String> {
    let GeneralizedTransactionSet::V1(v1) = gen;

    if v1.phases.len() != 2 {
        return Err(format!(
            "Expected exactly 2 phases, got {}",
            v1.phases.len()
        ));
    }

    for (phase_id, phase) in v1.phases.iter().enumerate() {
        match phase {
            TransactionPhase::V0(components) => {
                validate_sequential_phase_xdr_structure(components.as_slice())?;
            }
            TransactionPhase::V1(parallel) => {
                if phase_id != 1 {
                    return Err(format!(
                        "Non-Soroban parallel phase at index {}",
                        phase_id
                    ));
                }
                validate_parallel_component(parallel)?;
            }
        }
    }

    Ok(())
}

/// Validate the XDR structure of a sequential (V0) phase.
fn validate_sequential_phase_xdr_structure(
    components: &[TxSetComponent],
) -> std::result::Result<(), String> {
    let is_sorted = components.windows(2).all(|pair| {
        let fee_a = match &pair[0] {
            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) => c.base_fee,
        };
        let fee_b = match &pair[1] {
            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(c) => c.base_fee,
        };
        match (fee_a, fee_b) {
            (None, Some(_)) => true,
            (None, None) => false,
            (Some(_), None) => false,
            (Some(a), Some(b)) => a < b,
        }
    });
    if !is_sorted {
        return Err("Incorrect component order or duplicate base fees".to_string());
    }

    for component in components {
        match component {
            TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                if comp.txs.is_empty() {
                    return Err("Empty component in sequential phase".to_string());
                }
            }
        }
    }

    Ok(())
}

/// Validate the structure of a parallel (V1) phase component.
fn validate_parallel_component(
    parallel: &stellar_xdr::curr::ParallelTxsComponent,
) -> std::result::Result<(), String> {
    for stage in parallel.execution_stages.iter() {
        if stage.is_empty() {
            return Err("Empty stage in parallel phase".to_string());
        }
        for cluster in stage.iter() {
            if cluster.is_empty() {
                return Err("Empty cluster in parallel phase".to_string());
            }
        }
    }
    Ok(())
}

/// Validate that a transaction envelope has a valid fee for inclusion in a tx set.
///
/// Mirrors upstream `XDRProvidesValidFee`.
fn validate_tx_fee(env: &TransactionEnvelope) -> std::result::Result<(), String> {
    let is_soroban = match env {
        TransactionEnvelope::TxV0(e) => e.tx.operations.iter().any(|op| {
            matches!(
                op.body,
                stellar_xdr::curr::OperationBody::InvokeHostFunction(_)
                    | stellar_xdr::curr::OperationBody::ExtendFootprintTtl(_)
                    | stellar_xdr::curr::OperationBody::RestoreFootprint(_)
            )
        }),
        TransactionEnvelope::Tx(e) => e.tx.operations.iter().any(|op| {
            matches!(
                op.body,
                stellar_xdr::curr::OperationBody::InvokeHostFunction(_)
                    | stellar_xdr::curr::OperationBody::ExtendFootprintTtl(_)
                    | stellar_xdr::curr::OperationBody::RestoreFootprint(_)
            )
        }),
        TransactionEnvelope::TxFeeBump(e) => match &e.tx.inner_tx {
            FeeBumpTransactionInnerTx::Tx(inner) => inner.tx.operations.iter().any(|op| {
                matches!(
                    op.body,
                    stellar_xdr::curr::OperationBody::InvokeHostFunction(_)
                        | stellar_xdr::curr::OperationBody::ExtendFootprintTtl(_)
                        | stellar_xdr::curr::OperationBody::RestoreFootprint(_)
                )
            }),
        },
    };

    if is_soroban {
        match env {
            TransactionEnvelope::TxV0(_) => {
                return Err("Soroban transaction uses TxV0 envelope".to_string());
            }
            TransactionEnvelope::Tx(e) => match &e.tx.ext {
                stellar_xdr::curr::TransactionExt::V0 => {
                    return Err(
                        "Soroban transaction missing SorobanTransactionData".to_string(),
                    );
                }
                stellar_xdr::curr::TransactionExt::V1(data) => {
                    let resource_fee = data.resource_fee;
                    if resource_fee < 0 || resource_fee > MAX_RESOURCE_FEE {
                        return Err(format!(
                            "Soroban resource fee {} out of valid range",
                            resource_fee
                        ));
                    }
                }
            },
            TransactionEnvelope::TxFeeBump(e) => match &e.tx.inner_tx {
                FeeBumpTransactionInnerTx::Tx(inner) => match &inner.tx.ext {
                    stellar_xdr::curr::TransactionExt::V0 => {
                        return Err(
                            "Soroban fee-bump inner transaction missing SorobanTransactionData"
                                .to_string(),
                        );
                    }
                    stellar_xdr::curr::TransactionExt::V1(data) => {
                        let resource_fee = data.resource_fee;
                        if resource_fee < 0 || resource_fee > MAX_RESOURCE_FEE {
                            return Err(format!(
                                "Soroban resource fee {} out of valid range",
                                resource_fee
                            ));
                        }
                    }
                },
            },
        }
    }

    Ok(())
}

/// Check if a slice of transaction envelopes is sorted by hash.
fn is_sorted_by_hash(txs: &[TransactionEnvelope]) -> bool {
    txs.windows(2).all(|pair| {
        let hash_a = Hash256::hash_xdr(&pair[0]).unwrap_or_default();
        let hash_b = Hash256::hash_xdr(&pair[1]).unwrap_or_default();
        hash_a.0 <= hash_b.0
    })
}

/// Validate a set of wire-format transaction envelopes.
fn validate_wire_txs(
    txs: &[TransactionEnvelope],
    network_id: NetworkId,
    expect_soroban: bool,
) -> std::result::Result<(), String> {
    for env in txs {
        validate_tx_fee(env)?;

        let frame = henyey_tx::TransactionFrame::with_network(env.clone(), network_id);
        if frame.is_soroban() != expect_soroban {
            if expect_soroban {
                return Err("Classic transaction found in Soroban phase".to_string());
            } else {
                return Err("Soroban transaction found in classic phase".to_string());
            }
        }
    }

    if !is_sorted_by_hash(txs) {
        return Err("Transactions are not sorted correctly within component".to_string());
    }

    Ok(())
}

/// Extract all transactions from a GeneralizedTransactionSet.
fn extract_transactions_from_generalized(
    gen: &GeneralizedTransactionSet,
) -> Vec<TransactionEnvelope> {
    let GeneralizedTransactionSet::V1(v1) = gen;
    let mut transactions = Vec::new();

    for phase in v1.phases.iter() {
        match phase {
            stellar_xdr::curr::TransactionPhase::V0(components) => {
                for component in components.iter() {
                    match component {
                        stellar_xdr::curr::TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) => {
                            transactions.extend(comp.txs.iter().cloned());
                        }
                    }
                }
            }
            stellar_xdr::curr::TransactionPhase::V1(parallel) => {
                // V1 phase has execution_stages, which contains parallel stages
                for stage in parallel.execution_stages.iter() {
                    for cluster in stage.iter() {
                        transactions.extend(cluster.iter().cloned());
                    }
                }
            }
        }
    }

    transactions
}

fn tx_operation_count(envelope: &TransactionEnvelope) -> i64 {
    match envelope {
        TransactionEnvelope::TxV0(env) => env.tx.operations.len() as i64,
        TransactionEnvelope::Tx(env) => env.tx.operations.len() as i64,
        TransactionEnvelope::TxFeeBump(env) => match &env.tx.inner_tx {
            stellar_xdr::curr::FeeBumpTransactionInnerTx::Tx(inner) => {
                inner.tx.operations.len() as i64
            }
        },
    }
}

fn tx_inclusion_fee(envelope: &TransactionEnvelope) -> i64 {
    match envelope {
        TransactionEnvelope::TxV0(env) => env.tx.fee as i64,
        TransactionEnvelope::Tx(env) => env.tx.fee as i64,
        TransactionEnvelope::TxFeeBump(env) => env.tx.fee,
    }
}

fn summary_generalized_tx_set(gen: &GeneralizedTransactionSet) -> String {
    use std::collections::BTreeMap;

    let GeneralizedTransactionSet::V1(tx_set) = gen;
    if tx_set.phases.is_empty() {
        return "empty tx set".to_string();
    }

    let mut parts = Vec::new();
    for (phase_idx, phase) in tx_set.phases.iter().enumerate() {
        let mut component_stats: BTreeMap<Option<i64>, (i64, i64)> = BTreeMap::new();
        match phase {
            TransactionPhase::V0(components) => {
                for component in components.iter() {
                    let TxSetComponent::TxsetCompTxsMaybeDiscountedFee(comp) = component;
                    let base_fee = comp.base_fee;
                    for tx in comp.txs.iter() {
                        let entry = component_stats.entry(base_fee).or_insert((0, 0));
                        entry.0 += 1;
                        entry.1 += tx_operation_count(tx);
                    }
                }
            }
            TransactionPhase::V1(parallel) => {
                let base_fee = parallel.base_fee;
                for stage in parallel.execution_stages.iter() {
                    for cluster in stage.iter() {
                        for tx in cluster.0.iter() {
                            let entry = component_stats.entry(base_fee).or_insert((0, 0));
                            entry.0 += 1;
                            entry.1 += tx_operation_count(tx);
                        }
                    }
                }
            }
        }

        let mut component_parts = Vec::new();
        for (fee, stats) in component_stats.iter() {
            if let Some(base_fee) = fee {
                component_parts.push(format!(
                    "{{discounted txs:{}, ops:{}, base_fee:{}}}",
                    stats.0, stats.1, base_fee
                ));
            } else {
                component_parts.push(format!(
                    "{{non-discounted txs:{}, ops:{}}}",
                    stats.0, stats.1
                ));
            }
        }
        let phase_name = match phase_idx {
            0 => "classic",
            1 => "soroban",
            _ => "unknown",
        };
        parts.push(format!(
            "{} phase: {} component(s): [{}]",
            phase_name,
            component_stats.len(),
            component_parts.join(", ")
        ));
    }

    parts.join(", ")
}
