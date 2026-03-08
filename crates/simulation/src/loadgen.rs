//! Deterministic load and transaction generation for simulation workloads.

use henyey_common::Hash256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedTransaction {
    pub source: String,
    pub destination: String,
    pub sequence: u64,
    pub fee_bid: u32,
    pub amount: i64,
    pub nonce: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadStep {
    pub step_index: usize,
    pub transactions: Vec<GeneratedTransaction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedLoadConfig {
    pub accounts: Vec<String>,
    pub txs_per_step: usize,
    pub steps: usize,
    pub fee_bid: u32,
    pub amount: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadReport {
    pub total_steps: usize,
    pub total_transactions: usize,
}

pub struct TxGenerator;

impl TxGenerator {
    pub fn payment_series(
        accounts: &[String],
        start_sequence: u64,
        tx_count: usize,
        fee_bid: u32,
        amount: i64,
    ) -> Vec<GeneratedTransaction> {
        if accounts.len() < 2 || tx_count == 0 {
            return Vec::new();
        }

        let mut txs = Vec::with_capacity(tx_count);
        for i in 0..tx_count {
            let source = accounts[i % accounts.len()].clone();
            let destination = accounts[(i + 1) % accounts.len()].clone();
            let sequence = start_sequence + i as u64;
            let nonce =
                Hash256::hash(format!("{}:{}:{}", source, destination, sequence).as_bytes());
            txs.push(GeneratedTransaction {
                source,
                destination,
                sequence,
                fee_bid,
                amount,
                nonce,
            });
        }
        txs
    }
}

pub struct LoadGenerator;

impl LoadGenerator {
    pub fn step_plan(config: &GeneratedLoadConfig) -> Vec<LoadStep> {
        let mut steps = Vec::with_capacity(config.steps);
        let mut next_sequence = 1u64;
        for step_index in 0..config.steps {
            let transactions = TxGenerator::payment_series(
                &config.accounts,
                next_sequence,
                config.txs_per_step,
                config.fee_bid,
                config.amount,
            );
            next_sequence += transactions.len() as u64;
            steps.push(LoadStep {
                step_index,
                transactions,
            });
        }
        steps
    }

    pub fn summarize(steps: &[LoadStep]) -> LoadReport {
        LoadReport {
            total_steps: steps.len(),
            total_transactions: steps.iter().map(|s| s.transactions.len()).sum(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_series_is_deterministic() {
        let accounts = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let a = TxGenerator::payment_series(&accounts, 1, 5, 100, 10);
        let b = TxGenerator::payment_series(&accounts, 1, 5, 100, 10);
        assert_eq!(a, b);
    }

    #[test]
    fn step_plan_counts_transactions() {
        let config = GeneratedLoadConfig {
            accounts: vec!["a".to_string(), "b".to_string()],
            txs_per_step: 3,
            steps: 4,
            fee_bid: 100,
            amount: 10,
        };
        let steps = LoadGenerator::step_plan(&config);
        let report = LoadGenerator::summarize(&steps);
        assert_eq!(report.total_steps, 4);
        assert_eq!(report.total_transactions, 12);
    }
}
