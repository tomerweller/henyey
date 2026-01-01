//! SCP history queries.

use rusqlite::{params, Connection, OptionalExtension};
use stellar_core_common::Hash256;
use stellar_xdr::curr::{Limits, NodeId, PublicKey, ReadXdr, ScpEnvelope, ScpQuorumSet, Uint256, WriteXdr};

use super::super::error::DbError;

/// Trait for querying and storing SCP history.
pub trait ScpQueries {
    /// Store SCP envelopes for a ledger (replaces existing entries).
    fn store_scp_history(&self, ledger_seq: u32, envelopes: &[ScpEnvelope]) -> Result<(), DbError>;

    /// Load SCP envelopes for a ledger.
    fn load_scp_history(&self, ledger_seq: u32) -> Result<Vec<ScpEnvelope>, DbError>;

    /// Store a quorum set by hash, updating last-seen ledger sequence.
    fn store_scp_quorum_set(
        &self,
        hash: &Hash256,
        last_ledger_seq: u32,
        quorum_set: &ScpQuorumSet,
    ) -> Result<(), DbError>;

    /// Load a quorum set by hash.
    fn load_scp_quorum_set(&self, hash: &Hash256) -> Result<Option<ScpQuorumSet>, DbError>;
}

impl ScpQueries for Connection {
    fn store_scp_history(&self, ledger_seq: u32, envelopes: &[ScpEnvelope]) -> Result<(), DbError> {
        self.execute(
            "DELETE FROM scphistory WHERE ledgerseq = ?1",
            params![ledger_seq],
        )?;

        if envelopes.is_empty() {
            return Ok(());
        }

        let mut ordered = envelopes.to_vec();
        ordered.sort_by_key(|env| node_id_hex(&env.statement.node_id));

        for envelope in ordered {
            let node_id = node_id_hex(&envelope.statement.node_id);
            let data = envelope.to_xdr(Limits::none())?;
            self.execute(
                "INSERT INTO scphistory (nodeid, ledgerseq, envelope) VALUES (?1, ?2, ?3)",
                params![node_id, ledger_seq, data],
            )?;
        }

        Ok(())
    }

    fn load_scp_history(&self, ledger_seq: u32) -> Result<Vec<ScpEnvelope>, DbError> {
        let mut stmt = self.prepare(
            "SELECT envelope FROM scphistory WHERE ledgerseq = ?1 ORDER BY nodeid",
        )?;
        let rows = stmt.query_map(params![ledger_seq], |row| row.get::<_, Vec<u8>>(0))?;
        let mut envelopes = Vec::new();
        for row in rows {
            let data = row?;
            let envelope = ScpEnvelope::from_xdr(data.as_slice(), Limits::none())?;
            envelopes.push(envelope);
        }
        Ok(envelopes)
    }

    fn store_scp_quorum_set(
        &self,
        hash: &Hash256,
        last_ledger_seq: u32,
        quorum_set: &ScpQuorumSet,
    ) -> Result<(), DbError> {
        let hash_hex = hash.to_hex();
        let existing: Option<u32> = self
            .query_row(
                "SELECT lastledgerseq FROM scpquorums WHERE qsethash = ?1",
                params![hash_hex],
                |row| row.get(0),
            )
            .optional()?;

        if let Some(last_seen) = existing {
            if last_seen >= last_ledger_seq {
                return Ok(());
            }
            self.execute(
                "UPDATE scpquorums SET lastledgerseq = ?1 WHERE qsethash = ?2",
                params![last_ledger_seq, hash_hex],
            )?;
            return Ok(());
        }

        let data = quorum_set.to_xdr(Limits::none())?;
        self.execute(
            "INSERT INTO scpquorums (qsethash, lastledgerseq, qset) VALUES (?1, ?2, ?3)",
            params![hash_hex, last_ledger_seq, data],
        )?;
        Ok(())
    }

    fn load_scp_quorum_set(&self, hash: &Hash256) -> Result<Option<ScpQuorumSet>, DbError> {
        let hash_hex = hash.to_hex();
        let result: Option<Vec<u8>> = self
            .query_row(
                "SELECT qset FROM scpquorums WHERE qsethash = ?1",
                params![hash_hex],
                |row| row.get(0),
            )
            .optional()?;
        match result {
            Some(data) => Ok(Some(ScpQuorumSet::from_xdr(data.as_slice(), Limits::none())?)),
            None => Ok(None),
        }
    }
}

fn node_id_hex(node_id: &NodeId) -> String {
    match &node_id.0 {
        PublicKey::PublicKeyTypeEd25519(Uint256(bytes)) => hex::encode(bytes),
    }
}
