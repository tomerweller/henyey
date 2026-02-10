//! Soroban contract event handling.
//!
//! Records events emitted during contract execution.

use stellar_xdr::curr::{ContractId, Hash, ScVal, WriteXdr};

/// Type of contract event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    /// Regular contract event.
    Contract,
    /// System event (created/deleted entries).
    System,
    /// Diagnostic event (debug info).
    Diagnostic,
}

/// A contract event emitted during execution.
#[derive(Debug, Clone)]
pub struct ContractEvent {
    /// The type of event.
    pub event_type: EventType,
    /// The contract that emitted the event.
    pub contract_id: Option<ContractId>,
    /// Event topics (indexed fields).
    pub topics: Vec<ScVal>,
    /// Event data.
    pub data: ScVal,
}

impl ContractEvent {
    /// Create a new contract event.
    pub fn new(
        event_type: EventType,
        contract_id: Option<ContractId>,
        topics: Vec<ScVal>,
        data: ScVal,
    ) -> Self {
        Self {
            event_type,
            contract_id,
            topics,
            data,
        }
    }

    /// Create a system event for entry creation.
    pub fn entry_created(contract_id: &ContractId, key: &ScVal) -> Self {
        Self {
            event_type: EventType::System,
            contract_id: Some(contract_id.clone()),
            topics: vec![ScVal::Symbol(
                "entry_created".try_into().unwrap_or_default(),
            )],
            data: key.clone(),
        }
    }

    /// Create a system event for entry deletion.
    pub fn entry_deleted(contract_id: &ContractId, key: &ScVal) -> Self {
        Self {
            event_type: EventType::System,
            contract_id: Some(contract_id.clone()),
            topics: vec![ScVal::Symbol(
                "entry_deleted".try_into().unwrap_or_default(),
            )],
            data: key.clone(),
        }
    }

    /// Compute the hash of this event.
    pub fn hash(&self) -> Hash {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        // Hash event type
        hasher.update([self.event_type as u8]);

        // Hash contract ID if present
        if let Some(ref id) = self.contract_id {
            hasher.update(id.0 .0);
        }

        // Hash topics
        for topic in &self.topics {
            if let Ok(bytes) = topic.to_xdr(stellar_xdr::curr::Limits::none()) {
                hasher.update(&bytes);
            }
        }

        // Hash data
        if let Ok(bytes) = self.data.to_xdr(stellar_xdr::curr::Limits::none()) {
            hasher.update(&bytes);
        }

        Hash(hasher.finalize().into())
    }
}

/// Collection of events from a contract execution.
#[derive(Debug, Clone, Default)]
pub struct ContractEvents {
    /// The events.
    events: Vec<ContractEvent>,
    /// Diagnostic events (not included in hash).
    diagnostic_events: Vec<ContractEvent>,
}

impl ContractEvents {
    /// Create an empty event collection.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an event.
    pub fn push(&mut self, event: ContractEvent) {
        if event.event_type == EventType::Diagnostic {
            self.diagnostic_events.push(event);
        } else {
            self.events.push(event);
        }
    }

    /// Get all non-diagnostic events.
    pub fn events(&self) -> &[ContractEvent] {
        &self.events
    }

    /// Get diagnostic events.
    pub fn diagnostic_events(&self) -> &[ContractEvent] {
        &self.diagnostic_events
    }

    /// Get the number of events.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Check if there are no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Compute the hash of all events.
    pub fn hash(&self) -> Hash {
        use sha2::{Digest, Sha256};

        if self.events.is_empty() {
            return Hash([0u8; 32]);
        }

        let mut hasher = Sha256::new();
        for event in &self.events {
            hasher.update(event.hash().0);
        }
        Hash(hasher.finalize().into())
    }

    /// Convert to XDR events vector.
    pub fn to_xdr(&self) -> Vec<stellar_xdr::curr::ContractEvent> {
        self.events
            .iter()
            .filter_map(|e| self.event_to_xdr(e))
            .collect()
    }

    fn event_to_xdr(&self, event: &ContractEvent) -> Option<stellar_xdr::curr::ContractEvent> {
        use stellar_xdr::curr::{
            ContractEvent as XdrContractEvent, ContractEventBody, ContractEventType,
            ContractEventV0, ExtensionPoint,
        };

        let event_type = match event.event_type {
            EventType::Contract => ContractEventType::Contract,
            EventType::System => ContractEventType::System,
            EventType::Diagnostic => ContractEventType::Diagnostic,
        };

        let body = ContractEventBody::V0(ContractEventV0 {
            topics: event.topics.clone().try_into().ok()?,
            data: event.data.clone(),
        });

        Some(XdrContractEvent {
            ext: ExtensionPoint::V0,
            contract_id: event.contract_id.clone(),
            type_: event_type,
            body,
        })
    }

    /// Clear all events.
    pub fn clear(&mut self) {
        self.events.clear();
        self.diagnostic_events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_creation() {
        let contract_id = ContractId(Hash([1u8; 32]));
        let event = ContractEvent::new(
            EventType::Contract,
            Some(contract_id),
            vec![ScVal::Symbol("transfer".try_into().unwrap())],
            ScVal::I64(1000),
        );

        assert_eq!(event.event_type, EventType::Contract);
        assert!(event.contract_id.is_some());
    }

    #[test]
    fn test_events_collection() {
        let mut events = ContractEvents::new();
        assert!(events.is_empty());

        let event = ContractEvent::new(EventType::Contract, None, vec![], ScVal::Void);
        events.push(event);

        assert_eq!(events.len(), 1);
        assert!(!events.is_empty());
    }

    #[test]
    fn test_diagnostic_events_separate() {
        let mut events = ContractEvents::new();

        events.push(ContractEvent::new(
            EventType::Contract,
            None,
            vec![],
            ScVal::Void,
        ));
        events.push(ContractEvent::new(
            EventType::Diagnostic,
            None,
            vec![],
            ScVal::Void,
        ));

        assert_eq!(events.events().len(), 1);
        assert_eq!(events.diagnostic_events().len(), 1);
    }

    /// Test system event for entry creation.
    #[test]
    fn test_entry_created_event() {
        let contract_id = ContractId(Hash([2u8; 32]));
        let key = ScVal::U32(42);
        let event = ContractEvent::entry_created(&contract_id, &key);

        assert_eq!(event.event_type, EventType::System);
        assert!(event.contract_id.is_some());
        assert_eq!(event.topics.len(), 1);
        assert!(matches!(event.data, ScVal::U32(42)));
    }

    /// Test system event for entry deletion.
    #[test]
    fn test_entry_deleted_event() {
        let contract_id = ContractId(Hash([3u8; 32]));
        let key = ScVal::I64(100);
        let event = ContractEvent::entry_deleted(&contract_id, &key);

        assert_eq!(event.event_type, EventType::System);
        assert!(event.contract_id.is_some());
        assert_eq!(event.topics.len(), 1);
        assert!(matches!(event.data, ScVal::I64(100)));
    }

    /// Test event hash computation.
    #[test]
    fn test_event_hash() {
        let event1 = ContractEvent::new(
            EventType::Contract,
            Some(ContractId(Hash([1u8; 32]))),
            vec![ScVal::I32(1)],
            ScVal::I64(100),
        );
        let event2 = ContractEvent::new(
            EventType::Contract,
            Some(ContractId(Hash([2u8; 32]))),
            vec![ScVal::I32(1)],
            ScVal::I64(100),
        );

        let hash1 = event1.hash();
        let hash2 = event2.hash();

        // Different contract IDs should produce different hashes
        assert_ne!(hash1, hash2);

        // Same event should produce same hash
        let hash1_again = event1.hash();
        assert_eq!(hash1, hash1_again);
    }

    /// Test events collection hash.
    #[test]
    fn test_events_collection_hash() {
        let mut events = ContractEvents::new();

        // Empty events should have zero hash
        let empty_hash = events.hash();
        assert_eq!(empty_hash, Hash([0u8; 32]));

        // Add an event
        events.push(ContractEvent::new(
            EventType::Contract,
            None,
            vec![],
            ScVal::I32(42),
        ));

        let hash = events.hash();
        assert_ne!(hash, Hash([0u8; 32]));
    }

    /// Test events clear.
    #[test]
    fn test_events_clear() {
        let mut events = ContractEvents::new();

        events.push(ContractEvent::new(
            EventType::Contract,
            None,
            vec![],
            ScVal::Void,
        ));
        events.push(ContractEvent::new(
            EventType::Diagnostic,
            None,
            vec![],
            ScVal::Void,
        ));

        assert_eq!(events.len(), 1);
        assert_eq!(events.diagnostic_events().len(), 1);

        events.clear();

        assert!(events.is_empty());
        assert!(events.diagnostic_events().is_empty());
    }

    /// Test to_xdr conversion.
    #[test]
    fn test_events_to_xdr() {
        let mut events = ContractEvents::new();

        events.push(ContractEvent::new(
            EventType::Contract,
            Some(ContractId(Hash([4u8; 32]))),
            vec![ScVal::Symbol("test".try_into().unwrap())],
            ScVal::U64(999),
        ));
        events.push(ContractEvent::new(
            EventType::System,
            None,
            vec![],
            ScVal::Void,
        ));

        let xdr_events = events.to_xdr();
        assert_eq!(xdr_events.len(), 2);
    }

    /// Test event without contract_id.
    #[test]
    fn test_event_no_contract_id() {
        let event = ContractEvent::new(
            EventType::Contract,
            None,
            vec![ScVal::Bool(true)],
            ScVal::I32(-1),
        );

        assert!(event.contract_id.is_none());
        // Hash should still work
        let hash = event.hash();
        assert_ne!(hash.0, [0u8; 32]);
    }

    /// Test event with multiple topics.
    #[test]
    fn test_event_multiple_topics() {
        let event = ContractEvent::new(
            EventType::Contract,
            Some(ContractId(Hash([5u8; 32]))),
            vec![
                ScVal::Symbol("transfer".try_into().unwrap()),
                ScVal::I64(100),
                ScVal::I64(200),
            ],
            ScVal::Bool(true),
        );

        assert_eq!(event.topics.len(), 3);
    }
}
