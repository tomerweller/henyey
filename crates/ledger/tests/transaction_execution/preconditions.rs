use super::*;

#[test]
fn test_execute_transaction_missing_operation() {
    let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
    let tx = Transaction {
        source_account: source,
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: VecM::default(),
        ext: TransactionExt::V0,
    };
    let envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let snapshot = LedgerSnapshot::empty(1);
    let snapshot = SnapshotHandle::new(snapshot);
    let context = henyey_tx::LedgerContext::new(
        1,
        1000,
        100,
        5_000_000,
        25,
        NetworkId::testnet(),
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        ClassicEventConfig::default(),
    );

    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");
    assert_eq!(result.failure, Some(ExecutionFailure::MissingOperation));
}

#[test]
fn test_execute_transaction_time_bounds_too_early() {
    let secret = SecretKey::from_seed(&[7u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry(account_id.clone(), 1, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: Preconditions::Time(TimeBounds {
            min_time: TimePoint(2_000),
            max_time: TimePoint(0),
        }),
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let context = henyey_tx::LedgerContext::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        classic_events,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::TooEarly));
}

#[test]
fn test_execute_transaction_min_seq_num_precondition() {
    let secret = SecretKey::from_seed(&[9u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry(account_id.clone(), 1, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: Some(SequenceNumber(5)),
        min_seq_age: Duration(0),
        min_seq_ledger_gap: 0,
        extra_signers: VecM::default(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let context = henyey_tx::LedgerContext::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        classic_events,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::BadMinSeqAgeOrGap));
}

/// Test that with minSeqNum set, sequence validation is relaxed.
/// Instead of requiring tx.seqNum == account.seqNum + 1,
/// it allows any tx.seqNum where account.seqNum >= minSeqNum AND account.seqNum < tx.seqNum
#[test]
fn test_execute_transaction_min_seq_num_relaxed_sequence() {
    let secret = SecretKey::from_seed(&[14u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    // Account has seq_num = 100
    let (key, entry) = create_account_entry(account_id.clone(), 100, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    // With minSeqNum = 50, account.seqNum (100) >= minSeqNum (50) is satisfied.
    // tx.seqNum = 105, account.seqNum (100) < tx.seqNum (105) is satisfied.
    // Without minSeqNum, this would fail because 100 + 1 != 105.
    // With minSeqNum, this should pass the sequence check.
    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: Some(SequenceNumber(50)),
        min_seq_age: Duration(0),
        min_seq_ledger_gap: 0,
        extra_signers: VecM::default(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(105), // Not account.seqNum + 1, but within valid range
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let context = henyey_tx::LedgerContext::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        ClassicEventConfig::default(),
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    // Should succeed (or at least not fail with BadSequence)
    // The tx might fail for other reasons (like destination doesn't exist),
    // but the sequence check should pass.
    assert!(
        result.failure != Some(ExecutionFailure::BadSequence),
        "Transaction should not fail with BadSequence when minSeqNum is set and sequence is in valid range"
    );
}

/// Test that without minSeqNum, the strict sequence check still applies.
#[test]
fn test_execute_transaction_strict_sequence_without_min_seq_num() {
    let secret = SecretKey::from_seed(&[15u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    // Account has seq_num = 100
    let (key, entry) = create_account_entry(account_id.clone(), 100, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    // Without minSeqNum, tx.seqNum must equal account.seqNum + 1.
    // tx.seqNum = 105, but account.seqNum + 1 = 101, so this should fail.
    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: None, // No minSeqNum
        min_seq_age: Duration(0),
        min_seq_ledger_gap: 0,
        extra_signers: VecM::default(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(105), // Wrong: should be 101
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let context = henyey_tx::LedgerContext::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        ClassicEventConfig::default(),
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    // Should fail with BadSequence because strict check: 100 + 1 != 105
    assert_eq!(
        result.failure,
        Some(ExecutionFailure::BadSequence),
        "Transaction should fail with BadSequence when minSeqNum is not set and sequence doesn't match"
    );
}

#[test]
fn test_execute_transaction_min_seq_age_precondition() {
    let secret = SecretKey::from_seed(&[12u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();
    let seq_ledger = 5;
    let seq_time = 900;

    // Create account with seq_time set (for min_seq_age checking)
    let (key, entry) =
        create_account_entry_with_seq_info(account_id.clone(), 1, 10_000_000, seq_ledger, seq_time);
    let snapshot = SnapshotBuilder::new(10)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    // min_seq_age = 200, close_time = 1000, seq_time = 900
    // Check: closeTime - minSeqAge < accSeqTime → 1000 - 200 < 900 → 800 < 900 → TRUE → FAIL
    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: None,
        min_seq_age: Duration(200),
        min_seq_ledger_gap: 0,
        extra_signers: VecM::default(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let context = henyey_tx::LedgerContext::new(
        10,
        1_000, // close_time
        100,
        5_000_000,
        25,
        network_id,
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        ClassicEventConfig::default(),
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::BadMinSeqAgeOrGap));
}

#[test]
fn test_execute_transaction_min_seq_ledger_gap_precondition() {
    let secret = SecretKey::from_seed(&[13u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();
    let seq_ledger = 8;
    let seq_time = 0;

    // Create account with seq_ledger set (for min_seq_ledger_gap checking)
    let (key, entry) =
        create_account_entry_with_seq_info(account_id.clone(), 1, 10_000_000, seq_ledger, seq_time);
    let snapshot = SnapshotBuilder::new(10)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    // min_seq_ledger_gap = 5, ledger_seq = 10, seq_ledger = 8
    // Check: ledgerSeq - minSeqLedgerGap < accSeqLedger → 10 - 5 < 8 → 5 < 8 → TRUE → FAIL
    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: None,
        min_seq_age: Duration(0),
        min_seq_ledger_gap: 5,
        extra_signers: VecM::default(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let context = henyey_tx::LedgerContext::new(
        10,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        ClassicEventConfig::default(),
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::BadMinSeqAgeOrGap));
}

#[test]
fn test_execute_transaction_extra_signers_missing() {
    let secret = SecretKey::from_seed(&[10u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry(account_id.clone(), 1, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([3u8; 32])));
    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let extra_signer = SignerKey::Ed25519(Uint256([4u8; 32]));
    let preconditions = Preconditions::V2(PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: None,
        min_seq_age: Duration(0),
        min_seq_ledger_gap: 0,
        extra_signers: vec![extra_signer].try_into().unwrap(),
    });

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 100,
        seq_num: SequenceNumber(2),
        cond: preconditions,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let context = henyey_tx::LedgerContext::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        classic_events,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert_eq!(result.failure, Some(ExecutionFailure::BadAuthExtra));
}

#[test]
fn test_fee_bump_result_encoding() {
    let source = MuxedAccount::Ed25519(Uint256([0u8; 32]));
    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([1u8; 32])));

    let operation = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination,
            starting_balance: 1_000_000,
        }),
    };

    let inner_tx = Transaction {
        source_account: source.clone(),
        fee: 100,
        seq_num: SequenceNumber(1),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![operation].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let inner_env = TransactionV1Envelope {
        tx: inner_tx,
        signatures: VecM::default(),
    };

    let fee_bump = FeeBumpTransaction {
        fee_source: source,
        fee: 200,
        inner_tx: FeeBumpTransactionInnerTx::Tx(inner_env),
        ext: stellar_xdr::curr::FeeBumpTransactionExt::V0,
    };

    let envelope = TransactionEnvelope::TxFeeBump(FeeBumpTransactionEnvelope {
        tx: fee_bump,
        signatures: VecM::default(),
    });

    let exec = henyey_ledger::execution::TransactionExecutionResult {
        success: true,
        fee_charged: 200,
        fee_refund: 0,
        operation_results: vec![OperationResult::OpInner(OperationResultTr::CreateAccount(
            CreateAccountResult::Success,
        ))],
        error: None,
        failure: None,
        tx_meta: None,
        fee_changes: None,
        post_fee_changes: None,
        hot_archive_restored_keys: vec![],
        op_type_timings: std::collections::HashMap::new(),
    };

    let pair = build_tx_result_pair(
        &henyey_tx::TransactionFrame::with_network(envelope, NetworkId::testnet()),
        &NetworkId::testnet(),
        &exec,
        100, // base_fee
        24,  // protocol_version
    )
    .expect("build tx result");

    match pair.result.result {
        TransactionResultResult::TxFeeBumpInnerSuccess(InnerTransactionResultPair { .. }) => {}
        other => panic!("unexpected fee bump result: {:?}", other),
    }
}

#[test]
fn test_operation_failure_rolls_back_changes() {
    let secret = SecretKey::from_seed(&[11u8; 32]);
    let account_id: AccountId = (&secret.public_key()).into();

    let (key, entry) = create_account_entry(account_id.clone(), 1, 10_000_000);
    let snapshot = SnapshotBuilder::new(1)
        .add_entry(key, entry)
        .expect("add entry")
        .build_with_default_header();
    let snapshot = SnapshotHandle::new(snapshot);

    let destination = AccountId(PublicKey::PublicKeyTypeEd25519(Uint256([2u8; 32])));
    let op_create = Operation {
        source_account: None,
        body: OperationBody::CreateAccount(CreateAccountOp {
            destination: destination.clone(),
            starting_balance: 1_000_000,
        }),
    };

    let op_payment = Operation {
        source_account: None,
        body: OperationBody::Payment(stellar_xdr::curr::PaymentOp {
            destination: MuxedAccount::Ed25519(Uint256([9u8; 32])),
            asset: stellar_xdr::curr::Asset::Native,
            amount: 10,
        }),
    };

    let tx = Transaction {
        source_account: MuxedAccount::Ed25519(Uint256(*secret.public_key().as_bytes())),
        fee: 200,
        seq_num: SequenceNumber(2),
        cond: Preconditions::None,
        memo: Memo::None,
        operations: vec![op_create, op_payment].try_into().unwrap(),
        ext: TransactionExt::V0,
    };

    let mut envelope = TransactionEnvelope::Tx(TransactionV1Envelope {
        tx,
        signatures: VecM::default(),
    });

    let network_id = NetworkId::testnet();
    let decorated = sign_envelope(&envelope, &secret, &network_id);
    if let TransactionEnvelope::Tx(ref mut env) = envelope {
        env.signatures = vec![decorated].try_into().unwrap();
    }

    let classic_events = ClassicEventConfig {
        emit_classic_events: true,
        backfill_stellar_asset_events: false,
    };
    let context = henyey_tx::LedgerContext::new(
        1,
        1_000,
        100,
        5_000_000,
        25,
        network_id,
    );
    let mut executor = TransactionExecutor::new(
        &context,
        0,
        SorobanConfig::default(),
        classic_events,
    );
    let result = executor
        .execute_transaction(&snapshot, &envelope, 100, None)
        .expect("execute");

    assert!(!result.success);
    assert_eq!(result.failure, Some(ExecutionFailure::InsufficientBalance));

    let state = executor.state();
    assert!(state.get_account(&destination).is_none());

    let source = state.get_account(&account_id).expect("source account");
    assert_eq!(source.seq_num.0, 2);
    assert_eq!(source.balance, 10_000_000 - 200);
}

