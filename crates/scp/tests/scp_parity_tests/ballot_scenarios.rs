use super::*;

// "normal round (1,x)" — stellar-core lines 2201-2301
// ===========================================================================

#[test]
fn test_ballot_normal_round_1x() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    nodes_all_pledge_to_commit(&scp, &x_value, qs_hash);
    assert_eq!(scp.envs_len(), 3);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // bunch of prepare messages with "commit b"
    let prepared_c1 = make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c2 = make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c3 = make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let _prepared_c4 = make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );

    // those should not trigger anything just yet
    scp.receive_envelope(prepared_c1);
    scp.receive_envelope(prepared_c2);
    assert_eq!(scp.envs_len(), 3);

    // this should cause the node to accept 'commit b' (quorum)
    // and therefore send a "CONFIRM" message
    scp.receive_envelope(prepared_c3);
    assert_eq!(scp.envs_len(), 4);

    verify_confirm(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        1,
        &b,
        b.counter,
        b.counter,
    );

    // bunch of confirm messages
    let confirm1 = make_confirm(&v1_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm2 = make_confirm(&v2_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm3 = make_confirm(&v3_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm4 = make_confirm(&v4_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);

    // those should not trigger anything just yet
    scp.receive_envelope(confirm1);
    scp.receive_envelope(confirm2.clone());
    assert_eq!(scp.envs_len(), 4);

    scp.receive_envelope(confirm3);
    // this causes our node to externalize (confirm commit c)
    assert_eq!(scp.envs_len(), 5);

    // The slot should have externalized the value
    assert_eq!(scp.externalized_value_count(), 1);
    assert_eq!(scp.externalized_value(0), Some(x_value.clone()));

    verify_externalize(&scp.get_env(4), &v0_id(), qs_hash0, 0, &b, b.counter);

    // extra vote should not do anything
    scp.receive_envelope(confirm4);
    assert_eq!(scp.envs_len(), 5);
    assert_eq!(scp.externalized_value_count(), 1);

    // duplicate should just no-op
    scp.receive_envelope(confirm2);
    assert_eq!(scp.envs_len(), 5);
    assert_eq!(scp.externalized_value_count(), 1);
}

/// Helper to set up a fully externalized normal round, returning the TestSCP.
fn setup_normal_round_externalized(
    x_value: &Value,
    qs: &ScpQuorumSet,
    qs_hash: Hash256,
) -> TestSCP {
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(qs);

    nodes_all_pledge_to_commit(&scp, x_value, qs_hash);
    assert_eq!(scp.envs_len(), 3);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // Accept commit via quorum of prepares with commit
    let prepared_c1 = make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c2 = make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c3 = make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );

    scp.receive_envelope(prepared_c1);
    scp.receive_envelope(prepared_c2);
    scp.receive_envelope(prepared_c3);
    assert_eq!(scp.envs_len(), 4);
    verify_confirm(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        1,
        &b,
        b.counter,
        b.counter,
    );

    // Externalize via quorum of confirms
    let confirm1 = make_confirm(&v1_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm2 = make_confirm(&v2_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);
    let confirm3 = make_confirm(&v3_id(), qs_hash, 0, b.counter, &b, b.counter, b.counter);

    scp.receive_envelope(confirm1);
    scp.receive_envelope(confirm2);
    scp.receive_envelope(confirm3);
    assert_eq!(scp.envs_len(), 5);
    assert_eq!(scp.externalized_value_count(), 1);
    assert_eq!(scp.externalized_value(0), Some(x_value.clone()));
    verify_externalize(&scp.get_env(4), &v0_id(), qs_hash0, 0, &b, b.counter);

    scp
}

/// Helper to verify that bumpToBallot is prevented after externalization.
fn verify_bump_to_ballot_prevented(
    scp: &TestSCP,
    _x_value: &Value,
    _z_value: &Value,
    b2: &ScpBallot,
    qs_hash: Hash256,
) {
    let confirm1b2 = make_confirm(&v1_id(), qs_hash, 0, b2.counter, b2, b2.counter, b2.counter);
    let confirm2b2 = make_confirm(&v2_id(), qs_hash, 0, b2.counter, b2, b2.counter, b2.counter);
    let confirm3b2 = make_confirm(&v3_id(), qs_hash, 0, b2.counter, b2, b2.counter, b2.counter);
    let confirm4b2 = make_confirm(&v4_id(), qs_hash, 0, b2.counter, b2, b2.counter, b2.counter);

    scp.receive_envelope(confirm1b2);
    scp.receive_envelope(confirm2b2);
    scp.receive_envelope(confirm3b2);
    scp.receive_envelope(confirm4b2);
    assert_eq!(scp.envs_len(), 5);
    assert_eq!(scp.externalized_value_count(), 1);
}

#[test]
fn test_ballot_bump_to_ballot_prevented_by_value() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = setup_normal_round_externalized(&x_value, &qs, qs_hash);

    // b2 = (1, zValue) — different value, same counter
    let b2 = ScpBallot {
        counter: 1,
        value: z_value.clone(),
    };
    verify_bump_to_ballot_prevented(&scp, &x_value, &z_value, &b2, qs_hash);
}

#[test]
fn test_ballot_bump_to_ballot_prevented_by_counter() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = setup_normal_round_externalized(&x_value, &qs, qs_hash);

    // b2 = (2, xValue) — same value, higher counter
    let b2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    verify_bump_to_ballot_prevented(&scp, &x_value, &z_value, &b2, qs_hash);
}

#[test]
fn test_ballot_bump_to_ballot_prevented_by_value_and_counter() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = setup_normal_round_externalized(&x_value, &qs, qs_hash);

    // b2 = (2, zValue) — different value and higher counter
    let b2 = ScpBallot {
        counter: 2,
        value: z_value.clone(),
    };
    verify_bump_to_ballot_prevented(&scp, &x_value, &z_value, &b2, qs_hash);
}

// ===========================================================================
// "range check" — stellar-core lines 2304-2368
// ===========================================================================

#[test]
fn test_ballot_range_check() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    nodes_all_pledge_to_commit(&scp, &x_value, qs_hash);
    assert_eq!(scp.envs_len(), 3);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // bunch of prepare messages with "commit b"
    let prepared_c1 = make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c2 = make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );
    let prepared_c3 = make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b,
        Some(&b),
        b.counter,
        b.counter,
        None,
    );

    // those should not trigger anything just yet
    scp.receive_envelope(prepared_c1);
    scp.receive_envelope(prepared_c2);
    assert_eq!(scp.envs_len(), 3);

    // this should cause the node to accept 'commit b' (quorum)
    // and therefore send a "CONFIRM" message
    scp.receive_envelope(prepared_c3);
    assert_eq!(scp.envs_len(), 4);

    verify_confirm(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        1,
        &b,
        b.counter,
        b.counter,
    );

    // bunch of confirm messages with different ranges
    let confirm1 = make_confirm(
        &v1_id(),
        qs_hash,
        0,
        4,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );
    let confirm2 = make_confirm(
        &v2_id(),
        qs_hash,
        0,
        6,
        &ScpBallot {
            counter: 6,
            value: x_value.clone(),
        },
        2,
        6,
    );
    let _confirm3 = make_confirm(
        &v3_id(),
        qs_hash,
        0,
        5,
        &ScpBallot {
            counter: 5,
            value: x_value.clone(),
        },
        3,
        5,
    );
    let confirm4 = make_confirm(
        &v4_id(),
        qs_hash,
        0,
        6,
        &ScpBallot {
            counter: 6,
            value: x_value.clone(),
        },
        3,
        6,
    );

    // this should not trigger anything just yet
    scp.receive_envelope(confirm1);

    // v-blocking
    //   * b gets bumped to (4,x)
    //   * p gets bumped to (4,x)
    //   * (c,h) gets bumped to (2,4)
    scp.receive_envelope(confirm2);
    assert_eq!(scp.envs_len(), 5);
    verify_confirm(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        4,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );

    // this causes to externalize
    // range is [3,4]
    scp.receive_envelope(confirm4);
    assert_eq!(scp.envs_len(), 6);

    // The slot should have externalized the value
    assert_eq!(scp.externalized_value_count(), 1);
    assert_eq!(scp.externalized_value(0), Some(x_value.clone()));

    verify_externalize(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 3,
            value: x_value.clone(),
        },
        4,
    );
}

// ===========================================================================
// "timeout when h is set -> stay locked on h" — stellar-core lines 2370-2389
// ===========================================================================

#[test]
fn test_ballot_timeout_h_set_stay_locked() {
    let (x_value, y_value, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    let bx = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };
    assert!(scp.bump_state(0, x_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking -> prepared
    // quorum -> confirm prepared
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, bx.clone(), Some(bx.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &bx,
        Some(&bx),
        bx.counter,
        bx.counter,
        None,
    );

    // now, see if we can timeout and move to a different value
    assert!(scp.bump_state(0, y_value.clone()));
    assert_eq!(scp.envs_len(), 4);
    let newbx = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &newbx,
        Some(&bx),
        bx.counter,
        bx.counter,
        None,
    );
}

// ===========================================================================
// "timeout when h exists but can't be set -> vote for h" — stellar-core lines 2390-2415
// ===========================================================================

#[test]
fn test_ballot_timeout_h_cant_be_set_vote_for_h() {
    let (x_value, y_value, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    // start with (1,y)
    let by = ScpBallot {
        counter: 1,
        value: y_value.clone(),
    };
    assert!(scp.bump_state(0, y_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    let bx = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };
    // but quorum goes with (1,x)
    // v-blocking -> prepared
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, bx.clone(), Some(bx.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &by,
        Some(&bx),
        0,
        0,
        None,
    );
    // quorum -> confirm prepared (no-op as b > h)
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, bx.clone(), Some(bx.clone()), 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);

    assert!(scp.bump_state(0, y_value.clone()));
    assert_eq!(scp.envs_len(), 3);
    let newbx = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    // on timeout:
    // * we should move to the quorum's h value
    // * c can't be set yet as b > h
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &newbx,
        Some(&bx),
        0,
        bx.counter,
        None,
    );
}

// ===========================================================================
// "timeout from multiple nodes" — stellar-core lines 2417-2460
// ===========================================================================

#[test]
fn test_ballot_timeout_from_multiple_nodes() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    assert!(scp.bump_state(0, x_value.clone()));

    let x1 = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &x1,
        None,
        0,
        0,
        None,
    );

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, x1.clone(), None, 0, 0, None),
    );
    // quorum -> prepared (1,x)
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &x1,
        Some(&x1),
        0,
        0,
        None,
    );

    let x2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    // timeout from local node
    assert!(scp.bump_state(0, x_value.clone()));
    // prepares (2,x)
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x1),
        0,
        0,
        None,
    );

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, x1.clone(), Some(x1.clone()), 0, 0, None),
    );
    // quorum -> set nH=1
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x1),
        0,
        1,
        None,
    );
    assert_eq!(scp.envs_len(), 4);

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, x2.clone(), Some(x2.clone()), 1, 1, None),
    );
    // v-blocking prepared (2,x) -> prepared (2,x)
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x2),
        0,
        1,
        None,
    );

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, x2.clone(), Some(x2.clone()), 1, 1, None),
    );
    // quorum (including us) confirms (2,x) prepared -> set h=c=x2
    // we also get extra message: a quorum not including us confirms
    // (1,x) prepared
    //  -> we confirm c=h=x1
    assert_eq!(scp.envs_len(), 7);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x2),
        2,
        2,
        None,
    );
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &x2, 1, 1);
}

// ===========================================================================
// "timeout after prepare, receive old messages to prepare" — stellar-core lines 2462-2508
// ===========================================================================

#[test]
fn test_ballot_timeout_after_prepare_receive_old_messages() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash0 = quorum_set_hash(&scp.scp.local_quorum_set());

    assert!(scp.bump_state(0, x_value.clone()));

    let x1 = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &x1,
        None,
        0,
        0,
        None,
    );

    scp.receive_envelope(make_prepare(&v1_id(), qs_hash, 0, &x1, None, 0, 0, None));
    scp.receive_envelope(make_prepare(&v2_id(), qs_hash, 0, &x1, None, 0, 0, None));
    scp.receive_envelope(make_prepare(&v3_id(), qs_hash, 0, &x1, None, 0, 0, None));

    // quorum -> prepared (1,x)
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &x1,
        Some(&x1),
        0,
        0,
        None,
    );

    let x2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    // timeout from local node
    assert!(scp.bump_state(0, x_value.clone()));
    // prepares (2,x)
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &x2,
        Some(&x1),
        0,
        0,
        None,
    );

    let x3 = ScpBallot {
        counter: 3,
        value: x_value.clone(),
    };
    // timeout again
    assert!(scp.bump_state(0, x_value.clone()));
    // prepares (3,x)
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &x3,
        Some(&x1),
        0,
        0,
        None,
    );

    // other nodes moved on with x2
    scp.receive_envelope(make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &x2,
        Some(&x2),
        1,
        2,
        None,
    ));
    scp.receive_envelope(make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &x2,
        Some(&x2),
        1,
        2,
        None,
    ));
    // v-blocking -> prepared x2
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &x3,
        Some(&x2),
        0,
        0,
        None,
    );

    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &x2,
        Some(&x2),
        1,
        2,
        None,
    ));
    // quorum -> set nH=2
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &x3,
        Some(&x2),
        0,
        2,
        None,
    );
}

// ===========================================================================
// "non validator watching the network" — stellar-core lines 2510-2538
// ===========================================================================

#[test]
fn test_non_validator_watching_the_network() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    // Create a non-validator node (NV) using a distinct node ID
    let nv_id = make_node_id(10); // distinct from v0-v4
    let scp = TestSCP::new_non_validator(nv_id.clone(), qs.clone());
    scp.store_quorum_set(&qs);
    let qs_hash_nv = quorum_set_hash(&scp.scp.local_quorum_set());

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // Non-validator bumps state — no envelopes emitted
    assert!(scp.bump_state(0, x_value.clone()));
    assert_eq!(scp.envs_len(), 0);

    // But internally it should have moved to PREPARE
    verify_prepare(
        &scp.get_current_envelope(0, &nv_id),
        &nv_id,
        qs_hash_nv,
        0,
        &b,
        None,
        0,
        0,
        None,
    );

    // Receive 4 EXTERNALIZE envelopes from v1-v4
    let ext1 = make_externalize(&v1_id(), qs_hash, 0, &b, 1);
    let ext2 = make_externalize(&v2_id(), qs_hash, 0, &b, 1);
    let ext3 = make_externalize(&v3_id(), qs_hash, 0, &b, 1);
    let ext4 = make_externalize(&v4_id(), qs_hash, 0, &b, 1);

    scp.receive_envelope(ext1);
    scp.receive_envelope(ext2);
    scp.receive_envelope(ext3);
    // After 3 EXTERNALIZE envelopes: no emitted envelopes (non-validator)
    assert_eq!(scp.envs_len(), 0);

    // Internal state should be CONFIRM (accept commit via v-blocking,
    // quorum confirms -> CONFIRM with UINT32_MAX)
    let b_inf = ScpBallot {
        counter: u32::MAX,
        value: x_value.clone(),
    };
    verify_confirm(
        &scp.get_current_envelope(0, &nv_id),
        &nv_id,
        qs_hash_nv,
        0,
        u32::MAX,
        &b_inf,
        1,
        u32::MAX,
    );

    scp.receive_envelope(ext4);
    // Still no emitted envelopes
    assert_eq!(scp.envs_len(), 0);

    // Internal state should be EXTERNALIZE
    verify_externalize(
        &scp.get_current_envelope(0, &nv_id),
        &nv_id,
        qs_hash_nv,
        0,
        &b,
        u32::MAX,
    );

    // Value should be externalized
    assert_eq!(scp.externalized_value(0), Some(x_value.clone()));
}

// ===========================================================================
// "restore ballot protocol" — stellar-core lines 2540-2563
// Tests that setStateFromEnvelope doesn't crash for PREPARE/CONFIRM/EXTERNALIZE
// ===========================================================================

#[test]
fn test_restore_ballot_protocol_prepare() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };

    let envelope = make_prepare(&v0_id(), qs_hash, 0, &b, None, 0, 0, None);
    scp.set_state_from_envelope(&envelope);
}

#[test]
fn test_restore_ballot_protocol_confirm() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };

    let envelope = make_confirm(&v0_id(), qs_hash, 0, 2, &b, 1, 2);
    scp.set_state_from_envelope(&envelope);
}

#[test]
fn test_restore_ballot_protocol_externalize() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };

    let envelope = make_externalize(&v0_id(), qs_hash, 0, &b, 2);
    scp.set_state_from_envelope(&envelope);
}

// ===========================================================================

