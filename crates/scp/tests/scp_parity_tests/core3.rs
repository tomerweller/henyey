use super::*;

// "ballot protocol core3" — stellar-core lines 2569-2757
// Core3 has an edge case where v-blocking and quorum can be the same
// v-blocking set size: 2, threshold: 2 = 1 + self or 2 others
// ===========================================================================

/// Core3 helper: recv_quorum for a 3-node quorum where receiving from v1
/// alone forms a quorum (with self). The `min_quorum` flag skips sending e2.
fn recv_quorum_checks_ex_core3(
    scp: &TestSCP,
    gen: &dyn Fn(&NodeId) -> ScpEnvelope,
    with_checks: bool,
    delayed_quorum: bool,
    check_upcoming: bool,
    min_quorum: bool,
) {
    let e1 = gen(&v1_id());
    let e2 = gen(&v2_id());

    scp.bump_timer_offset();

    let i = scp.envs_len() + 1;
    scp.receive_envelope(e1);
    if with_checks && !delayed_quorum {
        assert_eq!(scp.envs_len(), i);
    }
    if check_upcoming {
        assert!(scp.has_ballot_timer_upcoming());
    }
    if !min_quorum {
        // nothing happens with an extra vote (unless we're in delayedQuorum)
        scp.receive_envelope(e2);
        if with_checks {
            assert_eq!(scp.envs_len(), i);
        }
    }
}

/// Core3 helper: standard quorum check (no min_quorum)
fn recv_quorum_checks_core3(
    scp: &TestSCP,
    gen: &dyn Fn(&NodeId) -> ScpEnvelope,
    with_checks: bool,
    delayed_quorum: bool,
) {
    recv_quorum_checks_ex_core3(scp, gen, with_checks, delayed_quorum, false, false);
}

// ---------------------------------------------------------------------------
// "prepared B1 (quorum votes B1) local aValue" — stellar-core lines 2659-2703
// ---------------------------------------------------------------------------

#[test]
fn test_core3_prepared_b1_quorum_votes_b1_local_a_value() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    // core3: aValue = zValue, bValue = xValue
    let a_value = &z_value;
    let b_value = &x_value;

    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // no timer is set
    assert!(!scp.has_ballot_timer());

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);
    assert!(!scp.has_ballot_timer());

    // quorum votes B1 -> prepared B1
    scp.bump_timer_offset();
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &b1, None, 0, 0, None),
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// "prepared B1 (quorum votes B1) -> quorum prepared B1 -> quorum bumps to A1"
// stellar-core lines 2670-2701
// ---------------------------------------------------------------------------

#[test]
fn test_core3_quorum_prepared_b1_then_bumps_to_a1() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &z_value;
    let b_value = &x_value;

    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // quorum votes B1 -> prepared B1
    scp.bump_timer_offset();
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &b1, None, 0, 0, None),
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
    assert!(scp.has_ballot_timer_upcoming());

    // quorum prepared B1
    scp.bump_timer_offset();
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &b1, Some(&b1), 0, 0, None),
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);
    // nothing happens:
    // computed_h = B1 (2)
    //    does not actually update h as b > computed_h
    //    also skips (3)
    assert!(!scp.has_ballot_timer_upcoming());

    // quorum bumps to A1 (min_quorum = true)
    scp.bump_timer_offset();
    recv_quorum_checks_ex_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &a1, Some(&b1), 0, 0, None),
        false,
        false,
        false,
        true,
    );
    assert_eq!(scp.envs_len(), 3);
    // still does not set h as b > computed_h
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        Some(&b1),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    // quorum commits A1
    scp.bump_timer_offset();
    recv_quorum_checks_ex_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &a2, Some(&a1), 1, 1, Some(&b1)),
        false,
        false,
        false,
        true,
    );
    assert_eq!(scp.envs_len(), 4);
    verify_confirm(&scp.get_env(3), &v0_id(), qs_hash0, 0, 2, &a1, 1, 1);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// "prepared A1 with timeout" — stellar-core lines 2705-2730
// ---------------------------------------------------------------------------

#[test]
fn test_core3_prepared_a1_with_timeout() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &z_value;
    let b_value = &x_value;

    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // starts with bValue (smallest)
    assert!(scp.bump_state(0, b_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // setup: quorum votes prepare A1 with p'=A1, nC=0, nH=1
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &a1, Some(&a1), 0, 1, None),
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&a1),
        1,
        1,
        None,
    );

    // now, receive bumped votes
    recv_quorum_checks_core3(
        &scp,
        &|node_id| make_prepare(node_id, qs_hash, 0, &a2, Some(&b2), 0, 1, Some(&a1)),
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 3);
    // p=B2, p'=A1 (1)
    // computed_h = B2 (2)
    //   does not update h as b < computed_h
    // v-blocking ahead -> b = computed_h = B2 (9)
    // h = B2 (2) (now possible)
    // c = 0 (1)
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &b2,
        Some(&a2),
        0,
        2,
        Some(&b2),
    );
}

// ---------------------------------------------------------------------------
// "node without self - quorum timeout" — stellar-core lines 2731-2754
// ---------------------------------------------------------------------------

#[test]
fn test_core3_node_without_self_quorum_timeout() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let a_value = &z_value;

    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };

    // Create a node that is NOT in the quorum set (NodeNS)
    let ns_id = make_node_id(20); // distinct from v0-v2
    let scp_nns = TestSCP::new(ns_id.clone(), qs.clone());
    scp_nns.store_quorum_set(&qs);
    let qs_hash_ns = quorum_set_hash(&scp_nns.scp.local_quorum_set());

    // Receive envelopes from v1 and v2 (forms quorum without self since
    // NodeNS is not in the quorum set, so threshold is met by v1+v2 alone)
    scp_nns.receive_envelope(make_prepare(
        &v1_id(),
        qs_hash,
        0,
        &a2,
        Some(&b2),
        0,
        1,
        Some(&a1),
    ));
    scp_nns.receive_envelope(make_prepare(
        &v2_id(),
        qs_hash,
        0,
        &a1,
        Some(&a1),
        1,
        1,
        None,
    ));

    assert_eq!(scp_nns.envs_len(), 1);
    verify_prepare(
        &scp_nns.get_env(0),
        &ns_id,
        qs_hash_ns,
        0,
        &a1,
        Some(&a1),
        1,
        1,
        None,
    );

    scp_nns.receive_envelope(make_prepare(
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&b2),
        0,
        1,
        Some(&a1),
    ));

    assert_eq!(scp_nns.envs_len(), 2);
    verify_prepare(
        &scp_nns.get_env(1),
        &ns_id,
        qs_hash_ns,
        0,
        &b2,
        Some(&a2),
        0,
        2,
        Some(&b2),
    );
}

