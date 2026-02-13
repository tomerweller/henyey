use super::*;

// ===========================================================================
// Helper: set up through "Accept commit > Quorum A2" (6 envelopes)
// ===========================================================================

/// Drive SCP through Confirm prepared A2 → Accept commit (Quorum A2).
/// Returns scp at env[5] = CONFIRM(nP=2, b=A2, nC=2, nH=2).
#[allow(clippy::type_complexity)]
fn setup_accept_commit_quorum_a2() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (scp, x_value, y_value, z_value, zz_value, qs_hash) = setup_confirm_prepared_a2();
    let a_value = x_value.clone();
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

// ===========================================================================
// Ballot core5 > Accept commit > Quorum A2 > deep branches
// ===========================================================================

// ---------------------------------------------------------------------------
// v-blocking prepared A3 (stellar-core line 1054)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_prepared_a3() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// v-blocking prepared A3+B3 (stellar-core line 1063)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_prepared_a3_b3() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(b3), 2, 2, Some(a3)),
    );
    assert_eq!(scp.envs_len(), 7);
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// v-blocking confirm A3 (stellar-core line 1072)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_confirm_a3() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// Hang - does not switch to B in CONFIRM > Network EXTERNALIZE (stellar-core line 1084)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_hang_no_switch_externalize() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // v-blocking EXTERNALIZE with B2 → bumps to AInf but stays on A
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2.clone(), 3));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &a_inf, 2, 2);
    assert!(!scp.has_ballot_timer());

    // stuck: quorum EXTERNALIZE with B2 doesn't externalize
    recv_quorum_checks_ex(
        &scp,
        &make_externalize_gen(qs_hash, b2, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 7);
    assert!(scp.externalized_value(0).is_none());
    // timer scheduled as there is a quorum with (2, *)
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// Hang > Network CONFIRMS other ballot > at same counter (stellar-core line 1110)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_hang_confirm_same_counter() {
    let (scp, _x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let b_value = z_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // nothing should happen, node should not switch p
    recv_quorum_checks_ex(
        &scp,
        &make_confirm_gen(qs_hash, 3, b2, 2, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 6);
    assert!(scp.externalized_value(0).is_none());
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// Hang > Network CONFIRMS other ballot > at a different counter (stellar-core line 1125)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_hang_confirm_different_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // v-blocking CONFIRM B3 → bumps to A3 but keeps nC=2 nH=2
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, b3.clone(), 3, 3));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());

    // quorum CONFIRM B3 → stuck, no externalization
    recv_quorum_checks_ex(
        &scp,
        &make_confirm_gen(qs_hash, 3, b3, 3, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 7);
    assert!(scp.externalized_value(0).is_none());
    // timer scheduled as there is a quorum with (3, *)
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// v-blocking after Quorum prepared A3 > Confirm A3 (stellar-core line 1004)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_accept_more_a3_confirm() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    // Quorum prepared A3 (same as full ext path, lines 957-969)
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &a3, 2, 2);

    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);
    verify_confirm(&scp.get_env(7), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);

    // v-blocking CONFIRM A3 with nC=2 nH=3 → updates nH
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 3));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash0, 0, 3, &a3, 2, 3);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// v-blocking after Quorum prepared A3 > Externalize A3 (stellar-core line 1015)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_accept_more_a3_externalize() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // Quorum prepared A3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);

    // v-blocking EXTERNALIZE A2 with nH=3 → bumps to infinite
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2, 3));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(
        &scp.get_env(8),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &a_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// v-blocking accept more A3 > other nodes moved to c=A4 h=A5 > Confirm A4..5 (stellar-core line 1029)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_accept_more_a3_confirm_a4_a5() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a5 = ScpBallot {
        counter: 5,
        value: a_value.clone(),
    };

    // Quorum prepared A3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);

    // v-blocking CONFIRM A5 nC=4 nH=5
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a5.clone(), 4, 5));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash0, 0, 3, &a5, 4, 5);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// v-blocking accept more A3 > other nodes moved to c=A4 h=A5 > Externalize A4..5 (stellar-core line 1039)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_vblocking_accept_more_a3_externalize_a4_a5() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // Quorum prepared A3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);

    // v-blocking EXTERNALIZE A4 nH=5
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a4, 5));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(
        &scp.get_env(8),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &a_inf,
        4,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// Accept commit > v-blocking > CONFIRM A3..4 (stellar-core line 1164)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_confirm_a3_a4() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 4, a4.clone(), 3, 4));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 4, &a4, 3, 4);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// Accept commit > v-blocking > CONFIRM B2 (stellar-core line 1174)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_confirm_b2() {
    let (scp, _x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let b_value = z_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, b2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 2, &b2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// Accept commit > v-blocking > EXTERNALIZE B2 (stellar-core line 1197)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_externalize_b2() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let b_value = z_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b_inf = ScpBallot {
        counter: u32::MAX,
        value: b_value.clone(),
    };

    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &b_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// get conflicting prepared B > same counter (stellar-core line 1212)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_conflicting_prepared_b_same_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // v-blocking PREPARE B2 prepared=B2 → sets p=B2, p'=A2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b2),
        0,
        2,
        Some(&a2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    // quorum PREPARE B2 nC=2 nH=2 → CONFIRM B2
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &b2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// get conflicting prepared B > higher counter (stellar-core line 1228)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_conflicting_prepared_b_higher_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // v-blocking PREPARE B3 prepared=B2 nC=2 nH=2 → bumps to A3, p=B2, p'=A2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a3,
        Some(&b2),
        0,
        2,
        Some(&a2),
    );
    assert!(!scp.has_ballot_timer());

    // delayed quorum PREPARE B3 → CONFIRM
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b2.clone()), 2, 2, None),
        true,
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 3, &b3, 2, 2);
}

// ---------------------------------------------------------------------------
// get conflicting prepared B > higher counter mixed (stellar-core line 1244)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_conflicting_prepared_b_higher_counter_mixed() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;
    let a_value = x_value;
    let b_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // v-blocking PREPARE A3 prepared=B3 nC=0 nH=2 p'=A2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a3.clone(),
            Some(b3.clone()),
            0,
            2,
            Some(a2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 6);
    // p=B3, p'=A2, counter=3, b=A3 (same value as h), c=0
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a3,
        Some(&b3),
        0,
        2,
        Some(&a2),
    );

    // quorum PREPARE same → p=B3, p'=A3, computed_h=B3, b=B3, h=B3, c=3
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(b3.clone()), 0, 2, Some(a2)),
        true,
    );
    assert_eq!(scp.envs_len(), 7);
    verify_prepare(
        &scp.get_env(6),
        &v0_id(),
        qs_hash0,
        0,
        &b3,
        Some(&b3),
        3,
        3,
        Some(&a3),
    );
}

// ---------------------------------------------------------------------------
// Confirm prepared mixed > mixed A2 (stellar-core line 1280)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_prepared_mixed_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();

    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
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

    // Start → prepared A1 → bump → prepared A2
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    scp.bump_timer_offset();
    scp.scp.force_bump_state(0, a_value.clone());
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), None, 0, 0, None),
        true,
    );

    // v-blocking prepared B2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            b2.clone(),
            Some(b2.clone()),
            0,
            0,
            Some(a2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b2),
        0,
        0,
        Some(&a2),
    );

    // mixed B2: causes h=B2, c=B2
    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &b2,
        Some(&b2),
        2,
        2,
        Some(&a2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 6);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// switch prepared B1 from A1 > v-blocking switches to previous value of p (stellar-core line 1344)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepared_no_downgrade_p() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // Start → prepared A1
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // switch to B1 prepared
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        Some(&a1),
    );

    // bump counter to 2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), None, 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 4);
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b1),
        0,
        0,
        Some(&a1),
    );

    // update p to B2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b2),
        0,
        0,
        Some(&a1),
    );

    // bump counter to 3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), None, 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 6);
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a3,
        Some(&b2),
        0,
        0,
        Some(&a1),
    );
    assert!(!scp.has_ballot_timer());

    // v-blocking says B1 is prepared — but we already have p=B2, should not downgrade
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b1), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 6);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// switch prepared B1 from A1 > switch p' to Mid2 (stellar-core line 1361)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepared_pprime_to_mid2() {
    let (x_value, y_value, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let mid_value = y_value; // midValue = yValue
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
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let mid2 = ScpBallot {
        counter: 2,
        value: mid_value.clone(),
    };

    // Start → prepared A1 → switch to B1 → bump to 2 → update p to B2
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), None, 0, 0, None),
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);

    // (p,p') = (B2, Mid2)
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            b2.clone(),
            Some(b2.clone()),
            0,
            0,
            Some(mid2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&b2),
        0,
        0,
        Some(&mid2),
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// switch prepared B1 from A1 > switch again Big2 (stellar-core line 1371)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepared_big2() {
    let (x_value, _y, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let big_value = zz_value; // bigValue = zzValue
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
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let big2 = ScpBallot {
        counter: 2,
        value: big_value.clone(),
    };

    // Start → prepared A1 → switch to B1 → bump to 2 → update p to B2
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), None, 0, 0, None),
    );
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);

    // both p and p' get updated: (p,p') = (Big2, B2)
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            b2.clone(),
            Some(big2.clone()),
            0,
            0,
            Some(b2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&big2),
        0,
        0,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// switch prepare B1 (quorum, delayed) (stellar-core line 1383)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepare_b1_quorum() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start → prepared A1
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // Quorum PREPARE B1 (delayed quorum — local voted A1 not B1)
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        true,
        true,
        false,
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        Some(&a1),
    );
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// prepare higher counter (v-blocking) (stellar-core line 1391)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepare_higher_counter_vblocking() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    // Start → prepared A1
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // v-blocking PREPARE B2 → bumps counter to 2
    recv_v_blocking(&scp, &make_prepare_gen(qs_hash, b2, None, 0, 0, None));
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());

    // v-blocking PREPARE B3 → bumps counter to 3
    recv_v_blocking(&scp, &make_prepare_gen(qs_hash, b3, None, 0, 0, None));
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &a3,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// prepared B (v-blocking) — no prior prepared (stellar-core line 1407)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepared_b_vblocking_from_start() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking PREPARE B1 prepared=B1 → sets p=B1
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
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
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// prepare B (quorum) — no prior prepared (stellar-core line 1414)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepare_b_quorum_from_start() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // quorum PREPARE B1 (delayed — local voted A1)
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        true,
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
}

// ---------------------------------------------------------------------------
// confirm (v-blocking) > via CONFIRM (stellar-core line 1423)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_vblocking_via_confirm_higher() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking via two CONFIRM messages with different counters
    scp.bump_timer_offset();
    scp.receive_envelope(make_confirm(&v1_id(), qs_hash, 0, 3, &a3, 3, 3));
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };
    scp.receive_envelope(make_confirm(&v2_id(), qs_hash, 0, 4, &a4, 2, 4));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(&scp.get_env(1), &v0_id(), qs_hash0, 0, 3, &a3, 3, 3);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// confirm (v-blocking) > via EXTERNALIZE (stellar-core line 1435)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_vblocking_via_externalize_higher() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking via two EXTERNALIZE messages
    scp.receive_envelope(make_externalize(&v1_id(), qs_hash, 0, &a2, 4));
    scp.receive_envelope(make_externalize(&v2_id(), qs_hash, 0, &a3, 5));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &a_inf,
        3,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ===========================================================================

