use super::*;

// "start <1,z>" branch — stellar-core lines 1452-1975
//
// This is the mirror of "start <1,x>" with inverted value ordering:
//   aValue = zValue (larger), bValue = xValue (smaller)
// So B < A at the same counter, which changes conflicting prepared behavior.
// ===========================================================================

// ---------------------------------------------------------------------------
// Setup helpers for <1,z> branch
// ---------------------------------------------------------------------------

/// Setup for "start <1,z>" → prepared A1 → bump prepared A2.
///
/// Returns scp at env[3] = PREPARE(A2, p=A2)
/// where aValue = zValue, bValue = xValue.
fn setup_bump_prepared_a2_z() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (x_value, y_value, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    // In <1,z>: aValue = zValue, bValue = xValue
    let a_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Start → env[0] = PREPARE(A1)
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);
    assert!(!scp.has_ballot_timer());

    // prepared A1: quorum PREPARE(A1) → env[1] = PREPARE(A1, p=A1)
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        None,
    );

    // bump to (2,a) → env[2] = PREPARE(A2, p=A1)
    scp.bump_timer_offset();
    scp.scp.force_bump_state(0, a_value.clone());
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());

    // quorum PREPARE(A2) → env[3] = PREPARE(A2, p=A2)
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    );

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

/// Setup for "start <1,z>" → prepared A1 → bump prepared A2 → Confirm prepared A2.
///
/// Returns scp at env[4] = PREPARE(A2, p=A2, nC=2, nH=2)
/// where aValue = zValue, bValue = xValue.
fn setup_confirm_prepared_a2_z() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (scp, x_value, y_value, z_value, zz_value, qs_hash) = setup_bump_prepared_a2_z();
    let a_value = z_value.clone();
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Confirm prepared A2: receive quorum PREPARE with prepared=A2
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        2,
        2,
        None,
    );
    assert!(!scp.has_ballot_timer_upcoming());

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

/// Setup for "start <1,z>" → Accept commit > Quorum A2.
///
/// Returns scp at env[5] = CONFIRM(nP=2, b=A2, nC=2, nH=2)
/// where aValue = zValue, bValue = xValue.
fn setup_accept_commit_quorum_a2_z() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (scp, x_value, y_value, z_value, zz_value, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value.clone();
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

// ---------------------------------------------------------------------------
// start <1,z> > prepared A1 > bump prepared A2 > Confirm prepared A2 (stellar-core line 1513)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_prepared_a2() {
    let (_scp, _x, _y, _z, _zz, _qs_hash) = setup_confirm_prepared_a2_z();
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > Quorum A2 (stellar-core line 1523)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_quorum_a2() {
    let (_scp, _x, _y, _z, _zz, _qs_hash) = setup_accept_commit_quorum_a2_z();
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > Quorum A2 > Quorum prepared A3 (stellar-core line 1532)
// ---------------------------------------------------------------------------

/// Helper: drives from accept_commit_quorum_a2_z through "Quorum prepared A3"
/// arriving at env[7] = CONFIRM(nP=3, b=A3, nC=2, nH=2)
fn setup_quorum_prepared_a3_z() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (scp, x_value, y_value, z_value, zz_value, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value.clone();
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    // v-blocking PREPARE(A3, p=A2, nC=2, nH=2)
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 2, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());

    // quorum PREPARE(A3, p=A2, nC=2, nH=2)
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);
    verify_confirm(&scp.get_env(7), &v0_id(), qs_hash, 0, 3, &a3, 2, 2);

    (scp, x_value, y_value, z_value, zz_value, qs_hash)
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept more commit A3 > Quorum externalize A3 (stellar-core line 1562)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_quorum_externalize_a3() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    // Accept more commit A3
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 3, None),
    );
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash, 0, 3, &a3, 2, 3);
    assert!(!scp.has_ballot_timer_upcoming());
    assert_eq!(scp.externalized_value_count(), 0);

    // Quorum externalize A3
    recv_quorum(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 3));
    assert_eq!(scp.envs_len(), 10);
    verify_externalize(&scp.get_env(9), &v0_id(), qs_hash, 0, &a2, 3);
    assert!(!scp.has_ballot_timer());
    assert_eq!(scp.externalized_value_count(), 1);
    assert_eq!(scp.externalized_value(0), Some(a_value));
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking accept more A3 > Confirm A3 (stellar-core line 1581)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_accept_more_a3_confirm() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 3));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash, 0, 3, &a3, 2, 3);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking accept more A3 > Externalize A3 (stellar-core line 1592)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_accept_more_a3_externalize() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2.clone(), 3));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(
        &scp.get_env(8),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking accept more A3 > other nodes c=A4 h=A5 > Confirm (stellar-core line 1606)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_accept_more_a3_confirm_a4_a5() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a5 = ScpBallot {
        counter: 5,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a5.clone(), 4, 5));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash, 0, 3, &a5, 4, 5);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking accept more A3 > other nodes c=A4 h=A5 > Externalize (stellar-core line 1616)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_accept_more_a3_externalize_a4_a5() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_quorum_prepared_a3_z();
    let a_value = z_value;
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a4.clone(), 5));
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(
        &scp.get_env(8),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        4,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking prepared A3 (stellar-core line 1631)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_prepared_a3() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking prepared A3+B3 (stellar-core line 1640)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_prepared_a3_b3() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let b_value = x_value;
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
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 2, Some(b3)),
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > v-blocking confirm A3 (stellar-core line 1649)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_vblocking_confirm_a3() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 3, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > Hang - does not switch to B in CONFIRM > Network EXTERNALIZE (stellar-core line 1661)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_hang_no_switch_externalize() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    // externalize messages have a counter at infinite
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2.clone(), 3));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 2, &a_inf, 2, 2);
    assert!(!scp.has_ballot_timer());

    // stuck
    recv_quorum_checks_ex(
        &scp,
        &make_externalize_gen(qs_hash, b2.clone(), 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 7);
    assert_eq!(scp.externalized_value_count(), 0);
    // timer scheduled as there is a quorum with (inf, *)
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Hang > Network CONFIRMS other ballot > at same counter (stellar-core line 1687)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_hang_confirm_same_counter() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // nothing should happen here, node should not attempt to switch 'p'
    recv_quorum_checks_ex(
        &scp,
        &make_confirm_gen(qs_hash, 3, b2.clone(), 2, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 6);
    assert_eq!(scp.externalized_value_count(), 0);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Hang > Network CONFIRMS other ballot > at a different counter (stellar-core line 1702)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_hang_confirm_different_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_accept_commit_quorum_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let b3 = ScpBallot {
        counter: 3,
        value: b_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 3, b3.clone(), 3, 3));
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 2, &a3, 2, 2);
    assert!(!scp.has_ballot_timer());

    recv_quorum_checks_ex(
        &scp,
        &make_confirm_gen(qs_hash, 3, b3.clone(), 3, 3),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 7);
    assert_eq!(scp.externalized_value_count(), 0);
    // timer scheduled as there is a quorum with (3, *)
    assert!(scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > CONFIRM A2 (stellar-core line 1731)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_confirm_a2() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, a2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > CONFIRM A3..4 (stellar-core line 1741)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_confirm_a3_a4() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 4, a4.clone(), 3, 4));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 4, &a4, 3, 4);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > CONFIRM B2 (stellar-core line 1751)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_confirm_b2() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, b2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash, 0, 2, &b2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > EXTERNALIZE A2 (stellar-core line 1764)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_externalize_a2() {
    let (scp, _x, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2.clone(), 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > Accept commit > v-blocking > EXTERNALIZE B2 (stellar-core line 1774)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_accept_commit_vblocking_externalize_b2() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b_inf = ScpBallot {
        counter: u32::MAX,
        value: b_value.clone(),
    };

    // can switch to B2 with externalize (higher counter)
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2.clone(), 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &b_inf,
        2,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > Conflicting prepared B > same counter (stellar-core line 1791)
// messages are ignored as B2 < A2
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_conflicting_prepared_b_same_counter() {
    let (scp, x_value, _y, _z, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let b_value = x_value;
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // messages are ignored as B2 < A2
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 5);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Conflicting prepared B > higher counter (stellar-core line 1800)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_conflicting_prepared_b_higher_counter() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let b_value = x_value;
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

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    // A2 > B2 -> p = A2, p'=B2
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        &a3,
        Some(&a2),
        2,
        2,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer());

    // node is trying to commit A2 but rest of quorum is trying to commit B2
    // we end up with a delayed quorum
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), Some(b2.clone()), 2, 2, None),
        true,
        true,
        true,
    );
    assert_eq!(scp.envs_len(), 7);
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash, 0, 3, &b3, 2, 2);
}

// ---------------------------------------------------------------------------
// start <1,z> > Conflicting prepared B > higher counter mixed (stellar-core line 1820)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_conflicting_prepared_b_higher_counter_mixed() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_confirm_prepared_a2_z();
    let a_value = z_value;
    let b_value = x_value;
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
    let b4 = ScpBallot {
        counter: 4,
        value: b_value.clone(),
    };

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
    // h still A2
    // v-blocking: prepared B3 -> p=B3, p'=A2 (1), counter 3, b=A3 (same value as h), c=0
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        &a3,
        Some(&b3),
        0,
        2,
        Some(&a2),
    );

    recv_quorum_ex(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a3.clone(),
            Some(b3.clone()),
            0,
            2,
            Some(a2.clone()),
        ),
        true,
    );
    // p=A3, p'=B3 (1)
    // computed_h = B3 (2) z = B - cannot update b
    assert_eq!(scp.envs_len(), 7);
    verify_prepare(
        &scp.get_env(6),
        &v0_id(),
        qs_hash,
        0,
        &a3,
        Some(&a3),
        0,
        2,
        Some(&b3),
    );
    // timeout, bump to B4
    assert!(scp.has_ballot_timer_upcoming());
    scp.fire_ballot_timer();
    // computed_h = B3, h = B3 (2), c = 0
    assert_eq!(scp.envs_len(), 8);
    verify_prepare(
        &scp.get_env(7),
        &v0_id(),
        qs_hash,
        0,
        &b4,
        Some(&a3),
        0,
        3,
        Some(&b3),
    );
}

// ---------------------------------------------------------------------------
// start <1,z> > Confirm prepared mixed > mixed A2 (stellar-core line 1864)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_prepared_mixed_a2() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_bump_prepared_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // a few nodes prepared B2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a2.clone(),
            Some(a2.clone()),
            0,
            0,
            Some(b2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    // causes h=A2, c=A2
    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 6);
    verify_prepare(
        &scp.get_env(5),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        2,
        2,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v4_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 6);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > Confirm prepared mixed > mixed B2 (stellar-core line 1883)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_prepared_mixed_b2() {
    let (scp, x_value, _y, z_value, _zz, qs_hash) = setup_bump_prepared_a2_z();
    let a_value = z_value;
    let b_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    // a few nodes prepared B2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a2.clone(),
            Some(a2.clone()),
            0,
            0,
            Some(b2.clone()),
        ),
    );
    assert_eq!(scp.envs_len(), 5);
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        Some(&b2),
    );
    assert!(!scp.has_ballot_timer_upcoming());

    // causes computed_h=B2 ~ not set as h ~!= b → noop
    scp.bump_timer_offset();
    scp.receive_envelope(make_prepare(
        &v3_id(),
        qs_hash,
        0,
        &a2,
        Some(&b2),
        0,
        0,
        None,
    ));
    assert_eq!(scp.envs_len(), 5);
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
    assert_eq!(scp.envs_len(), 5);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > switch prepared B1 from A1 (stellar-core line 1903)
// can't switch to B1 because B1 < A1
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_switch_prepared_b1_from_a1() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));

    // prepared A1
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        None,
    );

    // can't switch to B1
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > switch prepare B1 (stellar-core line 1911)
// doesn't switch as B1 < A1
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_switch_prepare_b1_quorum() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));

    // prepared A1
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // doesn't switch as B1 < A1
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// start <1,z> > prepare higher counter (v-blocking) (stellar-core line 1919)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_prepare_higher_counter_vblocking() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
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

    assert!(scp.bump_state(0, a_value.clone()));

    // prepared A1
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // v-blocking PREPARE(B2) → bump to A2
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), None, 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 3);
    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a1),
        0,
        0,
        None,
    );
    assert!(!scp.has_ballot_timer());

    // more timeout from vBlocking set → bump to A3
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b3.clone(), None, 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash,
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
// start <1,z> > prepared B (v-blocking) (stellar-core line 1935)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_prepared_b_vblocking_from_start() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
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

    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
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
// start <1,z> > prepare B (quorum) (stellar-core line 1942)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_prepare_b_quorum_from_start() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let b_value = x_value;
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
        qs_hash,
        0,
        &a1,
        Some(&b1),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// start <1,z> > confirm (v-blocking) > via CONFIRM (stellar-core line 1951)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_vblocking_via_confirm() {
    let (_x, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    scp.bump_timer_offset();
    scp.receive_envelope(make_confirm(&v1_id(), qs_hash, 0, 3, &a3, 3, 3));
    scp.receive_envelope(make_confirm(&v2_id(), qs_hash, 0, 4, &a4, 2, 4));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(&scp.get_env(1), &v0_id(), qs_hash, 0, 3, &a3, 3, 3);
    assert!(!scp.has_ballot_timer());
}

// ---------------------------------------------------------------------------
// start <1,z> > confirm (v-blocking) > via EXTERNALIZE (stellar-core line 1963)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_z_confirm_vblocking_via_externalize() {
    let (_x, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = z_value;
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

    scp.receive_envelope(make_externalize(&v1_id(), qs_hash, 0, &a2, 4));
    scp.receive_envelope(make_externalize(&v2_id(), qs_hash, 0, &a3, 5));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(
        &scp.get_env(1),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        3,
        u32::MAX,
    );
    assert!(!scp.has_ballot_timer());
}

// ===========================================================================

