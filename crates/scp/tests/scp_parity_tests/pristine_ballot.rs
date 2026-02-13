use super::*;

// "start from pristine" tests (stellar-core lines 1979-2199)
// Same test suite as "start <1,x>" but only keeping transitions observable
// when starting from empty (no bumpState call).
// aValue = xValue (smaller), bValue = zValue (larger)
// ===========================================================================

/// Helper: receives quorum of PREPARE(A1) from pristine state (no bumpState).
/// No envelope expected since we're starting from empty.
fn setup_pristine_prepared_a1(scp: &TestSCP, qs_hash: Hash256, a1: &ScpBallot) {
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        false,
        false,
        false,
    );
    assert_eq!(scp.envs_len(), 0);
}

/// Helper: extends setup_pristine_prepared_a1, receives v-blocking PREPARE(A2, p=A2).
/// No envelope expected.
fn setup_pristine_confirm_prepared_a2(
    scp: &TestSCP,
    qs_hash: Hash256,
    a1: &ScpBallot,
    a2: &ScpBallot,
) {
    setup_pristine_prepared_a1(scp, qs_hash, a1);
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);
}

// -- "Confirm prepared A2" -> "Quorum A2"
#[test]
fn test_ballot_pristine_confirm_prepared_a2_quorum_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value;
    let _ = &b_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // extra v-blocking PREPARE(A2, p=A2) -> no-op
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // quorum PREPARE(A2, p=A2) -> emit PREPARE(A2, p=A2, nC=1, nH=2)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&a2),
        1,
        2,
        None,
    );
}

// -- "Confirm prepared A2" -> "Quorum B2"
#[test]
fn test_ballot_pristine_confirm_prepared_a2_quorum_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
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

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking PREPARE(B2, p=B2) -> no-op
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // quorum PREPARE(B2, p=B2) -> emit PREPARE(B2, p=B2, nC=2, nH=2, p'=A2)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        2,
        2,
        Some(&a2),
    );
}

// -- "Accept commit" -> "Quorum A2"
#[test]
fn test_ballot_pristine_accept_commit_quorum_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let _ = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // quorum PREPARE(A2, p=A2, nC=2, nH=2) -> emit CONFIRM(2, A2, 2, 2)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
}

// -- "Accept commit" -> "Quorum B2"
#[test]
fn test_ballot_pristine_accept_commit_quorum_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
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

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // quorum PREPARE(B2, p=B2, nC=2, nH=2) -> emit CONFIRM(2, B2, 2, 2)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, b2.clone(), Some(b2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 2, &b2, 2, 2);
}

// -- "Accept commit" -> "v-blocking" -> "CONFIRM A2"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_confirm_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let _ = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking CONFIRM(2, A2, 2, 2) -> emit CONFIRM(2, A2, 2, 2)
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, a2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 2, &a2, 2, 2);
}

// -- "Accept commit" -> "v-blocking" -> "CONFIRM A3..4"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_confirm_a3_a4() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let _ = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking CONFIRM(4, A4, 3, 4) -> emit CONFIRM(4, A4, 3, 4)
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 4, a4.clone(), 3, 4));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 4, &a4, 3, 4);
}

// -- "Accept commit" -> "v-blocking" -> "CONFIRM B2"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_confirm_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let _ = &x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking CONFIRM(2, B2, 2, 2) -> emit CONFIRM(2, B2, 2, 2)
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, b2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 2, &b2, 2, 2);
}

// -- "Accept commit" -> "v-blocking" -> "EXTERNALIZE A2"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_externalize_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let _ = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };
    let a_inf = ScpBallot {
        counter: u32::MAX,
        value: a_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking EXTERNALIZE(A2, 2) -> emit CONFIRM(MAX, AInf, 2, MAX)
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2.clone(), 2));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        2,
        u32::MAX,
    );
}

// -- "Accept commit" -> "v-blocking" -> "EXTERNALIZE B2"
#[test]
fn test_ballot_pristine_accept_commit_vblocking_externalize_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let _ = &x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: x_value.clone(),
    };
    let b2 = ScpBallot {
        counter: 2,
        value: b_value.clone(),
    };
    let b_inf = ScpBallot {
        counter: u32::MAX,
        value: b_value.clone(),
    };

    setup_pristine_confirm_prepared_a2(&scp, qs_hash, &a1, &a2);

    // v-blocking EXTERNALIZE(B2, 2) -> emit CONFIRM(MAX, BInf, 2, MAX)
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, b2.clone(), 2));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &b_inf,
        2,
        u32::MAX,
    );
}

// -- "Confirm prepared mixed" -> "mixed A2"
#[test]
fn test_ballot_pristine_confirm_prepared_mixed_a2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
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

    setup_pristine_prepared_a1(&scp, qs_hash, &a1);

    // a few nodes prepared A2 => causes p=A2
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // a few nodes prepared B2 => causes p=B2, p'=A2
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a2.clone(),
            Some(b2.clone()),
            0,
            0,
            Some(a2.clone()),
        ),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // causes h=A2, but c=0 as p >!~ h
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
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        &a2,
        Some(&b2),
        0,
        2,
        Some(&a2),
    );

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
    assert_eq!(scp.envs_len(), 1);
}

// -- "Confirm prepared mixed" -> "mixed B2"
#[test]
fn test_ballot_pristine_confirm_prepared_mixed_b2() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
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

    setup_pristine_prepared_a1(&scp, qs_hash, &a1);

    // a few nodes prepared A2 => causes p=A2
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // a few nodes prepared B2 => causes p=B2, p'=A2
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(
            qs_hash,
            a2.clone(),
            Some(b2.clone()),
            0,
            0,
            Some(a2.clone()),
        ),
        false,
    );
    assert_eq!(scp.envs_len(), 0);

    // causes h=B2, c=B2
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
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        &b2,
        Some(&b2),
        2,
        2,
        Some(&a2),
    );

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
    assert_eq!(scp.envs_len(), 1);
}

// -- "switch prepared B1"
#[test]
fn test_ballot_pristine_switch_prepared_b1() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let b_value = z_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    setup_pristine_prepared_a1(&scp, qs_hash, &a1);

    // v-blocking PREPARE(B1, p=B1) -> no envelope
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);
}

// -- "prepared B (v-blocking)"
#[test]
fn test_ballot_pristine_prepared_b_vblocking() {
    let (x_value, _y, z_value, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let _ = &x_value;
    let b_value = z_value.clone();
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // v-blocking PREPARE(B1, p=B1) from pristine -> no envelope
    recv_v_blocking_checks(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
        false,
    );
    assert_eq!(scp.envs_len(), 0);
}

// -- "confirm (v-blocking)" -> "via CONFIRM"
#[test]
fn test_ballot_pristine_confirm_vblocking_via_confirm() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value;
    let a3 = ScpBallot {
        counter: 3,
        value: a_value.clone(),
    };
    let a4 = ScpBallot {
        counter: 4,
        value: a_value.clone(),
    };

    // from pristine, receive v-blocking CONFIRMs
    scp.receive_envelope(make_confirm(&v1_id(), qs_hash, 0, 3, &a3, 3, 3));
    scp.receive_envelope(make_confirm(&v2_id(), qs_hash, 0, 4, &a4, 2, 4));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(&scp.get_env(0), &v0_id(), qs_hash, 0, 3, &a3, 3, 3);
}

// -- "confirm (v-blocking)" -> "via EXTERNALIZE"
#[test]
fn test_ballot_pristine_confirm_vblocking_via_externalize() {
    let (x_value, _y, _z, _zz) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
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

    // from pristine, receive v-blocking EXTERNALIZEs
    scp.receive_envelope(make_externalize(&v1_id(), qs_hash, 0, &a2, 4));
    scp.receive_envelope(make_externalize(&v2_id(), qs_hash, 0, &a3, 5));
    assert_eq!(scp.envs_len(), 1);
    verify_confirm(
        &scp.get_env(0),
        &v0_id(),
        qs_hash,
        0,
        u32::MAX,
        &a_inf,
        3,
        u32::MAX,
    );
}

// ===========================================================================

