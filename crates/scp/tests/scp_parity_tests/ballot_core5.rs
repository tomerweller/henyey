use super::*;

// ===========================================================================
// TEST CASES
// ===========================================================================

// ---------------------------------------------------------------------------
// ballot protocol core5 > "bumpState x"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_bump_state_x() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash0 = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    assert!(scp.bump_state(0, x_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    let expected_ballot = ScpBallot {
        counter: 1,
        value: x_value,
    };

    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &expected_ballot,
        None,
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepared A1"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_start_1x_prepared_a1() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let _b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };

    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);
    assert!(!scp.has_ballot_timer());

    // Receive quorum PREPARE for A1 → should emit PREPARE with prepared=A1
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );

    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepared A1" > "bump prepared A2"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_bump_prepared_a2() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Start and get A1 prepared
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);

    // Bump to (2,a)
    scp.bump_timer_offset();
    assert!(scp.scp.force_bump_state(0, a_value.clone()));
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

    // Receive quorum PREPARE for A2
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 4);
    verify_prepare(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        &a2,
        Some(&a2),
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > prepared A1 > bump A2 > "Confirm prepared A2"
// ---------------------------------------------------------------------------

/// Helper: set up scp through "Confirm prepared A2" state.
/// Returns the scp instance positioned for the "Accept commit" or other branches.
#[allow(clippy::type_complexity)]
pub(crate) fn setup_confirm_prepared_a2() -> (TestSCP, Value, Value, Value, Value, Hash256) {
    let (x_value, y_value, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = x_value.clone();
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
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

    // Confirm prepared A2: receive quorum PREPARE with prepared=A2
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 5);
    let qs_hash0 = qs_hash;
    verify_prepare(
        &scp.get_env(4),
        &v0_id(),
        qs_hash0,
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

#[test]
fn test_ballot_core5_confirm_prepared_a2() {
    let (_scp, _x, _y, _z, _zz, _qs_hash) = setup_confirm_prepared_a2();
    // Just verifying setup completes without panic
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > Accept commit > Quorum A2
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_quorum_a2() {
    let (scp, x_value, _y_value, _z_value, _zz_value, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // Receive quorum PREPARE with nC=2 nH=2 → should emit CONFIRM
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 2, &a2, 2, 2);
    assert!(!scp.has_ballot_timer_upcoming());
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > Accept commit > Quorum A2 > Quorum prepared A3
// > Accept more commit A3 > Quorum externalize A3
// (Full happy path to externalization)
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_full_externalization_path() {
    let (scp, x_value, _y_value, _z_value, _zz_value, qs_hash) = setup_confirm_prepared_a2();
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

    // Accept commit: quorum PREPARE with nC=2 nH=2
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a2.clone(), Some(a2.clone()), 2, 2, None),
    );
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 2, &a2, 2, 2);

    // Quorum prepared A3: v-blocking PREPARE with A3
    // First send manually to debug
    let gen_a3_prep = make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None);
    let e1 = gen_a3_prep(&v1_id());
    let e2 = gen_a3_prep(&v2_id());
    scp.bump_timer_offset();
    let before = scp.envs_len();
    eprintln!("Before v-blocking PREPARE(A3): envs_len={}", before);
    let r1 = scp.receive_envelope(e1);
    eprintln!(
        "After v1 PREPARE(A3): envs_len={}, result={:?}",
        scp.envs_len(),
        r1
    );
    assert_eq!(
        scp.envs_len(),
        before,
        "v-blocking: first message should not emit"
    );
    let r2 = scp.receive_envelope(e2);
    eprintln!(
        "After v2 PREPARE(A3): envs_len={}, result={:?}",
        scp.envs_len(),
        r2
    );
    assert_eq!(
        scp.envs_len(),
        before + 1,
        "v-blocking: second message should emit exactly 1"
    );
    verify_confirm(&scp.get_env(6), &v0_id(), qs_hash0, 0, 2, &a3, 2, 2);

    // Now quorum PREPARE A3 prepared=A2 nC=2 nH=2 to bump nPrepared to 3
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a2.clone()), 2, 2, None),
        true,
    );
    assert_eq!(scp.envs_len(), 8);
    verify_confirm(&scp.get_env(7), &v0_id(), qs_hash0, 0, 3, &a3, 2, 2);

    // Accept more commit A3: quorum PREPARE with A3 nC=2 nH=3
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a3.clone(), Some(a3.clone()), 2, 3, None),
    );
    assert_eq!(scp.envs_len(), 9);
    verify_confirm(&scp.get_env(8), &v0_id(), qs_hash0, 0, 3, &a3, 2, 3);

    // Quorum externalize A3
    recv_quorum(&scp, &make_confirm_gen(qs_hash, 3, a3.clone(), 2, 3));
    assert_eq!(scp.envs_len(), 10);
    verify_externalize(&scp.get_env(9), &v0_id(), qs_hash0, 0, &a2, 3);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > Accept commit > v-blocking CONFIRM
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_confirm_a2() {
    let (scp, x_value, _y_value, _z_value, _zz_value, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // v-blocking CONFIRM for A2 → should emit CONFIRM
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 2, a2.clone(), 2, 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(&scp.get_env(5), &v0_id(), qs_hash0, 0, 2, &a2, 2, 2);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > Accept commit > v-blocking EXTERNALIZE
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_accept_commit_vblocking_externalize_a2() {
    let (scp, x_value, _y_value, _z_value, _zz_value, qs_hash) = setup_confirm_prepared_a2();
    let qs_hash0 = qs_hash;

    let a_value = x_value;
    let a2 = ScpBallot {
        counter: 2,
        value: a_value.clone(),
    };

    // v-blocking EXTERNALIZE for A2 → should emit CONFIRM with infinite ballot
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a2.clone(), 2));
    assert_eq!(scp.envs_len(), 6);
    verify_confirm(
        &scp.get_env(5),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &ScpBallot {
            counter: u32::MAX,
            value: a_value.clone(),
        },
        2,
        u32::MAX,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "normal round (1,x)" — full happy path
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_normal_round() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    nodes_all_pledge_to_commit(&scp, &x_value, qs_hash);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // At this point envs has 3 entries:
    // 0: PREPARE(1,x)
    // 1: PREPARE(1,x) prepared=(1,x)
    // 2: PREPARE(1,x) prepared=(1,x) nC=1 nH=1

    // Receive quorum PREPARE with nC=1 nH=1 → should emit CONFIRM
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, b.clone(), Some(b.clone()), 1, 1, None),
    );
    assert_eq!(scp.envs_len(), 4);
    verify_confirm(&scp.get_env(3), &v0_id(), qs_hash0, 0, 1, &b, 1, 1);

    // Receive quorum CONFIRM → should emit EXTERNALIZE
    recv_quorum(&scp, &make_confirm_gen(qs_hash, 1, b.clone(), 1, 1));
    assert_eq!(scp.envs_len(), 5);
    verify_externalize(&scp.get_env(4), &v0_id(), qs_hash0, 0, &b, 1);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "non validator watching the network"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_non_validator_watching() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new_non_validator(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // In stellar-core, bumpState returns true for non-validators (internal state is
    // updated via emitCurrentStateStatement, but sendLatestEnvelope is a no-op).
    assert!(scp.bump_state(0, x_value.clone()));
    // No envelopes emitted (non-validator doesn't broadcast)
    assert_eq!(scp.envs_len(), 0);

    // Receive quorum EXTERNALIZE messages
    let ext1 = make_externalize(&v1_id(), qs_hash, 0, &b, 1);
    let ext2 = make_externalize(&v2_id(), qs_hash, 0, &b, 1);
    let ext3 = make_externalize(&v3_id(), qs_hash, 0, &b, 1);
    let ext4 = make_externalize(&v4_id(), qs_hash, 0, &b, 1);

    scp.receive_envelope(ext1);
    scp.receive_envelope(ext2);
    scp.receive_envelope(ext3);
    // After quorum EXTERNALIZE, still no emitted envelopes (non-validator)
    assert_eq!(scp.envs_len(), 0);
    // stellar-core verifies internal CONFIRM state here via getCurrentEnvelope

    scp.receive_envelope(ext4);
    // Still no emitted envelopes
    assert_eq!(scp.envs_len(), 0);

    // Value should be externalized
    assert_eq!(scp.externalized_value(0), Some(x_value));
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "restore ballot protocol"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_restore_prepare() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // Create a PREPARE envelope from self
    let prepare = make_prepare(&v0_id(), qs_hash, 0, &b, Some(&b), 0, 0, None);

    // Restore state from this envelope
    let result = scp.scp.set_state_from_envelope(&prepare);
    assert!(result, "set_state_from_envelope should succeed for PREPARE");

    // Should be able to receive further messages
    assert_eq!(scp.envs_len(), 0); // No new emissions from restore
}

#[test]
fn test_ballot_core5_restore_confirm() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    let confirm = make_confirm(&v0_id(), qs_hash, 0, 1, &b, 1, 1);
    let result = scp.scp.set_state_from_envelope(&confirm);
    assert!(result, "set_state_from_envelope should succeed for CONFIRM");
}

#[test]
fn test_ballot_core5_restore_externalize() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    let externalize = make_externalize(&v0_id(), qs_hash, 0, &b, 1);
    let result = scp.scp.set_state_from_envelope(&externalize);
    assert!(
        result,
        "set_state_from_envelope should succeed for EXTERNALIZE"
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepared B (v-blocking)"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepared_b_vblocking() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking PREPARE for B1 with prepared=B1
    // Since B > A, this should update our prepared' to B1
    recv_v_blocking(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), Some(b1.clone()), 0, 0, None),
    );
    assert_eq!(scp.envs_len(), 2);
    // Should emit PREPARE(1,a) with prepared'=B1
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
// ballot protocol core5 > "start <1,x>" > "confirm (v-blocking)" > "via CONFIRM"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_vblocking_via_confirm() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let _b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking CONFIRM for A1 → should emit CONFIRM
    recv_v_blocking(&scp, &make_confirm_gen(qs_hash, 1, a1.clone(), 1, 1));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(&scp.get_env(1), &v0_id(), qs_hash0, 0, 1, &a1, 1, 1);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "confirm (v-blocking)" > "via EXTERNALIZE"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_confirm_vblocking_via_externalize() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // v-blocking EXTERNALIZE for A1 → should emit CONFIRM with nPrepared=MAX, nH=MAX
    recv_v_blocking(&scp, &make_externalize_gen(qs_hash, a1.clone(), 1));
    assert_eq!(scp.envs_len(), 2);
    verify_confirm(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        u32::MAX,
        &ScpBallot {
            counter: u32::MAX,
            value: a_value.clone(),
        },
        1,
        u32::MAX,
    );
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "start <1,x>" > "prepare B (quorum)"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_prepare_b_quorum() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);

    // Quorum PREPARE for B1 → should accept B1 as prepared.
    // delayedQuorum=true because v0 voted for A1, not B1, so quorum for B1
    // isn't reached until the 4th external node (v1+v2+v3+v4 = 4 nodes).
    recv_quorum_checks_ex(
        &scp,
        &make_prepare_gen(qs_hash, b1.clone(), None, 0, 0, None),
        true,
        true, // delayedQuorum
        true, // checkUpcoming
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
// ballot protocol core5 > "start <1,x>" > "prepared A1" >
// "switch prepared B1 from A1" > "v-blocking switches to previous value of p"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_switch_prepared_b1_from_a1() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let b_value = &z_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start and get A1 prepared
    assert!(scp.bump_state(0, a_value.clone()));
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );
    assert_eq!(scp.envs_len(), 2);
    verify_prepare(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        Some(&a1),
        0,
        0,
        None,
    );

    // v-blocking PREPARE for B1 with prepared=B1
    // Should switch p to B1, p' to A1
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
}

// ---------------------------------------------------------------------------
// ballot protocol core3 tests
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core3_prepared_b1_quorum_votes_b1() {
    let (x_value, _y_value, z_value, _zz_value) = setup_values();
    let qs = make_core3_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    // In core3 with threshold=2:
    // v-blocking set size = 1 (3 - 2 + 1 = 2, but actually min = 1 for t=2,n=3...
    // actually n-t+1 = 3-2+1 = 2, so v-blocking needs 2 nodes.)
    // quorum needs 2 nodes

    let a_value = &x_value; // aValue = xValue (smaller)
    let b_value = &z_value; // bValue = zValue (larger)
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };
    let b1 = ScpBallot {
        counter: 1,
        value: b_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));
    assert_eq!(scp.envs_len(), 1);
    verify_prepare(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &a1,
        None,
        0,
        0,
        None,
    );

    // In a 3-node quorum with threshold=2:
    // v0 voted A1, v1 votes B1, v2 votes B1.
    // v0 did NOT vote for B1 (incompatible value), so v0 is excluded from the
    // "voted to prepare B1" set. We need {v1, v2} to form a quorum for B1.
    // stellar-core uses recvQuorumChecks which sends from both v1 and v2.
    let prepare1 = make_prepare(&v1_id(), qs_hash, 0, &b1, None, 0, 0, None);
    let prepare2 = make_prepare(&v2_id(), qs_hash, 0, &b1, None, 0, 0, None);
    scp.receive_envelope(prepare1);
    // After v1 alone, quorum may not be reached yet (v0 didn't vote B1)
    scp.receive_envelope(prepare2);
    // Now {v1, v2} forms a quorum for B1 (threshold=2, both voted B1)
    assert_eq!(scp.envs_len(), 2);
    // Should have B1 as prepared (since quorum voted for B1)
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
// ballot protocol core5 > "range check"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_range_check() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let _qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    nodes_all_pledge_to_commit(&scp, &x_value, qs_hash);

    let _b = ScpBallot {
        counter: 1,
        value: x_value.clone(),
    };

    // envs[0..3] from nodes_all_pledge_to_commit

    // Receive CONFIRM messages with different commit ranges
    // nC=2, nH=4 (commit range [2,4])
    let c1 = make_confirm(
        &v1_id(),
        qs_hash,
        0,
        2,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );
    let c2 = make_confirm(
        &v2_id(),
        qs_hash,
        0,
        2,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );
    let c3 = make_confirm(
        &v3_id(),
        qs_hash,
        0,
        2,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );
    let c4 = make_confirm(
        &v4_id(),
        qs_hash,
        0,
        2,
        &ScpBallot {
            counter: 4,
            value: x_value.clone(),
        },
        2,
        4,
    );

    scp.receive_envelope(c1);
    scp.receive_envelope(c2);
    scp.receive_envelope(c3);
    // After quorum CONFIRM, should emit CONFIRM
    assert!(scp.envs_len() >= 4);
    scp.receive_envelope(c4);
}

// ---------------------------------------------------------------------------
// ballot protocol core5 > "timeout when h is set -> stay locked on h"
// ---------------------------------------------------------------------------

#[test]
fn test_ballot_core5_timeout_stay_locked_on_h() {
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let _qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let a_value = &x_value;
    let a1 = ScpBallot {
        counter: 1,
        value: a_value.clone(),
    };

    // Start with aValue
    assert!(scp.bump_state(0, a_value.clone()));

    // Get A1 prepared
    recv_quorum_ex(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), None, 0, 0, None),
        true,
    );

    // Confirm prepared A1 (quorum says prepared=A1)
    recv_quorum(
        &scp,
        &make_prepare_gen(qs_hash, a1.clone(), Some(a1.clone()), 0, 0, None),
    );

    // Now we have nC=1 nH=1 (confirmed prepared A1, h is set)
    // Timeout with value y should stay locked on h (= A1 value = x)
    scp.bump_timer_offset();
    scp.scp.force_bump_state(0, y_value.clone());

    // The bumped ballot should use x (locked on h), not y
    let last = scp.get_env(scp.envs_len() - 1);
    if let ScpStatementPledges::Prepare(prep) = &last.statement.pledges {
        assert_eq!(
            prep.ballot.value, *a_value,
            "should stay locked on h value (x), not switch to y"
        );
    } else {
        panic!("expected PREPARE envelope after bump");
    }
}

