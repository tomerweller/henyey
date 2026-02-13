use super::*;

// ---------------------------------------------------------------------------
// Nomination tests core5
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v0_is_top_nominates_x() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 is top (priority=1000 in our driver)
    // Nominate x
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![],
    );
}

// ---------------------------------------------------------------------------
// Nomination tests core5 > "v0 is top" > "others nominate x → prepare x" setup
// C++ SCPTests.cpp lines 2805-2866
// ---------------------------------------------------------------------------

/// Shared setup: drives nomination through "others nominate x → prepare x".
///
/// At exit:
/// - env[0] = NOMINATE(votes=[x], accepted=[])
/// - env[1] = NOMINATE(votes=[x], accepted=[x])
/// - env[2] = PREPARE(1, x)
/// - Total: 3 envelopes
///
/// Returns (scp, x_value, y_value, k_value, qs_hash, qs_hash0) ready for
/// the nested SECTION tests that extend this state.
#[allow(clippy::type_complexity)]
fn setup_nomination_others_nominate_x_prepare_x() -> (TestSCP, Value, Value, Value, Hash256, Hash256)
{
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 nominates x
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![],
    );

    // Others vote for x
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom4 = make_nominate(&v4_id(), qs_hash, 0, vec![x_value.clone()], vec![]);

    // nothing happens yet
    scp.receive_envelope(nom1);
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 1);

    // this causes 'x' to be accepted (quorum)
    scp.receive_envelope(nom3);
    assert_eq!(scp.envs_len(), 2);

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(x_value.clone());

    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    // extra message doesn't do anything
    scp.receive_envelope(nom4);
    assert_eq!(scp.envs_len(), 2);

    // Others accept x
    let acc1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc2 = make_nominate(
        &v2_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc3 = make_nominate(
        &v3_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc4 = make_nominate(
        &v4_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    // nothing happens yet
    scp.receive_envelope(acc1);
    scp.receive_envelope(acc2);
    assert_eq!(scp.envs_len(), 2);

    scp.driver().set_composite_value(x_value.clone());
    // this causes the node to send a prepare message (quorum)
    scp.receive_envelope(acc3);
    assert_eq!(scp.envs_len(), 3);

    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 1,
            value: x_value.clone(),
        },
        None,
        0,
        0,
        None,
    );

    scp.receive_envelope(acc4);
    assert_eq!(scp.envs_len(), 3);

    (scp, x_value, y_value, k_value, qs_hash, qs_hash0)
}

#[test]
fn test_nomination_core5_others_nominate_x_prepare_x() {
    // Just verify the setup completes successfully
    let (_scp, _x, _y, _k, _qs_hash, _qs_hash0) = setup_nomination_others_nominate_x_prepare_x();
}

// ---------------------------------------------------------------------------
// "nominate x → accept x → prepare (x) ; others accepted y → update latest to (z=x+y)"
// C++ SCPTests.cpp lines 2871-2904
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_others_accepted_y_update_latest() {
    let (scp, x_value, y_value, k_value, qs_hash, qs_hash0) =
        setup_nomination_others_nominate_x_prepare_x();

    // votes2 = [x, y]
    let votes2 = vec![x_value.clone(), y_value.clone()];

    let acc1_2 = make_nominate(&v1_id(), qs_hash, 0, votes2.clone(), votes2.clone());
    let acc2_2 = make_nominate(&v2_id(), qs_hash, 0, votes2.clone(), votes2.clone());
    let acc3_2 = make_nominate(&v3_id(), qs_hash, 0, votes2.clone(), votes2.clone());
    let acc4_2 = make_nominate(&v4_id(), qs_hash, 0, votes2.clone(), votes2.clone());

    scp.receive_envelope(acc1_2);
    assert_eq!(scp.envs_len(), 3);

    // v-blocking
    scp.receive_envelope(acc2_2);
    assert_eq!(scp.envs_len(), 4);
    verify_nominate(
        &scp.get_env(3),
        &v0_id(),
        qs_hash0,
        0,
        votes2.clone(),
        votes2.clone(),
    );

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    expected.insert(y_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(k_value.clone());

    // this updates the composite value to use next time
    // but does not prepare it
    scp.receive_envelope(acc3_2);
    assert_eq!(scp.envs_len(), 4);

    assert_eq!(scp.get_latest_composite_candidate(0), Some(k_value.clone()));

    scp.receive_envelope(acc4_2);
    assert_eq!(scp.envs_len(), 4);
}

// ---------------------------------------------------------------------------
// "nomination - restored state / ballot protocol not started"
// C++ SCPTests.cpp lines 2956-2964
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_restored_state_ballot_not_started() {
    let (_scp, x_value, _y_value, _k_value, qs_hash, qs_hash0) =
        setup_nomination_others_nominate_x_prepare_x();

    // Create a fresh SCP (scp2) and restore from the original's nomination state
    let qs = make_core5_quorum_set();
    let scp2 = TestSCP::new(v0_id(), qs.clone());
    scp2.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // At this point: votes = { x }, accepted = { x }
    let votes = vec![x_value.clone()];
    let accepted = vec![x_value.clone()];

    // Restore from the previous state
    let restore_env = make_nominate(&v0_id(), qs_hash0, 0, votes.clone(), accepted.clone());
    scp2.set_state_from_envelope(&restore_env);

    // tries to start nomination with yValue, but picks
    // xValue since it was already in the votes
    let (_, y_value, _, _) = setup_values();
    assert!(!scp2.nominate(0, y_value, &empty_value));
    assert_eq!(scp2.envs_len(), 0);

    // Recreate the nominate envelopes from the original setup
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, vec![x_value.clone()], vec![]);

    // other nodes vote for 'x'
    scp2.receive_envelope(nom1);
    scp2.receive_envelope(nom2);
    assert_eq!(scp2.envs_len(), 0);

    // 'x' is accepted (quorum)
    // but because the restored state already included
    // 'x' in the accepted set, no new message is emitted
    scp2.receive_envelope(nom3);

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp2.driver().set_expected_candidates(expected);
    scp2.driver().set_composite_value(x_value.clone());

    // other nodes emit 'x' as accepted
    let acc1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc2 = make_nominate(
        &v2_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc3 = make_nominate(
        &v3_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    scp2.receive_envelope(acc1);
    scp2.receive_envelope(acc2);
    assert_eq!(scp2.envs_len(), 0);

    scp2.driver().set_composite_value(x_value.clone());
    // this causes the node to update its composite value to x
    scp2.receive_envelope(acc3);

    // nomination ended up starting the ballot protocol
    assert_eq!(scp2.envs_len(), 1);

    verify_prepare(
        &scp2.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 1,
            value: x_value.clone(),
        },
        None,
        0,
        0,
        None,
    );
}

// ---------------------------------------------------------------------------
// "nomination - restored state / ballot protocol started (on value k)"
// C++ SCPTests.cpp lines 2965-2975
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_restored_state_ballot_started() {
    let (_scp, x_value, _y_value, k_value, qs_hash, qs_hash0) =
        setup_nomination_others_nominate_x_prepare_x();

    // Create a fresh SCP (scp2) and restore from the original's nomination state
    let qs = make_core5_quorum_set();
    let scp2 = TestSCP::new(v0_id(), qs.clone());
    scp2.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // At this point: votes = { x }, accepted = { x }
    let votes = vec![x_value.clone()];
    let accepted = vec![x_value.clone()];

    // First restore ballot protocol state (on value k)
    let ballot_restore_env = make_prepare(
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 1,
            value: k_value.clone(),
        },
        None,
        0,
        0,
        None,
    );
    scp2.set_state_from_envelope(&ballot_restore_env);

    // Then do the nomination restore
    let nom_restore_env = make_nominate(&v0_id(), qs_hash0, 0, votes.clone(), accepted.clone());
    scp2.set_state_from_envelope(&nom_restore_env);

    // tries to start nomination with yValue, but picks
    // xValue since it was already in the votes
    let (_, y_value, _, _) = setup_values();
    assert!(!scp2.nominate(0, y_value, &empty_value));
    assert_eq!(scp2.envs_len(), 0);

    // Recreate the nominate envelopes from the original setup
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, vec![x_value.clone()], vec![]);

    // other nodes vote for 'x'
    scp2.receive_envelope(nom1);
    scp2.receive_envelope(nom2);
    assert_eq!(scp2.envs_len(), 0);
    scp2.receive_envelope(nom3);

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp2.driver().set_expected_candidates(expected);
    scp2.driver().set_composite_value(x_value.clone());

    // other nodes emit 'x' as accepted
    let acc1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc2 = make_nominate(
        &v2_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc3 = make_nominate(
        &v3_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    scp2.receive_envelope(acc1);
    scp2.receive_envelope(acc2);
    assert_eq!(scp2.envs_len(), 0);

    scp2.driver().set_composite_value(x_value.clone());
    scp2.receive_envelope(acc3);

    // nomination didn't do anything (already working on k)
    assert_eq!(scp2.envs_len(), 0);
}

// ---------------------------------------------------------------------------
// "receive more messages, then v0 switches to a different leader"
// C++ SCPTests.cpp lines 2978-3005
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_switch_leader() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 nominates x (v0 is top)
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);

    // Receive messages from non-leaders
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![k_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![_y_value.clone()], vec![]);

    // nothing more happens
    scp.receive_envelope(nom1);
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 1);

    // switch leader to v1
    scp.set_priority_node(v1_id());
    assert!(scp.nominate_timeout(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 2);

    // votesXK sorted
    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    verify_nominate(&scp.get_env(1), &v0_id(), qs_hash0, 0, votes_xk, vec![]);
}

// ---------------------------------------------------------------------------
// "select accepted value from leader / receive accepted before timeout"
// C++ SCPTests.cpp lines 3020-3055
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_select_accepted_before_timeout() {
    let (x_value, y_value, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 nominates x
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);

    // Update round leader to v1
    scp.set_priority_node(v1_id());

    let nom1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![y_value.clone(), z_value.clone()],
        vec![y_value.clone()],
    );

    // receive accepted before timeout
    // nothing more happens, v0 is leader
    scp.receive_envelope(nom1);
    assert_eq!(scp.envs_len(), 1);

    // Update round leaders, vote for accepted value (y)
    assert!(scp.nominate_timeout(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 2);

    // Common tail: verify nominate envelope and test additional nom2
    let votes_xy = vec![x_value.clone(), y_value.clone()];
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        votes_xy.clone(),
        vec![],
    );

    let nom2 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![y_value.clone(), z_value.clone(), zz_value.clone()],
        vec![y_value.clone()],
    );
    scp.receive_envelope(nom2);
    // Nothing happens, as v0 already voted for the accepted value (y)
    assert_eq!(scp.envs_len(), 2);
    verify_nominate(&scp.get_env(1), &v0_id(), qs_hash0, 0, votes_xy, vec![]);
}

// ---------------------------------------------------------------------------
// "select accepted value from leader / receive accepted after timeout"
// C++ SCPTests.cpp lines 3030-3055
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_select_accepted_after_timeout() {
    let (x_value, y_value, z_value, zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 nominates x
    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);

    // Update round leader to v1
    scp.set_priority_node(v1_id());

    let nom1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![y_value.clone(), z_value.clone()],
        vec![y_value.clone()],
    );

    // receive accepted after timeout
    assert!(!scp.nominate_timeout(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);

    // Vote for accepted value (y)
    scp.receive_envelope(nom1);
    assert_eq!(scp.envs_len(), 2);

    // Common tail: verify nominate envelope and test additional nom2
    let votes_xy = vec![x_value.clone(), y_value.clone()];
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        votes_xy.clone(),
        vec![],
    );

    let nom2 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![y_value.clone(), z_value.clone(), zz_value.clone()],
        vec![y_value.clone()],
    );
    scp.receive_envelope(nom2);
    // Nothing happens, as v0 already voted for the accepted value (y)
    assert_eq!(scp.envs_len(), 2);
    verify_nominate(&scp.get_env(1), &v0_id(), qs_hash0, 0, votes_xy, vec![]);
}

// ---------------------------------------------------------------------------
// "self nominates 'x', others nominate y → prepare y / others only vote for y"
// C++ SCPTests.cpp lines 3078-3101
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_others_vote_y() {
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let mut my_votes = vec![x_value.clone()];

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(x_value.clone());

    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        my_votes.clone(),
        vec![],
    );

    let votes = vec![y_value.clone()];

    // Others only vote for y (no accepted)
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, votes.clone(), vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes.clone(), vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, votes.clone(), vec![]);
    let nom4 = make_nominate(&v4_id(), qs_hash, 0, votes.clone(), vec![]);

    // nothing happens yet
    scp.receive_envelope(nom1);
    scp.receive_envelope(nom2);
    scp.receive_envelope(nom3);
    assert_eq!(scp.envs_len(), 1);

    // 'y' is accepted (quorum)
    scp.receive_envelope(nom4);
    assert_eq!(scp.envs_len(), 2);
    my_votes.push(y_value.clone());
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        my_votes,
        vec![y_value.clone()],
    );
}

// ---------------------------------------------------------------------------
// "self nominates 'x', others nominate y → prepare y / others accepted y"
// C++ SCPTests.cpp lines 3102-3136
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_others_accepted_y() {
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;
    let scp = TestSCP::new(v0_id(), qs.clone());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let mut my_votes = vec![x_value.clone()];

    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(x_value.clone());

    assert!(scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        my_votes.clone(),
        vec![],
    );

    let votes = vec![y_value.clone()];
    let accepted_y = vec![y_value.clone()];

    // Others accepted y
    let acc1 = make_nominate(&v1_id(), qs_hash, 0, votes.clone(), accepted_y.clone());
    let acc2 = make_nominate(&v2_id(), qs_hash, 0, votes.clone(), accepted_y.clone());
    let acc3 = make_nominate(&v3_id(), qs_hash, 0, votes.clone(), accepted_y.clone());
    let acc4 = make_nominate(&v4_id(), qs_hash, 0, votes.clone(), accepted_y.clone());

    scp.receive_envelope(acc1);
    assert_eq!(scp.envs_len(), 1);

    // this causes 'y' to be accepted (v-blocking)
    scp.receive_envelope(acc2);
    assert_eq!(scp.envs_len(), 2);

    my_votes.push(y_value.clone());
    verify_nominate(&scp.get_env(1), &v0_id(), qs_hash0, 0, my_votes, accepted_y);

    let mut expected2 = BTreeSet::new();
    expected2.insert(y_value.clone());
    scp.driver().set_expected_candidates(expected2);
    scp.driver().set_composite_value(y_value.clone());

    // this causes the node to send a prepare message (quorum)
    scp.receive_envelope(acc3);
    assert_eq!(scp.envs_len(), 3);

    verify_prepare(
        &scp.get_env(2),
        &v0_id(),
        qs_hash0,
        0,
        &ScpBallot {
            counter: 1,
            value: y_value.clone(),
        },
        None,
        0,
        0,
        None,
    );

    scp.receive_envelope(acc4);
    assert_eq!(scp.envs_len(), 3);
}

// ---------------------------------------------------------------------------
// "value from v1 is a candidate, self should not introduce new value on timeout"
// C++ SCPTests.cpp lines 3191-3244
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v1_candidate_no_new_value_on_timeout() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    // v1 is top node
    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // v0 is not leader (v1 is), so nominate returns false
    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);

    // Receive x from v1, vote for it
    let nom1 = make_nominate(&v1_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, vec![x_value.clone()], vec![]);
    let nom3 = make_nominate(&v3_id(), qs_hash, 0, vec![x_value.clone()], vec![]);

    scp.receive_envelope(nom1);
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![],
    );

    scp.receive_envelope(nom2);
    scp.receive_envelope(nom3);
    assert_eq!(scp.envs_len(), 2);
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    let acc1 = make_nominate(
        &v1_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc2 = make_nominate(
        &v2_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );
    let acc3 = make_nominate(
        &v3_id(),
        qs_hash,
        0,
        vec![x_value.clone()],
        vec![x_value.clone()],
    );

    scp.receive_envelope(acc1);
    scp.receive_envelope(acc2);
    assert_eq!(scp.envs_len(), 2);

    // Receive accept from quorum, ratify and generate a candidate value
    assert!(scp.has_nomination_timer());
    scp.driver().set_composite_value(x_value.clone());
    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.receive_envelope(acc3);
    assert_eq!(scp.envs_len(), 3);
    // Timer is cancelled
    assert!(!scp.has_nomination_timer());

    // v0 is the new leader, but we already have a candidate
    scp.set_priority_node(v0_id());
    assert!(!scp.nominate_timeout(0, k_value, &empty_value));
}

// ---------------------------------------------------------------------------
// "nomination waits for v1"
// C++ SCPTests.cpp lines 3245-3290
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_nomination_waits_for_v1() {
    let (x_value, y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    // v1 is top node
    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let votes_xy = vec![x_value.clone(), y_value.clone()];
    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    let nom1 = make_nominate(&v1_id(), qs_hash, 0, votes_xy.clone(), vec![]);
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes_xk.clone(), vec![]);

    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);

    let nom4 = make_nominate(&v4_id(), qs_hash, 0, votes_xk.clone(), vec![]);

    // nothing happens with non top nodes
    scp.receive_envelope(nom2);
    // (note: don't receive anything from node3 - we want to pick
    // another dead node)
    assert_eq!(scp.envs_len(), 0);

    // v1 is leader -> nominate the first value from its message
    // that's "y" (the value with highest hash from v1's votes that
    // v0 hasn't already voted for)
    scp.receive_envelope(nom1);
    assert_eq!(scp.envs_len(), 1);
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![y_value.clone()],
        vec![],
    );

    scp.receive_envelope(nom4);
    assert_eq!(scp.envs_len(), 1);

    // "timeout -> pick another value from v1"
    let mut expected = BTreeSet::new();
    expected.insert(x_value.clone());
    scp.driver().set_expected_candidates(expected);
    scp.driver().set_composite_value(x_value.clone());

    // allows to pick another leader,
    // pick another dead node v3 as to force picking up
    // a new value from v1
    scp.set_priority_node(v3_id());

    // note: value passed in here should be ignored
    assert!(scp.nominate_timeout(0, k_value, &empty_value));
    // picks up 'x' from v1 (as we already have 'y')
    // which also happens to cause 'x' to be accepted
    assert_eq!(scp.envs_len(), 2);
    verify_nominate(
        &scp.get_env(1),
        &v0_id(),
        qs_hash0,
        0,
        votes_xy.clone(),
        vec![x_value.clone()],
    );
}

// ---------------------------------------------------------------------------
// Nomination tests core5 > v1 is top > "v1 dead, timeout" > "v0 is new top node"
// C++ SCPTests.cpp line 3291-3314
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v1_dead_timeout_v0_becomes_top() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    // k_value is independent (matches stellar-core kValue = sha256(d))
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    // Create SCP where v1 has highest priority (matching stellar-core line 3150)
    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    // votesXK = sorted [x, k]
    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    // nom2 = NOMINATE from v2 with votes [x, k] (stellar-core line 3188)
    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes_xk, vec![]);

    // stellar-core line 3293: v0 is not leader (v1 is), so nominate returns false
    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);

    // stellar-core line 3297: receive nom2 from v2 (not leader, so no new envelopes)
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 0);

    // stellar-core line 3304: change priority to v0
    scp.set_priority_node(v0_id());

    // stellar-core line 3308: timeout nomination — v0 is now top, should emit
    assert!(scp.nominate_timeout(0, x_value.clone(), &empty_value));

    // stellar-core line 3312: exactly 1 envelope emitted
    assert_eq!(scp.envs_len(), 1);

    // stellar-core line 3313: NOMINATE(votes=[x], accepted=[])
    verify_nominate(
        &scp.get_env(0),
        &v0_id(),
        qs_hash0,
        0,
        vec![x_value.clone()],
        vec![],
    );
}

// ---------------------------------------------------------------------------
// Nomination tests core5 > v1 is top > "v1 dead, timeout" > "v2 is new top node"
// C++ SCPTests.cpp line 3316-3333
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v1_dead_timeout_v2_becomes_top() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);
    let qs_hash0 = qs_hash;

    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes_xk, vec![]);

    // Same setup as v0 test
    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 0);

    // stellar-core line 3318: change priority to v2
    scp.set_priority_node(v2_id());

    // stellar-core line 3322: timeout nomination — v2 is now top leader
    assert!(scp.nominate_timeout(0, x_value.clone(), &empty_value));

    // stellar-core line 3326: exactly 1 envelope emitted
    assert_eq!(scp.envs_len(), 1);

    // stellar-core line 3327-3332: v2 votes for XK, but nomination only picks the highest value
    // std::max(xValue, kValue) — pick the larger of x and k
    let v2_top = std::cmp::max(x_value.clone(), k_value.clone());
    verify_nominate(&scp.get_env(0), &v0_id(), qs_hash0, 0, vec![v2_top], vec![]);
}

// ---------------------------------------------------------------------------
// Nomination tests core5 > v1 is top > "v1 dead, timeout" > "v3 is new top node"
// C++ SCPTests.cpp line 3334-3345
// ---------------------------------------------------------------------------

#[test]
fn test_nomination_core5_v1_dead_timeout_v3_becomes_top() {
    let (x_value, _y_value, _z_value, _zz_value) = setup_values();
    let k_value = Value(vec![0xFFu8; 32].try_into().unwrap());
    let qs = make_core5_quorum_set();
    let qs_hash = quorum_set_hash(&qs);

    let scp = TestSCP::new_with_priority(v0_id(), qs.clone(), v1_id());
    scp.store_quorum_set(&qs);

    let empty_value = Value(vec![].try_into().unwrap());

    let mut votes_xk = vec![x_value.clone(), k_value.clone()];
    votes_xk.sort();

    let nom2 = make_nominate(&v2_id(), qs_hash, 0, votes_xk, vec![]);

    // Same setup
    assert!(!scp.nominate(0, x_value.clone(), &empty_value));
    assert_eq!(scp.envs_len(), 0);
    scp.receive_envelope(nom2);
    assert_eq!(scp.envs_len(), 0);

    // stellar-core line 3336: change priority to v3
    scp.set_priority_node(v3_id());

    // stellar-core line 3340: nothing happens — we don't have any message for v3
    assert!(!scp.nominate_timeout(0, x_value.clone(), &empty_value));

    // stellar-core line 3344: no envelopes emitted
    assert_eq!(scp.envs_len(), 0);
}

