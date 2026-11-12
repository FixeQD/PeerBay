use std::sync::Arc;
use std::time::Duration;

use peerbay_lib::protocol::{
    ChannelMigration, ChannelResumeCursor, ResumeError, ResumeKey, ResumeRejectionReason,
    SessionChannel, SessionResumeAccepted, SessionResumeRequest,
};
use peerbay_lib::session::{
    ChannelSeqSnapshot, MigrationConfig, MigrationFailure, MigrationPhase, MigrationPlan,
    MigrationTeardownSummary, ResumeAcceptOutcome, ResumeKeyStore, SessionResumeOutcome,
    TransportMigrationInitiator, TransportMigrationResponder,
};
use peerbay_lib::transport::{
    ChannelKind, InMemoryTransport, PeerEndpoint, Transport as _, TransportChannel, TransportKind,
};

use peerbay_lib::session::SessionState;

const SESSION_ID: &str = "session-migration-abandon-0001";
const NOW_MS: u64 = 1_000_000;

struct HandshakeFixture {
    a: Arc<InMemoryTransport>,
    b: Arc<InMemoryTransport>,
    old_a: TransportChannel,
    old_b: TransportChannel,
    new_channel: TransportChannel,
    request: SessionResumeRequest,
    initiator: TransportMigrationInitiator,
    responder: TransportMigrationResponder,
}

fn session_key(hex_pairs: &str) -> ResumeKey {
    ResumeKey::new(hex_pairs.repeat(32)).expect("fixture resume key is valid")
}

fn initiator_config() -> MigrationConfig {
    MigrationConfig::new(Duration::from_millis(200), Duration::from_millis(60))
}

fn responder_config() -> MigrationConfig {
    MigrationConfig::new(Duration::from_millis(200), Duration::from_millis(100))
}

fn endpoint(id: &str) -> PeerEndpoint {
    PeerEndpoint::new(id, "127.0.0.1:9", TransportKind::Loopback)
        .expect("fixture peer endpoint is valid")
}

fn in_memory_pair() -> (Arc<InMemoryTransport>, Arc<InMemoryTransport>) {
    let (a, b) = InMemoryTransport::pair(
        endpoint("00000000-0000-0000-0000-000000000001"),
        endpoint("00000000-0000-0000-0000-000000000002"),
    )
    .expect("fixture transport pair");
    (Arc::new(a), Arc::new(b))
}

fn control_cursor() -> ChannelResumeCursor {
    ChannelResumeCursor::new(SessionChannel::Control, 9, 12)
}

fn snapshot() -> ChannelSeqSnapshot {
    ChannelSeqSnapshot {
        channel: SessionChannel::Control,
        last_sent_seq: 9,
        last_received_seq: 12,
    }
}

fn plan_for(old_transport: Arc<InMemoryTransport>, old_channel: TransportChannel) -> MigrationPlan {
    MigrationPlan {
        old_transport,
        old_channel,
        target: TransportKind::LocalNetwork,
        cursors: vec![control_cursor()],
    }
}

/// Runs the full resume handshake so both sides sit in `Resumed`/accepted.
fn accepted_handshake(baseline: SessionState) -> HandshakeFixture {
    let key = session_key("ab");
    let (a, b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let old_a = a
        .open(&peer, ChannelKind::Control)
        .expect("old channel opens");
    let old_b = b
        .accept()
        .expect("accept old channel")
        .expect("old channel accepted by responder");

    let mut initiator = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        baseline,
    )
    .expect("initiator creates");
    let mut responder = TransportMigrationResponder::try_new(
        responder_config(),
        SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(SESSION_ID, key.clone()).expect("responder store"),
        baseline,
    )
    .expect("responder creates");
    responder
        .note_local_old_channel(b.clone(), old_b.clone())
        .expect("responder tracks old channel");

    let request = initiator
        .begin(plan_for(a.clone(), old_a.clone()), key, NOW_MS)
        .expect("migration begins");
    let new_channel = initiator.new_channel().expect("new channel opened");
    let outcome = responder
        .handle_request(&request, NOW_MS + 10, Some(&[snapshot()]))
        .expect("responder handles request");
    let SessionResumeOutcome::Accepted(accepted) = outcome else {
        panic!("responder must accept the handshake request");
    };
    initiator
        .resume_accepted(&accepted, NOW_MS + 15)
        .expect("initiator processes acceptance");

    HandshakeFixture {
        a,
        b,
        old_a,
        old_b,
        new_channel,
        request,
        initiator,
        responder,
    }
}

#[test]
fn abandon_in_awaiting_accept_closes_new_channel() {
    let key = session_key("ab");
    let (a, b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let old_a = a
        .open(&peer, ChannelKind::Control)
        .expect("old channel opens");
    let _old_b = b
        .accept()
        .expect("accept old channel")
        .expect("old channel accepted");

    let mut initiator = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        SessionState::Connected,
    )
    .expect("initiator creates");
    let _request = initiator
        .begin(plan_for(a.clone(), old_a.clone()), key, NOW_MS)
        .expect("migration begins");
    let new_channel = initiator.new_channel().expect("new channel opened");
    assert_eq!(initiator.session_state(), SessionState::MigratingTransport);

    let summary = initiator.abandon();

    assert_eq!(
        summary,
        MigrationTeardownSummary {
            closed: 2,
            failed: 0
        }
    );
    assert!(
        !a.is_open(&new_channel).expect("new channel metadata"),
        "migrated channel must be closed on abandon"
    );
    assert!(
        !a.is_open(&old_a).expect("old channel metadata"),
        "old channel must be closed on abandon"
    );
    assert_eq!(
        initiator.phase(),
        MigrationPhase::Failed(MigrationFailure::SessionReleased)
    );
    assert_eq!(
        initiator.session_state(),
        SessionState::MigratingTransport,
        "abandon must not touch session state; release routing owns it"
    );
    assert!(initiator.new_channel().is_none());
    assert!(initiator.request().is_none());
    assert!(initiator.migration().is_none());
    assert_eq!(initiator.fallback_until_ms(), None);
}

#[test]
fn abandon_in_resumed_closes_both_channels() {
    let mut f = accepted_handshake(SessionState::Connected);
    assert_eq!(f.initiator.phase(), MigrationPhase::Resumed);
    assert_eq!(f.initiator.session_state(), SessionState::Connected);

    let summary = f.initiator.abandon();

    assert_eq!(
        summary,
        MigrationTeardownSummary {
            closed: 2,
            failed: 0
        }
    );
    assert!(
        !f.a.is_open(&f.new_channel).expect("new channel metadata"),
        "primary (migrated) channel must be closed on abandon"
    );
    assert!(
        !f.a.is_open(&f.old_a).expect("old channel metadata"),
        "fallback channel must be closed on abandon"
    );
    assert_eq!(
        f.initiator.phase(),
        MigrationPhase::Failed(MigrationFailure::SessionReleased)
    );
    assert_eq!(f.initiator.session_state(), SessionState::Connected);
}

#[test]
fn abandon_in_idle_is_noop() {
    let mut initiator = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        SessionState::Connected,
    )
    .expect("initiator creates");

    let summary = initiator.abandon();

    assert_eq!(
        summary,
        MigrationTeardownSummary {
            closed: 0,
            failed: 0
        }
    );
    assert_eq!(initiator.phase(), MigrationPhase::Idle);
    assert_eq!(initiator.session_state(), SessionState::Connected);
}

#[test]
fn abandon_in_completed_closes_primary_only() {
    let mut f = accepted_handshake(SessionState::Connected);
    f.initiator.tick(NOW_MS + 76).expect("fallback expiry");
    assert_eq!(f.initiator.phase(), MigrationPhase::Completed);
    assert!(
        !f.a.is_open(&f.old_a).expect("old channel metadata"),
        "tick closed the fallback already"
    );

    let summary = f.initiator.abandon();

    assert_eq!(
        summary,
        MigrationTeardownSummary {
            closed: 1,
            failed: 0
        }
    );
    assert!(
        !f.a.is_open(&f.new_channel).expect("new channel metadata"),
        "primary channel must be closed on abandon"
    );
    assert_eq!(
        f.initiator.phase(),
        MigrationPhase::Completed,
        "abandon must not rewrite completed migration history"
    );
}

#[test]
fn abandon_in_failed_closes_rolled_back_channel() {
    let key = session_key("ab");
    let (a, b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let old_a = a
        .open(&peer, ChannelKind::Control)
        .expect("old channel opens");
    let _old_b = b
        .accept()
        .expect("accept old channel")
        .expect("old channel accepted");

    let mut initiator = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        SessionState::Connected,
    )
    .expect("initiator creates");
    initiator
        .begin(plan_for(a.clone(), old_a.clone()), key, NOW_MS)
        .expect("migration begins");

    let forged = SessionResumeAccepted::new(
        SESSION_ID,
        ChannelMigration::new(
            SessionChannel::Control,
            "channel-rogue-old",
            "channel-rogue-new",
            "loopback",
            "local_network",
        )
        .expect("fixture migration"),
        vec![control_cursor()],
        NOW_MS + 10,
        NOW_MS + 210,
    )
    .expect("fixture acceptance is valid");
    let outcome = initiator
        .resume_accepted(&forged, NOW_MS + 15)
        .expect("violation is processed");
    assert_eq!(
        outcome,
        ResumeAcceptOutcome::Violation(MigrationFailure::RejectedByPeer {
            reason: ResumeRejectionReason::ProtocolViolation,
        })
    );
    assert!(
        a.is_open(&old_a).expect("old channel metadata"),
        "rollback keeps the old channel open until abandon"
    );

    let summary = initiator.abandon();

    assert_eq!(
        summary,
        MigrationTeardownSummary {
            closed: 1,
            failed: 0
        }
    );
    assert!(
        !a.is_open(&old_a).expect("old channel metadata"),
        "abandon closes the rolled-back old channel"
    );
    assert_eq!(initiator.session_state(), SessionState::Connected);
}

#[test]
fn begin_closes_channel_when_request_build_fails() {
    let key = session_key("ab");
    let (a, b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let old_a = a
        .open(&peer, ChannelKind::Control)
        .expect("old channel opens");
    b.accept()
        .expect("accept old channel")
        .expect("old channel accepted");

    let mut initiator = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        SessionState::Connected,
    )
    .expect("initiator creates");
    let plan = MigrationPlan {
        old_transport: a.clone(),
        old_channel: old_a.clone(),
        target: TransportKind::LocalNetwork,
        cursors: vec![control_cursor(), control_cursor()],
    };

    let error = initiator
        .begin(plan, key, NOW_MS)
        .expect_err("duplicate cursors must fail the request build");
    assert!(
        matches!(
            error.downcast_inner::<ResumeError>(),
            Ok(ResumeError::DuplicateChannel {
                channel: SessionChannel::Control
            })
        ),
        "begin must surface the duplicate-cursor request build failure"
    );
    assert_eq!(initiator.phase(), MigrationPhase::Idle);
    assert!(
        initiator.new_channel().is_none(),
        "a leaked channel handle must not stay tracked after the failed build"
    );

    let migrated = b
        .accept()
        .expect("accept probe")
        .expect("migrated channel link exists on the peer side");
    assert!(
        !a.is_open(&migrated).expect("new channel metadata"),
        "begin must close the migrated channel when the request build fails"
    );
    assert!(
        a.is_open(&old_a).expect("old channel metadata"),
        "the old channel is not touched by the failed attempt"
    );
}

#[test]
fn teardown_clears_keys_and_closes_old() {
    let mut f = accepted_handshake(SessionState::Connected);
    assert!(f.responder.accepted_migration().is_some());

    let summary = f.responder.teardown();

    assert_eq!(
        summary,
        MigrationTeardownSummary {
            closed: 1,
            failed: 0
        }
    );
    assert!(
        !f.b.is_open(&f.old_b).expect("old channel metadata"),
        "responder fallback must be closed by teardown"
    );
    assert_eq!(f.responder.accepted_migration(), None);
    assert_eq!(f.responder.fallback_until_ms(), None);

    let replay = f
        .responder
        .handle_request(&f.request, NOW_MS + 20, Some(&[snapshot()]))
        .expect("responder handles replay after teardown");
    let SessionResumeOutcome::Rejected(rejection) = replay else {
        panic!("cleared resume keys must reject a replayed request");
    };
    assert_eq!(
        rejection.reason,
        ResumeRejectionReason::InvalidResumeKey,
        "cleared keys must make the replay fail key validation"
    );
}

#[test]
fn teardown_leaves_session_state_to_release_routing() {
    let mut f = accepted_handshake(SessionState::Connected);
    assert_eq!(
        f.responder.session_state(),
        SessionState::MigratingTransport
    );

    let summary = f.responder.teardown();

    assert_eq!(
        summary,
        MigrationTeardownSummary {
            closed: 1,
            failed: 0
        }
    );
    assert_eq!(
        f.responder.session_state(),
        SessionState::MigratingTransport,
        "teardown must not touch session state; release routing owns it"
    );
}
