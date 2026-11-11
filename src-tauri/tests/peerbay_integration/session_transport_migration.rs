use std::sync::Arc;
use std::time::Duration;

use peerbay_lib::protocol::{
    ChannelMigration, ChannelResumeCursor, ResumeKey, ResumeRejectionReason, SessionChannel,
    SessionResumeRequest,
};
use peerbay_lib::session::{
    ChannelSeqSnapshot, MigrationConfig, MigrationError, MigrationPhase, MigrationPlan,
    MigrationRouteState, ResumeAcceptOutcome, ResumeKeyStore, SessionResumeOutcome,
    TransportMigrationInitiator, TransportMigrationResponder,
};
use peerbay_lib::transport::{
    ChannelKind, InMemoryTransport, PeerEndpoint, Transport as _, TransportKind,
};

use peerbay_lib::session::SessionState;

const SESSION_ID: &str = "session-migration-0001";
const NOW_MS: u64 = 1_000_000;

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

fn plan_for(
    old_transport: Arc<InMemoryTransport>,
    old_channel: peerbay_lib::transport::TransportChannel,
) -> MigrationPlan {
    MigrationPlan {
        old_transport,
        old_channel,
        target: TransportKind::LocalNetwork,
        cursors: vec![control_cursor()],
    }
}

fn build_request(
    migration: ChannelMigration,
    key: ResumeKey,
    cursors: Vec<ChannelResumeCursor>,
    requested_at_ms: u64,
    expires_at_ms: u64,
) -> SessionResumeRequest {
    SessionResumeRequest::new(
        SESSION_ID,
        key,
        migration,
        cursors,
        requested_at_ms,
        expires_at_ms,
    )
    .expect("fixture resume request is valid")
}

#[test]
fn migration_happy_path_switches_primary_and_closes_fallback_after_expiry() {
    let key = session_key("ab");
    let (a, b) = in_memory_pair();
    let old_a = a
        .open(
            &endpoint("00000000-0000-0000-0000-000000000002"),
            ChannelKind::Control,
        )
        .expect("old channel opens");
    let old_b = b
        .accept()
        .expect("accept old channel")
        .expect("old channel accepted by responder");
    assert!(a.is_open(&old_a).expect("old channel metadata"));

    let mut initiator = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        SessionState::Connected,
    )
    .expect("initiator creates");
    let mut responder = TransportMigrationResponder::try_new(
        responder_config(),
        SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(SESSION_ID, key.clone()).expect("responder store"),
        SessionState::Connected,
    )
    .expect("responder creates");
    responder
        .note_local_old_channel(b.clone(), old_b.clone())
        .expect("responder tracks old channel");

    let request = initiator
        .begin(plan_for(a.clone(), old_a.clone()), key, NOW_MS)
        .expect("migration begins");
    assert_eq!(initiator.session_state(), SessionState::MigratingTransport);
    assert_eq!(initiator.phase(), MigrationPhase::AwaitingAccept);
    let new_channel = initiator.new_channel().expect("new channel opened");
    assert!(a.is_open(&new_channel).expect("new channel metadata"));
    assert_eq!(
        new_channel.transport(),
        TransportKind::LocalNetwork,
        "migrated channel reports the requested target transport"
    );

    let outcome = responder
        .handle_request(
            &request,
            NOW_MS + 10,
            Some(&[ChannelSeqSnapshot {
                channel: SessionChannel::Control,
                last_sent_seq: 9,
                last_received_seq: 12,
            }]),
        )
        .expect("responder handles request");
    let SessionResumeOutcome::Accepted(accepted) = outcome else {
        panic!("responder must accept the happy-path request");
    };
    assert_eq!(accepted.cursors, request.cursors);
    assert_eq!(accepted.fallback_expires_at_ms, NOW_MS + 110);
    assert_eq!(responder.session_state(), SessionState::MigratingTransport);
    assert_eq!(
        responder.route_state(),
        MigrationRouteState::NewChannelPrimary {
            old_fallback_until_ms: NOW_MS + 110
        }
    );

    let outcome = initiator
        .resume_accepted(&accepted, NOW_MS + 15)
        .expect("initiator processes acceptance");
    assert_eq!(
        outcome,
        ResumeAcceptOutcome::Accepted {
            fallback_until_ms: NOW_MS + 75,
        },
        "initiator clamps fallback to its own ttl"
    );
    assert_eq!(initiator.session_state(), SessionState::Connected);
    assert!(matches!(
        initiator.route_state(),
        MigrationRouteState::NewChannelPrimary { .. }
    ));
    assert!(a.is_open(&old_a).expect("fallback stays open"));

    initiator.tick(NOW_MS + 50).expect("pre-expiry tick");
    assert!(a.is_open(&old_a).expect("fallback stays open"));

    initiator.tick(NOW_MS + 76).expect("fallback expiry");
    assert_eq!(initiator.phase(), MigrationPhase::Completed);
    assert_eq!(initiator.route_state(), MigrationRouteState::Migrated);
    assert_eq!(
        a.is_open(&old_a).expect("old channel metadata"),
        false,
        "fallback closed after its window"
    );
    assert_eq!(
        initiator
            .primary_channel()
            .map(|channel| channel.id().to_owned()),
        Some(new_channel.id().to_owned())
    );

    let closed = responder
        .close_expired_fallback(NOW_MS + 150)
        .expect("responder closes fallback");
    assert!(closed);
    assert_eq!(responder.session_state(), SessionState::Connected);
    assert_eq!(responder.route_state(), MigrationRouteState::Migrated);
    assert_eq!(
        b.is_open(&old_b).expect("old channel metadata"),
        false,
        "responder fallback closed too"
    );

    initiator
        .tick(NOW_MS + 200)
        .expect("post-completion tick no-op");
    assert_eq!(initiator.phase(), MigrationPhase::Completed);
}

#[test]
fn migration_initiator_rolls_back_when_peer_rejects_resume() {
    let key = session_key("ab");
    let (a, b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let old_a = a.open(&peer, ChannelKind::Control).expect("old channel");
    let old_b = b.accept().expect("accept").expect("accepted");

    let mut initiator = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        SessionState::Degraded,
    )
    .expect("initiator creates");
    let mut responder = TransportMigrationResponder::try_new(
        responder_config(),
        SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(SESSION_ID, session_key("cd")).expect("responder store"),
        SessionState::Degraded,
    )
    .expect("responder creates");
    responder
        .note_local_old_channel(b.clone(), old_b)
        .expect("track old channel");

    let request = initiator
        .begin(plan_for(a.clone(), old_a.clone()), key, NOW_MS)
        .expect("migration begins");
    let migrated = initiator.new_channel().expect("new channel opened");

    let outcome = responder
        .handle_request(&request, NOW_MS + 5, None)
        .expect("responder handles request");
    let SessionResumeOutcome::Rejected(rejection) = outcome else {
        panic!("peer with a different key must reject");
    };
    assert_eq!(
        rejection.reason,
        ResumeRejectionReason::InvalidResumeKey,
        "mismatched store key rejects as invalid resume key"
    );
    assert!(!rejection.retryable);
    assert_eq!(responder.session_state(), SessionState::Degraded);
    assert_eq!(
        responder.route_state(),
        MigrationRouteState::OldChannelPrimary
    );

    let failure = initiator
        .resume_rejected(&rejection)
        .expect("initiator processes rejection");
    assert_eq!(
        failure,
        peerbay_lib::session::MigrationFailure::RejectedByPeer {
            reason: ResumeRejectionReason::InvalidResumeKey,
        },
    );
    assert_eq!(initiator.phase(), MigrationPhase::Failed(failure));
    // Rollback keeps the old channel and closed only the migrated one.
    assert_eq!(a.is_open(&migrated).expect("new channel metadata"), false);
    assert_eq!(a.is_open(&old_a).expect("old channel metadata"), true);
    assert_eq!(initiator.session_state(), SessionState::Degraded);
    assert_eq!(initiator.route_state(), MigrationRouteState::RolledBack);
    assert_eq!(
        initiator
            .primary_channel()
            .map(|channel| channel.id().to_owned()),
        Some(old_a.id().to_owned())
    );
}

#[test]
fn migration_handshake_timeout_closes_new_channel_and_restores_baseline() {
    let key = session_key("ab");
    let (a, b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let old_a = a.open(&peer, ChannelKind::Control).expect("old channel");
    let _old_b = b.accept().expect("accept").expect("accepted");

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
    let migrated = initiator.new_channel().expect("new channel opened");

    initiator.tick(NOW_MS + 199).expect("in-handshake tick");
    assert_eq!(initiator.phase(), MigrationPhase::AwaitingAccept);

    initiator.tick(NOW_MS + 201).expect("handshake expiry");
    assert_eq!(
        initiator.phase(),
        MigrationPhase::Failed(peerbay_lib::session::MigrationFailure::HandshakeTimeout),
    );
    assert_eq!(a.is_open(&migrated).expect("new channel metadata"), false);
    assert_eq!(a.is_open(&old_a).expect("old channel metadata"), true);
    assert_eq!(initiator.session_state(), SessionState::Connected);
}

#[test]
fn migration_responder_rejects_expired_horizon_and_future_requests() {
    let key = session_key("ab");
    let mut responder = TransportMigrationResponder::try_new(
        responder_config(),
        SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(SESSION_ID, key.clone()).expect("store"),
        SessionState::Connected,
    )
    .expect("responder creates");
    let migration = ChannelMigration::new(
        SessionChannel::Control,
        "channel-old",
        "channel-new",
        "loopback",
        "local_network",
    )
    .expect("fixture migration");

    let expired = build_request(
        migration.clone(),
        key.clone(),
        vec![control_cursor()],
        NOW_MS - 1001,
        NOW_MS - 1,
    );
    assert_rejection(
        responder.handle_request(&expired, NOW_MS, None),
        ResumeRejectionReason::ExpiredResumeKey,
    );

    let futuristic = build_request(
        migration.clone(),
        key.clone(),
        vec![control_cursor()],
        NOW_MS + 5,
        NOW_MS + 105,
    );
    assert_rejection(
        responder.handle_request(&futuristic, NOW_MS, None),
        ResumeRejectionReason::ProtocolViolation,
    );

    let over_horizon = build_request(
        migration,
        key,
        vec![control_cursor()],
        NOW_MS - 10,
        NOW_MS + 10_000,
    );
    assert_rejection(
        responder.handle_request(&over_horizon, NOW_MS, None),
        ResumeRejectionReason::ProtocolViolation,
    );
}

#[test]
fn migration_responder_rejects_replayed_and_concurrent_requests() {
    let key = session_key("ab");
    let mut responder = TransportMigrationResponder::try_new(
        responder_config(),
        SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(SESSION_ID, key.clone()).expect("store"),
        SessionState::Connected,
    )
    .expect("responder creates");
    let migration = ChannelMigration::new(
        SessionChannel::Control,
        "channel-old",
        "memory-channel-0001",
        "loopback",
        "local_network",
    )
    .expect("fixture migration");
    let request = build_request(
        migration.clone(),
        key.clone(),
        vec![control_cursor()],
        NOW_MS,
        NOW_MS + 200,
    );

    assert!(matches!(
        responder.handle_request(&request, NOW_MS, None),
        Ok(SessionResumeOutcome::Accepted(_))
    ));

    assert_rejection(
        responder.handle_request(&request, NOW_MS + 1, None),
        ResumeRejectionReason::ChannelAlreadyActive,
    );

    let concurrent = build_request(
        ChannelMigration::new(
            SessionChannel::Control,
            "channel-old",
            "memory-channel-0400",
            "loopback",
            "local_network",
        )
        .expect("fixture migration"),
        key,
        vec![control_cursor()],
        NOW_MS + 2,
        NOW_MS + 202,
    );
    assert_rejection(
        responder.handle_request(&concurrent, NOW_MS + 2, None),
        ResumeRejectionReason::ChannelAlreadyActive,
    );
}

#[test]
fn migration_responder_requires_migrated_channel_cursor_and_consistent_sequence() {
    let key = session_key("ab");
    let mut responder = TransportMigrationResponder::try_new(
        responder_config(),
        SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(SESSION_ID, key.clone()).expect("store"),
        SessionState::Connected,
    )
    .expect("responder creates");
    let migration = ChannelMigration::new(
        SessionChannel::Control,
        "channel-old",
        "memory-channel-0001",
        "loopback",
        "local_network",
    )
    .expect("fixture migration");

    let missing = build_request(
        migration.clone(),
        key.clone(),
        vec![ChannelResumeCursor::new(SessionChannel::Bulk, 0, 0)],
        NOW_MS,
        NOW_MS + 200,
    );
    assert_rejection(
        responder.handle_request(&missing, NOW_MS, None),
        ResumeRejectionReason::UnknownChannel,
    );

    let overstated = build_request(
        migration.clone(),
        key.clone(),
        vec![ChannelResumeCursor::new(SessionChannel::Control, 11, 12)],
        NOW_MS,
        NOW_MS + 200,
    );
    assert_rejection(
        responder.handle_request(
            &overstated,
            NOW_MS,
            Some(&[ChannelSeqSnapshot {
                channel: SessionChannel::Control,
                last_sent_seq: 9,
                last_received_seq: 12,
            }]),
        ),
        ResumeRejectionReason::SequenceConflict,
    );

    let overstated_send = build_request(
        migration,
        key,
        vec![ChannelResumeCursor::new(SessionChannel::Control, 9, 13)],
        NOW_MS,
        NOW_MS + 200,
    );
    assert_rejection(
        responder.handle_request(
            &overstated_send,
            NOW_MS,
            Some(&[ChannelSeqSnapshot {
                channel: SessionChannel::Control,
                last_sent_seq: 9,
                last_received_seq: 12,
            }]),
        ),
        ResumeRejectionReason::SequenceConflict,
    );
}

#[test]
fn migration_begin_rejects_missing_cursor_without_leaking_channels() {
    let key = session_key("ab");
    let (a, b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let old_a = a.open(&peer, ChannelKind::Control).expect("old channel");
    b.accept().expect("accept").expect("accepted");

    let mut initiator = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        SessionState::Connected,
    )
    .expect("initiator creates");
    let plan = MigrationPlan {
        old_transport: a.clone(),
        old_channel: old_a,
        target: TransportKind::LocalNetwork,
        cursors: vec![ChannelResumeCursor::new(SessionChannel::Bulk, 0, 0)],
    };

    let error = initiator
        .begin(plan, key, NOW_MS)
        .expect_err("missing cursor must fail before opening a channel");
    assert!(
        matches!(
            error.downcast_inner::<MigrationError>(),
            Ok(MigrationError::CursorMissing {
                channel: SessionChannel::Control
            })
        ),
        "begin must fail with CursorMissing for the migrated channel"
    );
    assert_eq!(initiator.phase(), MigrationPhase::Idle);
    assert!(initiator.new_channel().is_none());
    assert!(
        b.accept().expect("accept probe").is_none(),
        "no new channel may remain pending after a failed begin"
    );
}

#[test]
fn migration_cannot_start_without_an_active_session_state() {
    let error = TransportMigrationInitiator::try_new(
        initiator_config(),
        SESSION_ID,
        SessionChannel::Control,
        SessionState::Disconnected,
    )
    .expect_err("inactive baseline must be refused");
    assert!(matches!(
        error.downcast_inner::<MigrationError>(),
        Ok(MigrationError::InvalidBaseline {
            got: SessionState::Disconnected
        }),
    ));
}

#[test]
fn migration_debug_output_never_contains_resume_key() {
    let key = session_key("ab");
    let mut responder = TransportMigrationResponder::try_new(
        responder_config(),
        SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(SESSION_ID, key.clone()).expect("store"),
        SessionState::Connected,
    )
    .expect("responder creates");
    let migration = ChannelMigration::new(
        SessionChannel::Control,
        "channel-old",
        "memory-channel-0001",
        "loopback",
        "local_network",
    )
    .expect("fixture migration");
    let request = build_request(
        migration,
        key.clone(),
        vec![control_cursor()],
        NOW_MS,
        NOW_MS + 200,
    );

    let _ = responder.handle_request(&request, NOW_MS, None);

    let rendered = format!("{:?}", request);
    assert!(
        !rendered.contains(key.as_str()),
        "resume key printed via request debug output"
    );
    assert!(
        !rendered.contains("ResumeKey(\""),
        "resume key shape leaked"
    );

    let rendered = format!("{:?}", responder);
    assert!(
        !rendered.contains(key.as_str()),
        "resume key printed via responder debug output"
    );
}

fn session_debug_helper() -> ResumeKeyStore {
    ResumeKeyStore::inherit(SESSION_ID, session_key("ef")).expect("store")
}

#[test]
fn resume_key_store_debug_is_redacted() {
    let store = session_debug_helper();
    let rendered = format!("{:?}", store);
    assert_eq!(rendered, "ResumeKeyStore(<redacted>)");
}

#[test]
fn transport_kind_labels_match_wire_names() {
    use peerbay_lib::transport::TransportKind as Kind;
    use serde_json::json;

    assert_eq!(Kind::LocalNetwork.as_str(), "local_network");
    assert_eq!(Kind::UsbAdb.as_str(), "usb_adb");
    assert_eq!(Kind::BluetoothLe.as_str(), "bluetooth_le");
    assert_eq!(Kind::WifiDirect.as_str(), "wifi_direct");
    assert_eq!(Kind::PhoneHotspot.as_str(), "phone_hotspot");
    assert_eq!(Kind::Loopback.as_str(), "loopback");

    for (kind, label) in [
        (Kind::LocalNetwork, "local_network"),
        (Kind::UsbAdb, "usb_adb"),
        (Kind::BluetoothLe, "bluetooth_le"),
        (Kind::WifiDirect, "wifi_direct"),
        (Kind::PhoneHotspot, "phone_hotspot"),
        (Kind::Loopback, "loopback"),
    ] {
        assert_eq!(serde_json::to_value(kind).unwrap(), json!(label));
    }
}

fn assert_rejection(outcome: eros::Result<SessionResumeOutcome>, expected: ResumeRejectionReason) {
    match outcome {
        Ok(SessionResumeOutcome::Rejected(rejection)) => {
            assert_eq!(rejection.reason, expected, "rejection reason mismatch");
            assert_eq!(rejection.session_id, SESSION_ID);
        }
        Ok(other) => panic!("expected rejection {expected:?}, got {other:?}"),
        Err(error) => panic!("expected rejection {expected:?}, got error {error}"),
    }
}
