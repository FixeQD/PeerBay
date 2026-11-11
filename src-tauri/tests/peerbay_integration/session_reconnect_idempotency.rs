use std::sync::{Arc, Mutex};
use std::time::Duration;

use peerbay_lib::protocol::{
    ChannelMigration, ChannelResumeCursor, ControlMessageType, MessageChannel, MessageEnvelope,
    MessageType, ResumeKey, SequenceError, SequenceTracker, SessionChannel, SessionResumeAccepted,
    SessionResumeRequest,
};
use peerbay_lib::session::{
    ChannelSeqSnapshot, MigrationConfig, MigrationRouteState, ReconnectBackoff,
    ReconnectBackoffConfig, ReconnectDecision, ResumeKeyStore, RouteDisposition, RoutedMessage,
    SessionMessageHandler, SessionResumeOutcome, SessionRouter, SessionState,
    TransportMigrationResponder,
};
use peerbay_lib::storage::{PeerRecord, PeerTrustStore};
use serde_json::{Value, json};

const SESSION_ID: &str = "session-reconnect-idem-0001";
const OTHER_SESSION_ID: &str = "session-reconnect-idem-0002";
const PEER_ID: &str = "00000000-0000-0000-0000-000000000003";
const NOW_MS: u64 = 1_000_000;
const TS_MS: u64 = 1_700_000_000_000;

fn control_envelope(session_id: &str, seq: u64) -> MessageEnvelope<Value> {
    MessageEnvelope::new(
        format!("control-{seq}"),
        MessageType::Control(ControlMessageType::Ping),
        session_id,
        seq,
        TS_MS,
        Value::Null,
    )
}

fn deliver(
    tracker: &mut SequenceTracker,
    router: &SessionRouter,
    envelope: &MessageEnvelope<Value>,
) -> eros::Result<RouteDisposition> {
    tracker.accept(envelope)?;
    router.route(envelope)
}

struct CountingHandler {
    domain: MessageChannel,
    seen: Mutex<Vec<u64>>,
}

impl CountingHandler {
    fn new(domain: MessageChannel) -> Self {
        Self {
            domain,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn count(&self) -> usize {
        self.seen.lock().expect("counting lock").len()
    }

    fn sequences(&self) -> Vec<u64> {
        self.seen.lock().expect("counting lock").clone()
    }
}

impl SessionMessageHandler for CountingHandler {
    fn domain(&self) -> MessageChannel {
        self.domain
    }

    fn handle(&self, message: &RoutedMessage, _body: &Value) -> eros::Result<()> {
        self.seen
            .lock()
            .expect("counting lock")
            .push(message.sequence);
        Ok(())
    }
}

fn migration_config() -> MigrationConfig {
    MigrationConfig::new(Duration::from_millis(200), Duration::from_millis(100))
}

fn session_key(hex_pairs: &str) -> ResumeKey {
    ResumeKey::new(hex_pairs.repeat(32)).expect("fixture resume key is valid")
}

fn resume_request(key: ResumeKey, cursors: Vec<ChannelResumeCursor>) -> SessionResumeRequest {
    let migration = ChannelMigration::new(
        SessionChannel::Control,
        "channel-old",
        "channel-resumed-0001",
        "loopback",
        "local_network",
    )
    .expect("fixture migration is valid");
    SessionResumeRequest::new(SESSION_ID, key, migration, cursors, NOW_MS, NOW_MS + 200)
        .expect("fixture resume request is valid")
}

fn resumed_responder(
    cursor: ChannelResumeCursor,
    snapshot: ChannelSeqSnapshot,
) -> (
    TransportMigrationResponder,
    SessionResumeRequest,
    SessionResumeAccepted,
) {
    let mut responder = TransportMigrationResponder::try_new(
        migration_config(),
        SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(SESSION_ID, session_key("ab")).expect("fixture resume key store"),
        SessionState::Connected,
    )
    .expect("fixture responder creates");
    let request = resume_request(session_key("ab"), vec![cursor]);
    let outcome = responder
        .handle_request(&request, NOW_MS, Some(&[snapshot]))
        .expect("fixture resume request handles");
    let SessionResumeOutcome::Accepted(accepted) = outcome else {
        panic!("fixture resume request must be accepted");
    };
    (responder, request, accepted)
}

fn accepted_control_sequences(tracker: &mut SequenceTracker, high: u64) {
    for seq in 0..=high {
        tracker
            .accept(&control_envelope(SESSION_ID, seq))
            .expect("pre-disconnect delivery should be accepted");
    }
}

#[test]
fn resume_keeps_tracker_continuity_and_rejects_redelivery() {
    let mut receiver = SequenceTracker::new(SESSION_ID).expect("tracker should be created");
    accepted_control_sequences(&mut receiver, 9);
    let local_watermark = receiver
        .last_accepted(MessageChannel::Control)
        .expect("delivered sequences leave a local watermark");

    let peer_cursor = ChannelResumeCursor::new(SessionChannel::Control, 0, 3);
    let (responder, request, accepted) = resumed_responder(
        peer_cursor.clone(),
        ChannelSeqSnapshot {
            channel: SessionChannel::Control,
            last_sent_seq: 0,
            last_received_seq: local_watermark,
        },
    );
    assert_eq!(
        accepted.cursors, request.cursors,
        "the acceptance echoes the peer cursors"
    );
    assert_eq!(
        responder.session_state(),
        SessionState::MigratingTransport,
        "an accepted resume moves the session into the migration state"
    );

    assert_ne!(
        peer_cursor.last_sent_seq, local_watermark,
        "fixture: the peer cursor must not coincide with the local watermark"
    );
    let mut resumed = SequenceTracker::new(SESSION_ID).expect("tracker should be created");
    resumed
        .restore(MessageChannel::Control, local_watermark)
        .expect("the local watermark should restore into the resumed tracker");

    // Redelivered frames execute nothing a second time...
    let duplicate = resumed
        .accept(&control_envelope(SESSION_ID, 9))
        .expect_err("the watermark frame must not be delivered twice")
        .downcast_inner::<SequenceError>()
        .expect("duplicate error should be preserved");
    assert_eq!(
        duplicate,
        SequenceError::Duplicate {
            channel: MessageChannel::Control,
            seq: 9,
        }
    );
    let replay = resumed
        .accept(&control_envelope(SESSION_ID, 5))
        .expect_err("frames below the watermark stay replays after a resume")
        .downcast_inner::<SequenceError>()
        .expect("replay error should be preserved");
    assert_eq!(
        replay,
        SequenceError::Replay {
            channel: MessageChannel::Control,
            seq: 5,
            last_accepted: 9,
        }
    );

    resumed
        .accept(&control_envelope(SESSION_ID, 10))
        .expect("the next sequence should be accepted after the resume");
    assert_eq!(resumed.last_accepted(MessageChannel::Control), Some(10));
}

#[test]
fn restored_tracker_after_receiver_restart_rejects_redelivery() {
    let mut receiver = SequenceTracker::new(SESSION_ID).expect("tracker should be created");
    accepted_control_sequences(&mut receiver, 9);
    let local_watermark = receiver
        .last_accepted(MessageChannel::Control)
        .expect("delivered sequences leave a local watermark");

    let mut restored = SequenceTracker::new(SESSION_ID).expect("tracker should be created");
    assert_eq!(
        restored.last_accepted(MessageChannel::Control),
        None,
        "a restarted tracker starts empty"
    );
    restored
        .restore(MessageChannel::Control, local_watermark)
        .expect("the local watermark should restore");
    assert_eq!(restored.last_accepted(MessageChannel::Control), Some(9));

    let duplicate = restored
        .accept(&control_envelope(SESSION_ID, 9))
        .expect_err("a restored watermark must reject its own frame")
        .downcast_inner::<SequenceError>()
        .expect("duplicate error should be preserved");
    assert_eq!(
        duplicate,
        SequenceError::Duplicate {
            channel: MessageChannel::Control,
            seq: 9,
        }
    );

    let stale_cursor_claim = 3;
    let regression = restored
        .restore(MessageChannel::Control, stale_cursor_claim)
        .expect_err("a stale peer cursor must not regress the watermark")
        .downcast_inner::<SequenceError>()
        .expect("restore regression error should be preserved");
    assert_eq!(
        regression,
        SequenceError::RestoreRegression {
            channel: MessageChannel::Control,
            requested: 3,
            current: 9,
        }
    );
    assert_eq!(
        restored.last_accepted(MessageChannel::Control),
        Some(9),
        "a refused restore keeps the local watermark"
    );

    restored
        .accept(&control_envelope(SESSION_ID, 10))
        .expect("the next sequence should be accepted after the refused restore");
    assert_eq!(restored.last_accepted(MessageChannel::Control), Some(10));
}

#[test]
fn duplicate_on_fallback_and_primary_channels_executes_once() {
    let (responder, _request, _accepted) = resumed_responder(
        ChannelResumeCursor::new(SessionChannel::Control, 0, 9),
        ChannelSeqSnapshot {
            channel: SessionChannel::Control,
            last_sent_seq: 0,
            last_received_seq: 9,
        },
    );
    assert_eq!(
        responder.route_state(),
        MigrationRouteState::NewChannelPrimary {
            old_fallback_until_ms: NOW_MS + 100
        },
        "the resumed channel runs with the old channel as fallback"
    );

    let mut tracker = SequenceTracker::new(SESSION_ID).expect("tracker should be created");
    accepted_control_sequences(&mut tracker, 9);
    let local_watermark = tracker
        .last_accepted(MessageChannel::Control)
        .expect("delivered sequences leave a local watermark");
    let mut resumed = SequenceTracker::new(SESSION_ID).expect("tracker should be created");
    resumed
        .restore(MessageChannel::Control, local_watermark)
        .expect("the local watermark should restore");

    let mut router = SessionRouter::new();
    let handler = Arc::new(CountingHandler::new(MessageChannel::Control));
    router
        .register(handler.clone())
        .expect("the control handler should register");

    let disposition = deliver(&mut resumed, &router, &control_envelope(SESSION_ID, 10))
        .expect("the first delivery should execute");
    assert_eq!(
        disposition,
        RouteDisposition::Handled(MessageChannel::Control)
    );
    assert_eq!(handler.sequences(), vec![10]);

    let error = deliver(&mut resumed, &router, &control_envelope(SESSION_ID, 10))
        .expect_err("a fallback redelivery must not execute twice")
        .downcast_inner::<SequenceError>()
        .expect("duplicate error should be preserved");
    assert_eq!(
        error,
        SequenceError::Duplicate {
            channel: MessageChannel::Control,
            seq: 10,
        }
    );
    assert_eq!(
        handler.sequences(),
        vec![10],
        "the router executed the message exactly once"
    );
}

#[test]
fn fresh_reconnect_rejects_old_session_messages() {
    let mut fresh = SequenceTracker::new(OTHER_SESSION_ID).expect("tracker should be created");
    let mut router = SessionRouter::new();
    let handler = Arc::new(CountingHandler::new(MessageChannel::Control));
    router
        .register(handler.clone())
        .expect("the control handler should register");

    let stale = control_envelope(SESSION_ID, 7);
    let error = deliver(&mut fresh, &router, &stale)
        .expect_err("an old-session frame must not execute after reconnect")
        .downcast_inner::<SequenceError>()
        .expect("session mismatch error should be preserved");
    assert_eq!(
        error,
        SequenceError::SessionMismatch {
            expected: OTHER_SESSION_ID.to_owned(),
            received: SESSION_ID.to_owned(),
        }
    );
    assert_eq!(
        handler.count(),
        0,
        "old-session frames must not reach any handler"
    );
    assert_eq!(
        fresh.last_accepted(MessageChannel::Control),
        None,
        "old-session frames must not create tracker state"
    );

    fresh
        .restore(MessageChannel::Control, 9)
        .expect("the local watermark should restore");
    let fresh_delivery = deliver(&mut fresh, &router, &control_envelope(OTHER_SESSION_ID, 10))
        .expect("a fresh-session delivery should execute");
    assert_eq!(
        fresh_delivery,
        RouteDisposition::Handled(MessageChannel::Control)
    );
    let late_stale = control_envelope(SESSION_ID, 11);
    let error = deliver(&mut fresh, &router, &late_stale)
        .expect_err("late old-session frames stay rejected")
        .downcast_inner::<SequenceError>()
        .expect("session mismatch error should be preserved");
    assert_eq!(
        error,
        SequenceError::SessionMismatch {
            expected: OTHER_SESSION_ID.to_owned(),
            received: SESSION_ID.to_owned(),
        }
    );
    assert_eq!(
        handler.sequences(),
        vec![10],
        "only fresh-session frames execute"
    );
}

#[test]
fn backoff_driven_reconnect_does_not_duplicate_state_transitions() {
    let config =
        ReconnectBackoffConfig::new(Duration::from_millis(10), 2, Duration::from_millis(100), 3);
    let mut backoff = ReconnectBackoff::try_new(config).expect("a valid config creates a backoff");

    let mut state = SessionState::Disconnected;
    let mut schedule = Vec::new();
    loop {
        match backoff.next_decision() {
            ReconnectDecision::Retry { attempt, delay } => {
                schedule.push((attempt, delay));
                assert!(
                    state.can_transition(SessionState::ResolvingPeer),
                    "an attempt must start by resolving the peer again"
                );
                state = SessionState::ResolvingPeer;
                assert!(
                    state.can_transition(SessionState::OpeningTransport),
                    "resolving leads into opening the transport"
                );
                state = SessionState::OpeningTransport;
                assert!(
                    state.can_transition(SessionState::Reconnecting),
                    "a failed opening attempt marks the session reconnecting"
                );
                state = SessionState::Reconnecting;
            }
            ReconnectDecision::GiveUp { attempts } => {
                assert_eq!(attempts, 3, "give-up reports the full attempt count");
                break;
            }
        }
    }

    assert_eq!(
        schedule,
        vec![
            (1, Duration::from_millis(10)),
            (2, Duration::from_millis(20)),
            (3, Duration::from_millis(40)),
        ],
        "the retry schedule is bounded by the configured maximum delay"
    );
    assert!(
        backoff.is_exhausted(),
        "the attempt cap marks the backoff exhausted"
    );
    assert!(
        matches!(
            backoff.next_decision(),
            ReconnectDecision::GiveUp { attempts: 3 }
        ),
        "give-up is stable instead of scheduling more retries"
    );
    assert!(
        matches!(
            backoff.next_decision(),
            ReconnectDecision::GiveUp { attempts: 3 }
        ),
        "repeated give-up decisions must not reset the schedule"
    );

    assert!(
        state.can_transition(SessionState::Connected)
            || state.can_transition(SessionState::Disconnected),
        "a reconnecting session may still connect or fall back to disconnected"
    );
    assert!(state.can_transition(SessionState::Disconnected));
    state = SessionState::Disconnected;
    assert!(!state.can_transition(SessionState::Reconnecting));
    assert!(
        !SessionState::Reconnecting.can_transition(SessionState::Reconnecting),
        "self-transitions are refused"
    );

    backoff.reset();
    assert!(!backoff.is_exhausted());
    assert!(
        matches!(
            backoff.next_decision(),
            ReconnectDecision::Retry { attempt: 1, .. }
        ),
        "a reset restarts the schedule at attempt one"
    );
}

#[test]
fn peer_policy_survives_reconnect_cycle() {
    let dir = tempfile::tempdir().expect("temporary directory should exist");
    let peers_dir = dir.path().join("peers");
    std::fs::create_dir(&peers_dir).expect("peers directory should create");
    let store = PeerTrustStore::new(peers_dir.clone());

    let policy = json!({"clipboard.text": "allowed", "files.receive": "ask"});
    let mut record = PeerRecord::new(
        PEER_ID,
        "Reconnect Peer",
        "linux",
        "ab".repeat(32),
        "pairing-token-hash",
        "loopback",
    );
    record.feature_policies = policy.clone();
    store
        .save(PEER_ID, &record)
        .expect("peer record should save");

    let mut refreshed = store.load(PEER_ID).expect("peer record should load");
    refreshed.last_seen_at = Some(NOW_MS);
    store
        .save(PEER_ID, &refreshed)
        .expect("refreshed record should save");
    let reloaded = store.load(PEER_ID).expect("peer record should reload");

    assert_eq!(
        reloaded.feature_policies, policy,
        "feature policies survive the reconnect cycle"
    );
    assert_eq!(reloaded.last_seen_at, Some(NOW_MS));
    assert!(
        !reloaded.is_revoked(),
        "a reconnect cycle must not revoke a trusted peer"
    );
    assert_eq!(
        store.list_active().expect("active peers should list"),
        vec![PEER_ID.to_owned()],
    );

    let records = std::fs::read_dir(&peers_dir)
        .expect("peers directory should read")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".json"))
        .count();
    assert_eq!(
        records, 1,
        "a reconnect cycle must not duplicate peer records"
    );

    let mut tracker = SequenceTracker::new(SESSION_ID).expect("tracker should be created");
    let mut router = SessionRouter::new();
    let handler = Arc::new(CountingHandler::new(MessageChannel::Control));
    router
        .register(handler.clone())
        .expect("the control handler should register");

    let first = deliver(&mut tracker, &router, &control_envelope(SESSION_ID, 0))
        .expect("the first post-resume delivery should execute");
    assert_eq!(first, RouteDisposition::Handled(MessageChannel::Control));

    store
        .load(PEER_ID)
        .expect("trust reload during the reconnect cycle should succeed");
    let second = deliver(&mut tracker, &router, &control_envelope(SESSION_ID, 1))
        .expect("the second post-resume delivery should execute");
    assert_eq!(second, RouteDisposition::Handled(MessageChannel::Control));
    assert_eq!(
        handler.sequences(),
        vec![0, 1],
        "handlers survive the reconnect cycle"
    );
}

#[test]
fn revoked_peer_is_not_resurrected_after_reconnect() {
    let dir = tempfile::tempdir().expect("temporary directory should exist");
    let peers_dir = dir.path().join("peers");
    std::fs::create_dir(&peers_dir).expect("peers directory should create");
    let store = PeerTrustStore::new(peers_dir);

    let mut record = PeerRecord::new(
        PEER_ID,
        "Revoked Peer",
        "linux",
        "ab".repeat(32),
        "pairing-token-hash",
        "loopback",
    );
    record.feature_policies = json!({"clipboard.text": "allowed"});
    store
        .save(PEER_ID, &record)
        .expect("peer record should save");
    store
        .revoke(PEER_ID, NOW_MS)
        .expect("peer record should revoke");

    let reloaded = store.load(PEER_ID).expect("peer record should load");
    assert!(
        reloaded.is_revoked(),
        "revocation must survive the disconnect"
    );
    assert_eq!(reloaded.revoked_at, Some(NOW_MS));
    assert!(
        !store
            .list_active()
            .expect("active peers should list")
            .iter()
            .any(|id| id == PEER_ID),
        "a revoked peer must not be listed as active"
    );

    let mut tracker = SequenceTracker::new(SESSION_ID).expect("tracker should be created");
    let mut router = SessionRouter::new();
    let handler = Arc::new(CountingHandler::new(MessageChannel::Control));
    router
        .register(handler.clone())
        .expect("the control handler should register");

    let authorized = !store
        .load(PEER_ID)
        .expect("trust check during reconnect should succeed")
        .is_revoked();
    if authorized {
        deliver(&mut tracker, &router, &control_envelope(SESSION_ID, 0))
            .expect("authorized deliveries should execute");
    }
    assert_eq!(
        handler.count(),
        0,
        "a revoked peer must not execute messages after reconnect"
    );
    assert_eq!(
        tracker.last_accepted(MessageChannel::Control),
        None,
        "no tracker state is created for a revoked peer"
    );
}
