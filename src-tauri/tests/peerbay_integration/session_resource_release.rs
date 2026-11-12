use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use peerbay_lib::protocol::{ChannelResumeCursor, ResumeKey, SessionChannel};
use peerbay_lib::session::{
    ChannelSeqSnapshot, DisconnectTrigger, Heartbeat, HeartbeatConfig, MigrationConfig,
    MigrationPlan, ReconnectBackoff, ReconnectBackoffConfig, ResumeKeyStore, SessionChannelLedger,
    SessionResources, SessionResumeOutcome, SessionState, TransportMigrationInitiator,
    TransportMigrationResponder,
};
use peerbay_lib::transport::{
    ChannelKind, InMemoryTransport, PeerEndpoint, Transport, TransportChannel, TransportKind,
    TransportMetrics,
};

const SESSION_ID: &str = "session-resource-release-0001";
const NOW_MS: u64 = 1_000_000;

#[derive(Debug)]
enum FixtureError {
    ForcedCloseFailure,
}

impl std::fmt::Display for FixtureError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForcedCloseFailure => write!(formatter, "forced close failure"),
        }
    }
}

impl std::error::Error for FixtureError {}

struct FailingCloseTransport {
    inner: Arc<InMemoryTransport>,
    fail_ids: Mutex<HashSet<String>>,
}

impl Transport for FailingCloseTransport {
    fn kind(&self) -> TransportKind {
        self.inner.kind()
    }

    fn discover(&self) -> eros::Result<Vec<PeerEndpoint>> {
        self.inner.discover()
    }

    fn open(&self, peer: &PeerEndpoint, channel: ChannelKind) -> eros::Result<TransportChannel> {
        self.inner.open(peer, channel)
    }

    fn close(&self, channel: &TransportChannel) -> eros::Result<()> {
        if self
            .fail_ids
            .lock()
            .expect("fixture mutex")
            .contains(channel.id())
        {
            return Err(eros::error!(FixtureError::ForcedCloseFailure));
        }
        self.inner.close(channel)
    }

    fn metrics(&self, channel: &TransportChannel) -> eros::Result<TransportMetrics> {
        self.inner.metrics(channel)
    }

    fn supports(&self, channel: ChannelKind) -> bool {
        self.inner.supports(channel)
    }

    fn migrate(
        &self,
        channel: &TransportChannel,
        target: TransportKind,
    ) -> eros::Result<TransportChannel> {
        self.inner.migrate(channel, target)
    }
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

fn backoff_config() -> ReconnectBackoffConfig {
    ReconnectBackoffConfig::new(Duration::from_millis(50), 2, Duration::from_secs(30), 4)
}

struct HandshakeFixture {
    a: Arc<InMemoryTransport>,
    b: Arc<InMemoryTransport>,
    old_a: TransportChannel,
    old_b: TransportChannel,
    new_channel: TransportChannel,
    initiator: TransportMigrationInitiator,
    responder: TransportMigrationResponder,
}

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
        initiator,
        responder,
    }
}

#[test]
fn release_during_handshake_closes_every_channel() {
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

    let mut resources = SessionResources::default();
    resources
        .channels
        .track(a.clone(), old_a.clone())
        .expect("session channel tracked");
    resources.initiator = Some(initiator);
    let mut state = SessionState::MigratingTransport;

    let report = resources
        .release(DisconnectTrigger::HeartbeatLost, &mut state)
        .expect("release during handshake succeeds");

    assert_eq!(report.trigger, DisconnectTrigger::HeartbeatLost);
    assert_eq!(report.from_state, SessionState::MigratingTransport);
    assert_eq!(report.to_state, SessionState::Reconnecting);
    assert_eq!(report.migration_channels_closed, 2);
    assert_eq!(report.migration_channels_failed, 0);
    assert_eq!(report.channels_closed, 1);
    assert_eq!(report.channels_failed, 0);
    assert_eq!(report.channels_already_closed, 0);
    assert!(
        !report.secrets_cleared,
        "no responder held resume keys in this release"
    );
    assert_eq!(report.workers_stopped, 0);
    assert!(!report.already_released);
    assert_eq!(state, SessionState::Reconnecting);
    assert!(
        !a.is_open(&new_channel).expect("new channel metadata"),
        "migrated channel must be closed by the migration abandon"
    );
    assert!(
        !a.is_open(&old_a).expect("old channel metadata"),
        "ledger channel must be closed by the session release"
    );
    assert!(resources.initiator.is_none());
}

#[test]
fn release_clears_resume_keys() {
    let fixture = accepted_handshake(SessionState::Connected);
    let mut resources = SessionResources {
        channels: SessionChannelLedger::default(),
        initiator: Some(fixture.initiator),
        responder: Some(fixture.responder),
        heartbeat: None,
        backoff: None,
    };
    let mut state = SessionState::MigratingTransport;

    let report = resources
        .release(DisconnectTrigger::HeartbeatLost, &mut state)
        .expect("release during accepted migration succeeds");

    assert!(
        report.secrets_cleared,
        "tearing down the responder must clear resume keys"
    );
    assert!(resources.responder.is_none());
    assert!(resources.initiator.is_none());
    assert_eq!(report.migration_channels_closed, 3);
    assert_eq!(report.migration_channels_failed, 0);
    assert_eq!(state, SessionState::Reconnecting);
    assert!(
        !fixture
            .a
            .is_open(&fixture.new_channel)
            .expect("new channel metadata"),
        "primary migration channel must be closed"
    );
    assert!(
        !fixture
            .a
            .is_open(&fixture.old_a)
            .expect("old channel metadata"),
        "initiator fallback channel must be closed"
    );
    assert!(
        !fixture
            .b
            .is_open(&fixture.old_b)
            .expect("responder channel metadata"),
        "responder fallback channel must be closed"
    );
}

#[test]
fn release_is_idempotent() {
    let (a, _b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let mut resources = SessionResources::default();
    let mut channels = Vec::new();
    for _ in 0..3 {
        let channel = a.open(&peer, ChannelKind::Control).expect("channel opens");
        resources
            .channels
            .track(a.clone(), channel.clone())
            .expect("session channel tracked");
        channels.push(channel);
    }
    let mut state = SessionState::Connected;

    assert!(
        resources
            .channels
            .close_channel(channels[0].id())
            .expect("fixture channel closes"),
        "pre-closed channel makes the release count already closed entries"
    );
    let first = resources
        .release(DisconnectTrigger::HeartbeatLost, &mut state)
        .expect("first release succeeds");

    assert_eq!(first.channels_closed, 2);
    assert_eq!(first.channels_already_closed, 1);
    assert_eq!(first.channels_failed, 0);
    assert!(!first.already_released);
    assert_eq!(state, SessionState::Reconnecting);
    assert!(resources.channels.is_empty());

    let second = resources
        .release(DisconnectTrigger::HeartbeatLost, &mut state)
        .expect("second release succeeds");

    assert!(second.already_released);
    assert_eq!(second.from_state, SessionState::Reconnecting);
    assert_eq!(second.to_state, SessionState::Reconnecting);
    assert_eq!(second.channels_closed, 0);
    assert_eq!(second.channels_failed, 0);
    assert_eq!(second.channels_already_closed, 0);
    assert_eq!(second.workers_stopped, 0);
    assert_eq!(state, SessionState::Reconnecting);
    for channel in &channels {
        assert!(
            !a.is_open(channel).expect("channel metadata"),
            "channels stay closed after a repeated release"
        );
    }
}

#[test]
fn terminal_trigger_releases() {
    let mut resources = SessionResources::default();
    let mut state = SessionState::Connected;

    let report = resources
        .release(DisconnectTrigger::TrustRevoked, &mut state)
        .expect("terminal release succeeds");

    assert_eq!(report.from_state, SessionState::Connected);
    assert_eq!(report.to_state, SessionState::Released);
    assert_eq!(state, SessionState::Released);
    assert!(!report.already_released);
    assert!(
        state.can_transition(SessionState::Closed),
        "closing a released session is the caller's explicit step, not release"
    );
}

#[test]
fn pre_connect_release_goes_disconnected() {
    let mut resources = SessionResources::default();
    let mut state = SessionState::OpeningTransport;

    let report = resources
        .release(DisconnectTrigger::SessionTimeout, &mut state)
        .expect("pre-connect release succeeds");

    assert_eq!(report.from_state, SessionState::OpeningTransport);
    assert_eq!(report.to_state, SessionState::Disconnected);
    assert_eq!(state, SessionState::Disconnected);
    assert!(!report.already_released);
}

#[test]
fn release_survives_failing_channel_close() {
    let (inner, _b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let transport = Arc::new(FailingCloseTransport {
        inner,
        fail_ids: Mutex::new(HashSet::new()),
    });
    let healthy = transport
        .open(&peer, ChannelKind::Control)
        .expect("healthy channel opens");
    let failing = transport
        .open(&peer, ChannelKind::Control)
        .expect("failing channel opens");
    transport
        .fail_ids
        .lock()
        .expect("fixture mutex")
        .insert(failing.id().to_owned());

    let mut resources = SessionResources::default();
    resources
        .channels
        .track(transport.clone(), healthy)
        .expect("healthy channel tracked");
    resources
        .channels
        .track(transport.clone(), failing)
        .expect("failing channel tracked");
    let mut state = SessionState::Connected;

    let report = resources
        .release(DisconnectTrigger::HeartbeatLost, &mut state)
        .expect("release survives a failing close");

    assert_eq!(report.channels_closed, 1);
    assert_eq!(report.channels_failed, 1);
    assert_eq!(state, SessionState::Reconnecting);
    assert_eq!(resources.channels.tracked_channels(), 1);
    assert_eq!(resources.channels.open_channels(), 1);
}

#[test]
fn release_stops_workers() {
    let mut resources = SessionResources {
        channels: SessionChannelLedger::default(),
        initiator: None,
        responder: None,
        heartbeat: Some(Heartbeat::new(HeartbeatConfig::default(), Instant::now())),
        backoff: Some(
            ReconnectBackoff::try_new(backoff_config()).expect("backoff config is valid"),
        ),
    };
    let mut state = SessionState::Connected;

    let report = resources
        .release(DisconnectTrigger::HeartbeatLost, &mut state)
        .expect("release stops workers");

    assert_eq!(report.workers_stopped, 2);
    assert!(resources.heartbeat.is_none());
    assert!(resources.backoff.is_none());
    assert_eq!(state, SessionState::Reconnecting);
}
