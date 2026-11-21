use std::net::SocketAddr;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::de::DeserializeOwned;

use identity::TransportCertificate;
use peerbay_lib::discovery::DiscoveryRegistry;
use peerbay_lib::messages::AppChannel;
use peerbay_lib::messages::{PairingAccepted, PairingConfirm};
use peerbay_lib::pairing::{PairingExchange, PairingExchangeState, PairingManager};
use peerbay_lib::session::{
    ChannelSeqSnapshot, DisconnectTrigger, LivenessStatus, MigrationConfig, MigrationPlan,
    PeerSession, ReconnectBackoff, ReconnectBackoffConfig, ReconnectDecision, ResumeKeyStore,
    SessionResumeOutcome, SessionState, TransportMigrationInitiator, TransportMigrationResponder,
};
use peerbay_lib::storage::PeerTrustStore;
use proto::{
    ChannelResumeCursor, ControlMessageType, MessageEnvelope, MessageType, PROTOCOL_VERSION,
    PingBody, PongBody, ResumeKey, ResumeRejectionReason, SequenceError, SessionChannel,
    SessionResumeAccepted, SessionResumeRequest,
};

use transport::{
    ChannelKind, InMemoryTransport, PeerEndpoint, TcpTransport, TlsTransport, Transport,
    TransportChannel, TransportKind,
};

const DEVICE_A: &str = "123e4567-e89b-12d3-a456-426614174000";
const DEVICE_B: &str = "123e4567-e89b-12d3-a456-426614174001";
const PLATFORM: &str = "linux";
const DISPLAY_NAME: &str = "PeerBay Linux";
const SESSION_ID: &str = "session-local-peer-0001";
const RECONNECTED_SESSION_ID: &str = "session-local-peer-0002";
const PAIRING_ID: &str = "pair-local-peer-0001";
const FOREIGN_SESSION_ID: &str = "session-foreign-0001";
const NOW_MS: u64 = 1_000_000;

struct LocalPeer {
    device_id: String,
    certificate: TransportCertificate,
    transport: Option<Arc<InMemoryTransport>>,
    control_channel: Option<TransportChannel>,
    remote_control_channel: Option<TransportChannel>,
    remote_endpoint: PeerEndpoint,
    registry: DiscoveryRegistry,
    pairing: PairingManager,
    trust: PeerTrustStore,
    _trust_dir: tempfile::TempDir,
    session: Option<PeerSession>,
}

impl LocalPeer {
    fn new(device_id: &str) -> Self {
        let certificate =
            TransportCertificate::generate_for_device(device_id).expect("fixture certificate");
        let trust_dir = tempfile::tempdir().expect("fixture temp dir");
        let peers_dir = trust_dir.path().join("peers");
        std::fs::create_dir(&peers_dir).expect("fixture peers dir");

        Self {
            device_id: device_id.to_owned(),
            certificate,
            transport: None,
            control_channel: None,
            remote_control_channel: None,
            remote_endpoint: PeerEndpoint::new(device_id, "127.0.0.1:9", TransportKind::Loopback)
                .expect("fixture endpoint"),
            registry: DiscoveryRegistry::new(Duration::from_secs(60), Duration::from_secs(30)),
            pairing: PairingManager::new(),
            trust: PeerTrustStore::new(peers_dir),
            _trust_dir: trust_dir,
            session: None,
        }
    }

    fn endpoint(device_id: &str) -> PeerEndpoint {
        PeerEndpoint::new(device_id, "127.0.0.1:9", TransportKind::Loopback)
            .expect("fixture peer endpoint")
    }

    fn source() -> SocketAddr {
        "127.0.0.1:9".parse().expect("fixture socket address")
    }

    fn transport(&self) -> &Arc<InMemoryTransport> {
        self.transport.as_ref().expect("transport attached")
    }

    fn session(&self) -> &PeerSession {
        self.session.as_ref().expect("session attached")
    }

    fn session_mut(&mut self) -> &mut PeerSession {
        self.session.as_mut().expect("session attached")
    }

    fn control_channel(&self) -> &TransportChannel {
        self.control_channel
            .as_ref()
            .expect("control channel attached")
    }

    fn remote_control_channel(&self) -> &TransportChannel {
        self.remote_control_channel
            .as_ref()
            .expect("peer control channel attached")
    }

    fn install_backoff(&mut self, config: ReconnectBackoffConfig) {
        self.session_mut().resources_mut().backoff =
            Some(ReconnectBackoff::try_new(config).expect("backoff config is valid"));
    }

    fn open_control(&mut self, other: &mut LocalPeer) {
        self.attach_control(other, SESSION_ID);
    }

    fn attach_control(&mut self, other: &mut LocalPeer, session_id: &str) {
        let now = Instant::now();
        let channel = self
            .transport()
            .open(&self.remote_endpoint, ChannelKind::Control)
            .expect("control channel opens");
        let expected_id = channel.id().to_owned();
        let remote_channel = loop {
            let accepted = other
                .transport()
                .accept()
                .expect("accept polls")
                .expect("peer accepts the control channel");
            if accepted.id() == expected_id {
                break accepted;
            }
        };

        let mut session = PeerSession::new(session_id, now).expect("session creates");
        session
            .open_channel(self.transport().clone(), channel.clone())
            .expect("session attaches");
        self.control_channel = Some(channel);
        self.session = Some(session);

        let mut peer_session = PeerSession::new(session_id, now).expect("peer session creates");
        peer_session
            .open_channel(other.transport().clone(), remote_channel.clone())
            .expect("peer session attaches");
        other.remote_control_channel = Some(remote_channel);
        other.session = Some(peer_session);
    }

    fn pair_with(&mut self, other: &mut LocalPeer) -> PairingAccepted {
        let initiator_session = self
            .pairing
            .begin_initiator(
                PAIRING_ID.to_owned(),
                self.device_id.clone(),
                self.certificate.fingerprint().to_owned(),
                vec![PROTOCOL_VERSION],
                Duration::from_secs(60),
            )
            .expect("manager starts the initiator exchange");
        let start = initiator_session.start_message().expect("start message");
        let (responder_exchange, commit) = PairingExchange::from_pairing_start(
            &start,
            other.device_id.clone(),
            other.certificate.fingerprint().to_owned(),
            vec![PROTOCOL_VERSION],
            Duration::from_secs(60),
        )
        .expect("responder exchange");
        let responder_session = other
            .pairing
            .insert(responder_exchange)
            .expect("manager tracks the responder exchange");
        let mut initiator_session = initiator_session;
        let mut responder_session = responder_session;

        initiator_session
            .apply_commit(&commit)
            .expect("commit applied");
        let initiator_nonce = initiator_session.reveal().expect("initiator nonce");
        let responder_nonce = responder_session.reveal().expect("responder nonce");
        responder_session
            .apply_nonce(&initiator_nonce)
            .expect("responder learned the initiator nonce");
        initiator_session
            .apply_nonce(&responder_nonce)
            .expect("initiator learned the responder nonce");

        let initiator_sas = initiator_session.sas_code().expect("initiator sas");
        let responder_sas = responder_session.sas_code().expect("responder sas");
        assert_eq!(
            initiator_sas.code, responder_sas.code,
            "both peers must compute the same SAS code"
        );

        let code = initiator_session
            .emit_pairing_code(10_000)
            .expect("initiator pairing code");
        let confirm =
            PairingConfirm::accepted(PAIRING_ID, code.sas_code).expect("confirmation message");
        responder_session
            .verify_pairing_confirm(&confirm)
            .expect("responder confirms");
        assert_eq!(responder_session.state(), PairingExchangeState::Confirmed);

        let accepted = responder_session
            .accept(&other.trust, DISPLAY_NAME, PLATFORM)
            .expect("responder accepts and persists trust");
        assert_eq!(
            responder_session.state(),
            PairingExchangeState::SessionTokenIssued
        );

        let code = initiator_session
            .emit_pairing_code(10_000)
            .expect("initiator confirms its own sas");
        let confirm =
            PairingConfirm::accepted(PAIRING_ID, code.sas_code).expect("confirmation message");
        initiator_session
            .verify_pairing_confirm(&confirm)
            .expect("initiator confirms");
        initiator_session
            .apply_accepted(
                &self.trust,
                other.device_id.clone(),
                &accepted,
                DISPLAY_NAME,
                PLATFORM,
            )
            .expect("initiator applies accepted trust");
        assert_eq!(
            initiator_session.state(),
            PairingExchangeState::SessionTokenIssued
        );

        accepted
    }

    fn hello(&mut self) {
        self.session_mut()
            .send_envelope(MessageType::Control(ControlMessageType::Hello), (), NOW_MS)
            .expect("hello sends");
    }

    fn welcome(&mut self) {
        self.session_mut()
            .send_envelope(
                MessageType::Control(ControlMessageType::Welcome),
                (),
                NOW_MS + 5,
            )
            .expect("welcome sends");
    }

    fn expect_hello(&mut self) -> MessageEnvelope<()> {
        self.session_mut()
            .receive_envelope::<()>()
            .expect("hello receives")
            .expect("hello payload")
    }

    fn expect_welcome(&mut self) -> MessageEnvelope<()> {
        self.session_mut()
            .receive_envelope::<()>()
            .expect("welcome receives")
            .expect("welcome payload")
    }

    fn ping(&mut self, now: Instant) -> u64 {
        self.session_mut().send_ping(now).expect("ping sends")
    }

    fn expect_ping(&mut self) -> MessageEnvelope<PingBody> {
        self.session_mut()
            .receive_envelope::<PingBody>()
            .expect("ping receives")
            .expect("ping payload")
    }

    fn pong(&mut self, ping: &MessageEnvelope<PingBody>) {
        self.session_mut()
            .handle_liveness(ping)
            .expect("pong sends");
    }

    fn expect_pong(&mut self) -> MessageEnvelope<PongBody> {
        let envelope = self
            .session_mut()
            .receive_envelope::<PongBody>()
            .expect("pong receives")
            .expect("pong payload");
        assert_eq!(
            envelope.message_type,
            MessageType::Control(ControlMessageType::Pong)
        );
        envelope
    }

    fn record_pong(&mut self, pong: &MessageEnvelope<PongBody>, now: Instant) -> u32 {
        self.session_mut()
            .on_pong(pong, now)
            .expect("pong matches the pending ping")
            .rtt_ms_saturating()
    }

    fn liveness(&mut self, now: Instant) -> LivenessStatus {
        self.session_mut()
            .resources_mut()
            .heartbeat
            .as_mut()
            .expect("heartbeat worker")
            .check(now)
    }

    fn send_resume_request(&mut self, request: SessionResumeRequest) {
        self.session_mut()
            .send_envelope(
                MessageType::Control(ControlMessageType::SessionResume),
                request,
                NOW_MS + 5,
            )
            .expect("resume request sends");
    }

    fn expect_resume_request(&mut self) -> MessageEnvelope<SessionResumeRequest> {
        self.session_mut()
            .receive_envelope::<SessionResumeRequest>()
            .expect("resume request receives")
            .expect("resume request payload")
    }

    fn send_resume_accepted(&mut self, accepted: SessionResumeAccepted) {
        self.session_mut()
            .send_envelope(
                MessageType::Control(ControlMessageType::SessionResume),
                accepted,
                NOW_MS + 12,
            )
            .expect("resume accepted sends");
    }

    fn expect_resume_accepted(&mut self) -> SessionResumeAccepted {
        self.session_mut()
            .receive_envelope::<SessionResumeAccepted>()
            .expect("resume accepted receives")
            .expect("resume accepted payload")
            .body
    }
}

fn local_peer_pair() -> (LocalPeer, LocalPeer) {
    let mut peer_a = LocalPeer::new(DEVICE_A);
    let mut peer_b = LocalPeer::new(DEVICE_B);
    let (transport_a, transport_b) =
        InMemoryTransport::pair(LocalPeer::endpoint(DEVICE_A), LocalPeer::endpoint(DEVICE_B))
            .expect("fixture transport pair");
    peer_a.transport = Some(Arc::new(transport_a));
    peer_a.remote_endpoint = LocalPeer::endpoint(DEVICE_B);
    peer_b.transport = Some(Arc::new(transport_b));
    peer_b.remote_endpoint = LocalPeer::endpoint(DEVICE_A);

    let observed_at = Instant::now();
    assert!(
        peer_a
            .registry
            .observe(DEVICE_B, PLATFORM, LocalPeer::source(), 9, observed_at)
            .expect("a observes b")
    );
    assert!(
        peer_b
            .registry
            .observe(DEVICE_A, PLATFORM, LocalPeer::source(), 9, observed_at)
            .expect("b observes a")
    );

    (peer_a, peer_b)
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

fn backoff_config(max_attempts: u32) -> ReconnectBackoffConfig {
    ReconnectBackoffConfig::new(
        Duration::from_millis(50),
        2,
        Duration::from_secs(10),
        max_attempts,
    )
}

fn control_cursor(last_sent_seq: u64, last_received_seq: u64) -> ChannelResumeCursor {
    ChannelResumeCursor::new(SessionChannel::Control, last_sent_seq, last_received_seq)
}

fn control_snapshot(last_sent_seq: u64, last_received_seq: u64) -> ChannelSeqSnapshot {
    ChannelSeqSnapshot {
        channel: SessionChannel::Control,
        last_sent_seq,
        last_received_seq,
    }
}

fn plan_for(
    old_transport: Arc<InMemoryTransport>,
    old_channel: TransportChannel,
    cursors: Vec<ChannelResumeCursor>,
) -> MigrationPlan {
    MigrationPlan {
        old_transport,
        old_channel,
        target: TransportKind::LocalNetwork,
        cursors,
    }
}

fn control_cursors(session: &PeerSession) -> Vec<ChannelResumeCursor> {
    vec![control_cursor(
        session.last_sent_seq().unwrap_or(0),
        session.last_received_seq(AppChannel::Control).unwrap_or(0),
    )]
}

fn socket_endpoint(device_id: &str, port: u16) -> PeerEndpoint {
    PeerEndpoint::new(
        device_id,
        format!("127.0.0.1:{}", port),
        TransportKind::Loopback,
    )
    .expect("fixture socket endpoint")
}

trait PendingAccept {
    fn accept_pending(&self) -> eros::Result<Option<TransportChannel>>;
}

impl PendingAccept for TcpTransport {
    fn accept_pending(&self) -> eros::Result<Option<TransportChannel>> {
        self.accept()
    }
}

impl PendingAccept for TlsTransport {
    fn accept_pending(&self) -> eros::Result<Option<TransportChannel>> {
        self.accept()
    }
}

fn wait_for_channel<T: PendingAccept>(transport: &T) -> TransportChannel {
    for _ in 0..150 {
        if let Some(channel) = transport.accept_pending().expect("accept polls") {
            return channel;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("peer did not accept the channel");
}

fn drain_envelope<T: DeserializeOwned>(session: &mut PeerSession) -> MessageEnvelope<T> {
    for _ in 0..150 {
        if let Some(envelope) = session.receive_envelope().expect("receive polls") {
            return envelope;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("peer did not deliver the envelope");
}

fn hello_ping_over<T>(initiator: &Arc<T>, responder: &Arc<T>, peer: &PeerEndpoint)
where
    T: Transport + PendingAccept + Send + Sync + 'static,
{
    let responder = Arc::clone(responder);
    let responder_thread = thread::spawn(move || {
        let channel = wait_for_channel(responder.as_ref());
        let mut session_b =
            PeerSession::new(SESSION_ID, Instant::now()).expect("session b creates");
        session_b
            .open_channel(responder.clone(), channel)
            .expect("session b attaches");

        let hello = drain_envelope::<()>(&mut session_b);
        assert_eq!(hello.v, PROTOCOL_VERSION);
        assert_eq!(hello.session_id, SESSION_ID);
        assert_eq!(hello.seq, 0);
        assert_eq!(
            hello.message_type,
            MessageType::Control(ControlMessageType::Hello)
        );

        session_b
            .send_envelope(
                MessageType::Control(ControlMessageType::Welcome),
                (),
                NOW_MS + 5,
            )
            .expect("welcome sends");
        let ping = drain_envelope::<PingBody>(&mut session_b);
        session_b.handle_liveness(&ping).expect("pong sends");
    });

    let channel = initiator
        .open(peer, ChannelKind::Control)
        .expect("control channel opens");
    let now = Instant::now();
    let mut session_a = PeerSession::new(SESSION_ID, now).expect("session a creates");
    session_a
        .open_channel(initiator.clone(), channel)
        .expect("session a attaches");
    session_a
        .send_envelope(MessageType::Control(ControlMessageType::Hello), (), NOW_MS)
        .expect("hello sends");

    let welcome = drain_envelope::<()>(&mut session_a);
    assert_eq!(welcome.seq, 0);
    assert_eq!(
        welcome.message_type,
        MessageType::Control(ControlMessageType::Welcome)
    );

    let start = Instant::now();
    let ping_seq = session_a.send_ping(start).expect("ping sends");
    assert_eq!(ping_seq, 1);
    let pong = drain_envelope::<PongBody>(&mut session_a);
    let rtt = session_a
        .on_pong(&pong, start + Duration::from_millis(20))
        .expect("pong matches the pending ping");
    assert!(rtt.rtt_ms_saturating() >= 20);

    responder_thread.join().expect("responder thread joins");
}

#[test]
fn two_local_peers_pair_hello_and_ping() {
    let (mut peer_a, mut peer_b) = local_peer_pair();

    let discovered = peer_a
        .registry
        .get(DEVICE_B)
        .expect("a discovered b through the registry");
    assert_eq!(discovered.device_id, DEVICE_B);
    assert_eq!(discovered.port, 9);
    assert!(discovered.addresses.contains_key("127.0.0.1:9"));

    peer_a.open_control(&mut peer_b);
    assert_eq!(peer_a.session().state(), SessionState::Connected);
    assert_eq!(peer_b.session().state(), SessionState::Connected);

    let accepted = peer_a.pair_with(&mut peer_b);
    assert_eq!(accepted.pairing_id, PAIRING_ID);
    assert!(!accepted.session_token.is_empty());
    assert!(accepted.expires_at_ms > 0);

    let record_a = peer_a
        .trust
        .load(DEVICE_B)
        .expect("initiator trusts the responder");
    assert_eq!(record_a.device_id, DEVICE_B);
    assert!(!record_a.is_revoked());
    assert!(!record_a.pairing_token_hash.is_empty());
    let record_b = peer_b
        .trust
        .load(DEVICE_A)
        .expect("responder trusts the initiator");
    assert_eq!(record_b.device_id, DEVICE_A);
    assert!(!record_b.is_revoked());

    peer_a.hello();
    let hello = peer_b.expect_hello();
    assert_eq!(hello.v, PROTOCOL_VERSION);
    assert_eq!(hello.session_id, SESSION_ID);
    assert_eq!(hello.seq, 0);
    assert_eq!(
        hello.message_type,
        MessageType::Control(ControlMessageType::Hello)
    );

    peer_b.welcome();
    let welcome = peer_a.expect_welcome();
    assert_eq!(welcome.seq, 0);
    assert_eq!(
        welcome.message_type,
        MessageType::Control(ControlMessageType::Welcome)
    );

    let start = Instant::now();
    let ping_seq = peer_a.ping(start);
    assert_eq!(ping_seq, 1);
    let ping = peer_b.expect_ping();
    peer_b.pong(&ping);
    let pong = peer_a.expect_pong();
    let rtt_ms = peer_a.record_pong(&pong, start + Duration::from_millis(20));
    assert!(rtt_ms >= 20);
    assert_eq!(
        peer_a.liveness(start + Duration::from_millis(60)),
        LivenessStatus::Alive
    );
}

#[test]
fn hello_sequence_is_session_scoped_and_monotonic() {
    let (mut peer_a, mut peer_b) = local_peer_pair();
    peer_a.open_control(&mut peer_b);

    peer_a.hello();
    assert_eq!(peer_b.expect_hello().seq, 0);
    peer_a.hello();
    assert_eq!(peer_b.expect_hello().seq, 1);
    peer_a.hello();
    assert_eq!(peer_b.expect_hello().seq, 2);

    let foreign = MessageEnvelope::new(
        "m-foreign",
        MessageType::Control(ControlMessageType::Hello),
        FOREIGN_SESSION_ID,
        9,
        NOW_MS,
        (),
    );
    let payload = serde_json::to_vec(&foreign).expect("encode foreign envelope");
    peer_a
        .transport()
        .send(
            peer_a
                .control_channel
                .as_ref()
                .expect("control channel attached"),
            payload,
        )
        .expect("foreign raw send");
    let error = peer_b
        .session_mut()
        .receive_envelope::<()>()
        .expect_err("foreign session envelope must fail");
    assert!(
        matches!(
            error.downcast_inner::<SequenceError>(),
            Ok(SequenceError::SessionMismatch { .. })
        ),
        "envelopes from another session must fail with SessionMismatch"
    );
}

#[test]
fn reconnect_after_channel_loss_restores_session() {
    let (mut peer_a, mut peer_b) = local_peer_pair();
    peer_a.open_control(&mut peer_b);
    let lost_channel = peer_a.control_channel().clone();

    peer_a
        .transport()
        .close(&lost_channel)
        .expect("initiator side loses the channel");
    peer_b
        .transport()
        .close(peer_b.remote_control_channel())
        .expect("responder side loses the channel");
    assert!(
        !peer_a
            .transport()
            .is_open(&lost_channel)
            .expect("lost channel metadata"),
        "channel loss leaves the link closed"
    );

    let report = peer_a
        .session_mut()
        .disconnect(DisconnectTrigger::HeartbeatLost)
        .expect("loss release routes state");
    assert_eq!(report.from_state, SessionState::Connected);
    assert_eq!(report.to_state, SessionState::Reconnecting);
    assert_eq!(report.channels_closed, 1);
    assert_eq!(report.workers_stopped, 1);
    assert_eq!(peer_a.session().state(), SessionState::Reconnecting);

    peer_a.install_backoff(backoff_config(3));
    let decision = peer_a
        .session_mut()
        .resources_mut()
        .backoff
        .as_mut()
        .expect("backoff installed")
        .next_decision_with_jitter(|delay| delay);
    assert_eq!(
        decision,
        ReconnectDecision::Retry {
            attempt: 1,
            delay: Duration::from_millis(50)
        }
    );

    peer_a.attach_control(&mut peer_b, RECONNECTED_SESSION_ID);
    assert_eq!(peer_a.session().session_id(), RECONNECTED_SESSION_ID);
    assert_eq!(peer_a.session().state(), SessionState::Connected);

    peer_a.hello();
    let hello = peer_b.expect_hello();
    assert_eq!(hello.session_id, RECONNECTED_SESSION_ID);
    assert_eq!(hello.seq, 0);

    let start = Instant::now();
    let ping_seq = peer_a.ping(start);
    assert_eq!(ping_seq, 1);
    let ping = peer_b.expect_ping();
    peer_b.pong(&ping);
    let pong = peer_a.expect_pong();
    assert!(peer_a.record_pong(&pong, start + Duration::from_millis(20)) >= 20);
    assert!(
        !peer_a
            .transport()
            .is_open(&lost_channel)
            .expect("lost channel metadata"),
        "the lost channel never comes back"
    );
}

#[test]
fn backoff_exhaustion_gives_up_before_release() {
    let (mut peer_a, mut peer_b) = local_peer_pair();
    peer_a.open_control(&mut peer_b);
    peer_a.install_backoff(ReconnectBackoffConfig::new(
        Duration::from_millis(20),
        2,
        Duration::from_secs(5),
        2,
    ));

    let backoff = peer_a
        .session_mut()
        .resources_mut()
        .backoff
        .as_mut()
        .expect("backoff installed");
    assert_eq!(
        backoff.next_decision_with_jitter(|delay| delay),
        ReconnectDecision::Retry {
            attempt: 1,
            delay: Duration::from_millis(20)
        }
    );
    assert_eq!(
        backoff.next_decision_with_jitter(|delay| delay),
        ReconnectDecision::Retry {
            attempt: 2,
            delay: Duration::from_millis(40)
        }
    );
    assert!(backoff.is_exhausted());
    assert_eq!(
        backoff.next_decision_with_jitter(|delay| delay),
        ReconnectDecision::GiveUp { attempts: 2 }
    );
    assert!(backoff.is_exhausted());

    let report = peer_a
        .session_mut()
        .disconnect(DisconnectTrigger::TrustRevoked)
        .expect("caller releases after the backoff gives up");
    assert_eq!(report.to_state, SessionState::Released);
    assert_eq!(peer_a.session().state(), SessionState::Released);
}

#[test]
fn resume_requests_are_rejected_after_disconnect() {
    let (mut peer_a, mut peer_b) = local_peer_pair();
    peer_a.open_control(&mut peer_b);
    let key = session_key("ab");

    let old_transport = peer_a.transport().clone();
    let old_channel = peer_a.control_channel().clone();
    let responder_transport = peer_b.transport().clone();
    let responder_channel = peer_b.remote_control_channel().clone();

    let initiator = TransportMigrationInitiator::try_new(
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
        .note_local_old_channel(responder_transport, responder_channel)
        .expect("responder tracks old channel");
    peer_a.session_mut().resources_mut().initiator = Some(initiator);
    peer_b.session_mut().resources_mut().responder = Some(responder);

    let stashed = peer_a
        .session_mut()
        .resources_mut()
        .initiator
        .as_mut()
        .expect("initiator installed")
        .begin(
            plan_for(old_transport, old_channel, vec![control_cursor(0, 0)]),
            key,
            NOW_MS,
        )
        .expect("migration begins");
    let outcome = peer_b
        .session_mut()
        .resources_mut()
        .responder
        .as_mut()
        .expect("responder installed")
        .handle_request(&stashed, NOW_MS + 10, Some(&[control_snapshot(0, 0)]))
        .expect("responder handles the request");
    let SessionResumeOutcome::Accepted(_accepted) = outcome else {
        panic!("responder must accept the handshake request");
    };

    let released = peer_b
        .session_mut()
        .disconnect(DisconnectTrigger::PeerReleased)
        .expect("responder releases");
    assert!(
        released.secrets_cleared,
        "release tears down the responder and clears resume keys"
    );
    assert_eq!(released.to_state, SessionState::Released);
    peer_a
        .session_mut()
        .disconnect(DisconnectTrigger::PeerReleased)
        .expect("initiator releases");

    let fresh_key = session_key("cd");
    peer_a.attach_control(&mut peer_b, RECONNECTED_SESSION_ID);
    let mut fresh_responder = TransportMigrationResponder::try_new(
        responder_config(),
        RECONNECTED_SESSION_ID,
        SessionChannel::Control,
        ResumeKeyStore::inherit(RECONNECTED_SESSION_ID, fresh_key).expect("fresh responder store"),
        SessionState::Connected,
    )
    .expect("fresh responder creates");

    let replay = MessageEnvelope::new(
        "m-replay",
        MessageType::Control(ControlMessageType::SessionResume),
        SESSION_ID,
        0,
        NOW_MS,
        stashed.clone(),
    );
    let payload = serde_json::to_vec(&replay).expect("encode stashed envelope");
    peer_a
        .transport()
        .send(peer_a.control_channel(), payload)
        .expect("replay raw send");
    let error = peer_b
        .session_mut()
        .receive_envelope::<SessionResumeRequest>()
        .expect_err("old session replay must fail");
    assert!(
        matches!(
            error.downcast_inner::<SequenceError>(),
            Ok(SequenceError::SessionMismatch { .. })
        ),
        "traffic bound to the old session is rejected by the sequence tracker"
    );

    let rekeyed = SessionResumeRequest::new(
        RECONNECTED_SESSION_ID,
        session_key("ab"),
        stashed.migration.clone(),
        stashed.cursors.clone(),
        NOW_MS + 20,
        NOW_MS + 220,
    )
    .expect("rekeyed request is valid");
    peer_a.send_resume_request(rekeyed);
    let replayed = peer_b.expect_resume_request();
    let outcome = fresh_responder
        .handle_request(&replayed.body, NOW_MS + 30, None)
        .expect("fresh responder handles the replay");
    let SessionResumeOutcome::Rejected(rejected) = outcome else {
        panic!("the old resume key must be rejected on the fresh session");
    };
    assert_eq!(
        rejected.reason,
        ResumeRejectionReason::InvalidResumeKey,
        "a disconnected session's resume key cannot open the reconnected one"
    );
}

#[test]
fn transport_resume_continues_sequence_across_migration() {
    let (mut peer_a, mut peer_b) = local_peer_pair();
    peer_a.open_control(&mut peer_b);

    peer_a.hello();
    let _hello = peer_b.expect_hello();
    peer_b.welcome();
    let _welcome = peer_a.expect_welcome();

    let key = session_key("ab");
    let old_transport = peer_a.transport().clone();
    let old_channel = peer_a.control_channel().clone();
    let responder_transport = peer_b.transport().clone();
    let responder_channel = peer_b.remote_control_channel().clone();

    let initiator = TransportMigrationInitiator::try_new(
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
        .note_local_old_channel(responder_transport, responder_channel)
        .expect("responder tracks old channel");
    peer_a.session_mut().resources_mut().initiator = Some(initiator);
    peer_b.session_mut().resources_mut().responder = Some(responder);

    let cursors = control_cursors(peer_a.session());
    let request = peer_a
        .session_mut()
        .resources_mut()
        .initiator
        .as_mut()
        .expect("initiator installed")
        .begin(plan_for(old_transport, old_channel, cursors), key, NOW_MS)
        .expect("migration begins");
    let snapshot = control_snapshot(0, 0);

    peer_a.send_resume_request(request);
    let received_request = peer_b.expect_resume_request();
    assert_eq!(received_request.seq, 1);
    let outcome = peer_b
        .session_mut()
        .resources_mut()
        .responder
        .as_mut()
        .expect("responder installed")
        .handle_request(&received_request.body, NOW_MS + 10, Some(&[snapshot]))
        .expect("responder handles the request");
    let SessionResumeOutcome::Accepted(accepted) = outcome else {
        panic!("responder must accept the handshake request");
    };
    peer_b.send_resume_accepted(accepted);
    let accepted = peer_a.expect_resume_accepted();
    peer_a
        .session_mut()
        .resources_mut()
        .initiator
        .as_mut()
        .expect("initiator installed")
        .resume_accepted(&accepted, NOW_MS + 15)
        .expect("initiator processes acceptance");

    let new_channel = peer_a
        .session()
        .resources()
        .initiator
        .as_ref()
        .expect("initiator installed")
        .new_channel()
        .expect("migrated channel opened")
        .clone();
    let transport_a = peer_a.transport().clone();
    let transport_b = peer_b.transport().clone();
    peer_a
        .session_mut()
        .adopt_primary(transport_a.clone(), new_channel.clone())
        .expect("initiator adopts the migrated primary");
    peer_b
        .session_mut()
        .adopt_primary(transport_b.clone(), new_channel.clone())
        .expect("responder adopts the migrated primary");

    let start = Instant::now();
    let ping_seq = peer_a.ping(start);
    assert_eq!(
        ping_seq, 2,
        "sequence continues across the migration without a replay"
    );
    let ping = peer_b.expect_ping();
    peer_b.pong(&ping);
    let pong = peer_a.expect_pong();
    assert!(peer_a.record_pong(&pong, start + Duration::from_millis(20)) >= 20);

    let old_channel_a = peer_a.control_channel().clone();
    assert!(
        transport_a
            .is_open(&old_channel_a)
            .expect("fallback channel metadata"),
        "the old channel stays open as the migration fallback"
    );
    peer_a
        .session_mut()
        .resources_mut()
        .initiator
        .as_mut()
        .expect("initiator installed")
        .tick(NOW_MS + 76)
        .expect("fallback expiry tick");
    assert!(
        !transport_a
            .is_open(&old_channel_a)
            .expect("fallback channel metadata"),
        "fallback closes after its window"
    );

    let old_channel_b = peer_b.remote_control_channel().clone();
    assert!(
        peer_b
            .session_mut()
            .resources_mut()
            .responder
            .as_mut()
            .expect("responder installed")
            .close_expired_fallback(NOW_MS + 150)
            .expect("responder closes its fallback")
    );
    assert!(
        !transport_b
            .is_open(&old_channel_b)
            .expect("fallback channel metadata"),
        "responder fallback closes too"
    );
}

#[test]
fn loopback_tcp_peers_complete_hello_and_ping() {
    let endpoint_a = socket_endpoint("peer-tcp-e2e-a", 19301);
    let endpoint_b = socket_endpoint("peer-tcp-e2e-b", 19302);
    let (tcp_a, tcp_b) = TcpTransport::pair(endpoint_a, endpoint_b.clone()).expect("tcp pair");
    hello_ping_over(&Arc::new(tcp_a), &Arc::new(tcp_b), &endpoint_b);
}

#[test]
fn loopback_tls_peers_complete_hello_and_ping_with_pinned_certs() {
    let certificate_a =
        TransportCertificate::generate_for_device(DEVICE_A).expect("certificate a generates");
    let certificate_b =
        TransportCertificate::generate_for_device(DEVICE_B).expect("certificate b generates");
    let tls_a = TlsTransport::with_certificate(
        socket_endpoint(DEVICE_A, 19911),
        certificate_a,
        Some(certificate_b.certificate_der().to_vec()),
    )
    .expect("tls client creates");
    let tls_b =
        TlsTransport::with_certificate(socket_endpoint(DEVICE_B, 19912), certificate_b, None)
            .expect("tls server creates");
    let peer_b = socket_endpoint(DEVICE_B, 19912);
    hello_ping_over(&Arc::new(tls_a), &Arc::new(tls_b), &peer_b);
}
