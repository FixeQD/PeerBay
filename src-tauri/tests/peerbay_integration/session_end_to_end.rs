use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use peerbay_lib::discovery::DiscoveryRegistry;
use peerbay_lib::identity::TransportCertificate;
use peerbay_lib::pairing::{PairingExchange, PairingExchangeState, PairingManager};
use peerbay_lib::protocol::pairing::{PairingAccepted, PairingConfirm};
use peerbay_lib::protocol::{
    ControlMessageType, MessageEnvelope, MessageType, PROTOCOL_VERSION, PingBody, PongBody,
    SequenceError,
};
use peerbay_lib::session::{LivenessStatus, PeerSession, SessionState};
use peerbay_lib::storage::PeerTrustStore;
use peerbay_lib::transport::{
    ChannelKind, InMemoryTransport, PeerEndpoint, Transport as _, TransportChannel, TransportKind,
};

const DEVICE_A: &str = "123e4567-e89b-12d3-a456-426614174000";
const DEVICE_B: &str = "123e4567-e89b-12d3-a456-426614174001";
const PLATFORM: &str = "linux";
const DISPLAY_NAME: &str = "PeerBay Linux";
const SESSION_ID: &str = "session-local-peer-0001";
const PAIRING_ID: &str = "pair-local-peer-0001";
const FOREIGN_SESSION_ID: &str = "session-foreign-0001";
const NOW_MS: u64 = 1_000_000;

struct LocalPeer {
    device_id: String,
    certificate: TransportCertificate,
    transport: Option<Arc<InMemoryTransport>>,
    control_channel: Option<TransportChannel>,
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

    fn open_control(&mut self, other: &mut LocalPeer) {
        let now = Instant::now();
        let channel = self
            .transport()
            .open(&self.remote_endpoint, ChannelKind::Control)
            .expect("control channel opens");
        let remote_channel = other
            .transport()
            .accept()
            .expect("accept polls")
            .expect("peer accepted the control channel");

        let mut session = PeerSession::new(SESSION_ID, now).expect("session creates");
        session
            .open_channel(self.transport().clone(), channel.clone())
            .expect("session attaches");
        self.control_channel = Some(channel);
        self.session = Some(session);

        let mut peer_session = PeerSession::new(SESSION_ID, now).expect("peer session creates");
        peer_session
            .open_channel(other.transport().clone(), remote_channel)
            .expect("peer session attaches");
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
