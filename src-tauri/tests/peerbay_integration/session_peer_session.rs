use std::sync::Arc;
use std::time::{Duration, Instant};

use peerbay_lib::session::{
    DisconnectTrigger, LivenessStatus, PeerSession, SessionError, SessionState,
};
use proto::{
    ControlMessageType, MessageEnvelope, MessageType, PROTOCOL_VERSION, PingBody, PongBody,
    SequenceError,
};

use transport::{ChannelKind, InMemoryTransport, PeerEndpoint, Transport as _, TransportKind};

const SESSION_ID: &str = "session-peer-session-0001";
const NOW_MS: u64 = 1_000_000;

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

struct AttachedPair {
    a: Arc<InMemoryTransport>,
    channel_a: transport::TransportChannel,
    peer_a: PeerSession,
    peer_b: PeerSession,
}

fn attached_pair() -> AttachedPair {
    let (a, b) = in_memory_pair();
    let peer = endpoint("00000000-0000-0000-0000-000000000002");
    let channel_a = a.open(&peer, ChannelKind::Control).expect("channel opens");
    let channel_b = b
        .accept()
        .expect("accept channel")
        .expect("channel accepted");
    let now = Instant::now();
    let mut peer_a = PeerSession::new(SESSION_ID, now).expect("session a creates");
    let mut peer_b = PeerSession::new(SESSION_ID, now).expect("session b creates");
    peer_a
        .open_channel(a.clone(), channel_a.clone())
        .expect("session a attaches");
    peer_b
        .open_channel(b.clone(), channel_b)
        .expect("session b attaches");

    AttachedPair {
        a,
        channel_a,
        peer_a,
        peer_b,
    }
}

#[test]
fn open_channel_and_roundtrip_envelope() {
    let mut pair = attached_pair();
    assert_eq!(pair.peer_a.state(), SessionState::Connected);
    assert_eq!(pair.peer_b.state(), SessionState::Connected);
    assert_eq!(pair.peer_a.session_id(), SESSION_ID);

    pair.peer_a
        .send_envelope(MessageType::Control(ControlMessageType::Hello), (), NOW_MS)
        .expect("hello sends");
    let hello = pair
        .peer_b
        .receive_envelope::<()>()
        .expect("hello receives")
        .expect("hello payload");
    assert_eq!(hello.v, PROTOCOL_VERSION);
    assert_eq!(
        hello.message_type,
        MessageType::Control(ControlMessageType::Hello)
    );
    assert_eq!(hello.session_id, SESSION_ID);
    assert_eq!(hello.seq, 0);
    assert_eq!(hello.timestamp_ms, NOW_MS);

    pair.peer_b
        .send_envelope(
            MessageType::Control(ControlMessageType::Welcome),
            (),
            NOW_MS + 5,
        )
        .expect("welcome sends");
    let welcome = pair
        .peer_a
        .receive_envelope::<()>()
        .expect("welcome receives")
        .expect("welcome payload");
    assert_eq!(
        welcome.message_type,
        MessageType::Control(ControlMessageType::Welcome)
    );
    assert_eq!(welcome.seq, 0);

    pair.peer_a
        .send_envelope(
            MessageType::Control(ControlMessageType::Ping),
            (),
            NOW_MS + 10,
        )
        .expect("second message sends");
    let second = pair
        .peer_b
        .receive_envelope::<()>()
        .expect("second message receives")
        .expect("second message payload");
    assert_eq!(second.seq, 1);
}

#[test]
fn receive_rejects_replayed_and_foreign_session_sequences() {
    let mut pair = attached_pair();
    pair.peer_a
        .send_envelope(MessageType::Control(ControlMessageType::Hello), (), NOW_MS)
        .expect("hello sends");
    let hello = pair
        .peer_b
        .receive_envelope::<()>()
        .expect("hello receives")
        .expect("hello payload");
    pair.peer_a
        .send_envelope(
            MessageType::Control(ControlMessageType::Ping),
            PingBody::new(),
            NOW_MS + 1,
        )
        .expect("ping sends");
    let _ping = pair
        .peer_b
        .receive_envelope::<PingBody>()
        .expect("ping receives")
        .expect("ping payload");

    let replay = serde_json::to_vec(&hello).expect("encode replay");
    pair.a
        .send(&pair.channel_a, replay)
        .expect("replay raw send");
    let error = pair
        .peer_b
        .receive_envelope::<()>()
        .expect_err("replayed sequence must fail");
    assert!(
        matches!(
            error.downcast_inner::<SequenceError>(),
            Ok(SequenceError::Replay {
                seq: 0,
                last_accepted: 1,
                ..
            })
        ),
        "replayed sequence below the watermark must fail with Replay"
    );

    let foreign = MessageEnvelope::new(
        "m-foreign",
        MessageType::Control(ControlMessageType::Hello),
        "session-foreign-0001",
        5,
        NOW_MS,
        (),
    );
    let payload = serde_json::to_vec(&foreign).expect("encode foreign envelope");
    pair.a
        .send(&pair.channel_a, payload)
        .expect("foreign raw send");
    let error = pair
        .peer_b
        .receive_envelope::<()>()
        .expect_err("foreign session must fail");
    assert!(
        matches!(
            error.downcast_inner::<SequenceError>(),
            Ok(SequenceError::SessionMismatch { .. })
        ),
        "envelopes from another session must fail with SessionMismatch"
    );
}

#[test]
fn ping_gets_pong_with_rtt() {
    let mut pair = attached_pair();
    let start = Instant::now();

    let ping_seq = pair.peer_a.send_ping(start).expect("ping sends");
    assert_eq!(ping_seq, 0);
    let ping = pair
        .peer_b
        .receive_envelope::<PingBody>()
        .expect("ping receives")
        .expect("ping payload");
    pair.peer_b.handle_liveness(&ping).expect("pong sends");
    let pong = pair
        .peer_a
        .receive_envelope::<PongBody>()
        .expect("pong receives")
        .expect("pong payload");
    assert_eq!(pong.body.ping_id, "m-0");
    assert_eq!(pong.body.ping_seq, Some(0));

    let answered = start + Duration::from_millis(20);
    let rtt = pair
        .peer_a
        .on_pong(&pong, answered)
        .expect("pong matches the pending ping");
    assert!(rtt.rtt_ms_saturating() >= 20);

    let heartbeat = pair
        .peer_a
        .resources_mut()
        .heartbeat
        .as_mut()
        .expect("heartbeat worker");
    assert!(heartbeat.latest_rtt().is_some());
    assert_eq!(
        heartbeat.check(answered + Duration::from_millis(60)),
        LivenessStatus::Alive
    );
}

#[test]
fn disconnect_releases_channel_and_routes_state() {
    let mut pair = attached_pair();

    let report = pair
        .peer_a
        .disconnect(DisconnectTrigger::HeartbeatLost)
        .expect("disconnect routes");

    assert_eq!(report.trigger, DisconnectTrigger::HeartbeatLost);
    assert_eq!(report.from_state, SessionState::Connected);
    assert_eq!(report.to_state, SessionState::Reconnecting);
    assert_eq!(report.channels_closed, 1);
    assert_eq!(report.workers_stopped, 1);
    assert!(!report.already_released);
    assert_eq!(pair.peer_a.state(), SessionState::Reconnecting);
    assert!(
        !pair.a.is_open(&pair.channel_a).expect("channel metadata"),
        "release must close the tracked channel"
    );
    assert!(
        pair.peer_a.resources().heartbeat.is_none(),
        "release stops the heartbeat worker"
    );

    let again = pair
        .peer_a
        .disconnect(DisconnectTrigger::HeartbeatLost)
        .expect("second disconnect");
    assert!(again.already_released);
    assert_eq!(again.to_state, SessionState::Reconnecting);
    assert_eq!(pair.peer_a.state(), SessionState::Reconnecting);

    let terminal = pair
        .peer_a
        .disconnect(DisconnectTrigger::TrustRevoked)
        .expect("terminal disconnect");
    assert_eq!(terminal.to_state, SessionState::Released);
    assert_eq!(pair.peer_a.state(), SessionState::Released);

    let error = pair
        .peer_a
        .send_envelope(MessageType::Control(ControlMessageType::Hello), (), NOW_MS)
        .expect_err("sending without a channel must fail");
    assert!(
        matches!(
            error.downcast_inner::<SessionError>(),
            Ok(SessionError::ChannelNotAttached)
        ),
        "a released session has no channel attached"
    );
}
