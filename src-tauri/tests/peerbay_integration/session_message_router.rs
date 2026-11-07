use std::sync::{Arc, Mutex};

use serde_json::{Value, json};

use peerbay_lib::protocol::{
    ClipboardMessageType, ControlMessageType, FileMessageType, InputMessageType, MediaMessageType,
    MessageChannel, MessageEnvelope, MessageType, PairingMessageType, PhoneMessageType,
};
use peerbay_lib::session::{
    RouteDisposition, RoutedMessage, SessionError, SessionMessageHandler, SessionRouter,
};

struct RecordingHandler {
    domain: MessageChannel,
    seen: Mutex<Vec<(String, u64, String)>>,
}

impl RecordingHandler {
    fn new(domain: MessageChannel) -> Self {
        Self {
            domain,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<(String, u64, String)> {
        self.seen.lock().expect("recording lock").clone()
    }
}

impl SessionMessageHandler for RecordingHandler {
    fn domain(&self) -> MessageChannel {
        self.domain
    }

    fn handle(&self, message: &RoutedMessage, _body: &Value) -> eros::Result<()> {
        self.seen.lock().expect("recording lock").push((
            message.message_id.clone(),
            message.sequence,
            message.message_type.as_str().to_owned(),
        ));
        Ok(())
    }
}

fn envelope(message_type: MessageType, seq: u64) -> MessageEnvelope<Value> {
    MessageEnvelope::new(
        format!("msg-{seq}"),
        message_type,
        "session-1",
        seq,
        1_700_000_000_000,
        json!({ "ok": true }),
    )
}

fn router_with_all_domains() -> (SessionRouter, Vec<(MessageChannel, Arc<RecordingHandler>)>) {
    let mut router = SessionRouter::new();
    let mut handlers = Vec::new();
    for domain in [
        MessageChannel::Control,
        MessageChannel::Pairing,
        MessageChannel::Clipboard,
        MessageChannel::Files,
        MessageChannel::Input,
        MessageChannel::Media,
        MessageChannel::Phone,
    ] {
        let handler = Arc::new(RecordingHandler::new(domain));
        router
            .register(handler.clone())
            .expect("domain should register");
        handlers.push((domain, handler));
    }
    (router, handlers)
}

#[test]
fn routes_control_messages_to_control_handler() {
    let mut router = SessionRouter::new();
    let handler = Arc::new(RecordingHandler::new(MessageChannel::Control));
    router.register(handler.clone()).expect("register");

    let disposition = router
        .route(&envelope(MessageType::Control(ControlMessageType::Ping), 1))
        .expect("route");

    assert_eq!(
        disposition,
        RouteDisposition::Handled(MessageChannel::Control)
    );
    assert_eq!(handler.seen(), vec![("msg-1".into(), 1, "ping".into())]);
}

#[test]
fn routes_feature_messages_to_their_domain_handlers() {
    let (router, handlers) = router_with_all_domains();

    let cases = [
        (
            MessageType::Control(ControlMessageType::Hello),
            MessageChannel::Control,
            "hello",
        ),
        (
            MessageType::Pairing(PairingMessageType::Start),
            MessageChannel::Pairing,
            "pair.start",
        ),
        (
            MessageType::Clipboard(ClipboardMessageType::Offer),
            MessageChannel::Clipboard,
            "clipboard.offer",
        ),
        (
            MessageType::Files(FileMessageType::Offer),
            MessageChannel::Files,
            "file.offer",
        ),
        (
            MessageType::Input(InputMessageType::Move),
            MessageChannel::Input,
            "input.move",
        ),
        (
            MessageType::Media(MediaMessageType::ScreenOffer),
            MessageChannel::Media,
            "screen.offer",
        ),
        (
            MessageType::Phone(PhoneMessageType::PrivilegeState),
            MessageChannel::Phone,
            "phone.privilege.state",
        ),
    ];

    for (index, (message_type, domain, wire)) in cases.into_iter().enumerate() {
        let seq = index as u64 + 1;
        let disposition = router.route(&envelope(message_type, seq)).expect("route");
        assert_eq!(disposition, RouteDisposition::Handled(domain));
        let (_, handler) = handlers
            .iter()
            .find(|(candidate, _)| *candidate == domain)
            .expect("handler present");
        let seen = handler.seen();
        assert_eq!(seen.last().map(|entry| entry.2.as_str()), Some(wire));
    }
}

#[test]
fn ignores_unknown_message_types_without_failing_the_session() {
    let mut router = SessionRouter::new();
    router
        .register(Arc::new(RecordingHandler::new(MessageChannel::Control)))
        .expect("register");

    let disposition = router
        .route(&envelope(
            MessageType::Unknown("vendor.custom".to_owned()),
            1,
        ))
        .expect("unknown message should not fail routing");

    assert_eq!(disposition, RouteDisposition::IgnoredUnknown);
}

#[test]
fn reports_unhandled_domains_without_panicking() {
    let router = SessionRouter::new();
    let disposition = router
        .route(&envelope(MessageType::Control(ControlMessageType::Bye), 1))
        .expect("missing handler should be reported as unhandled");

    assert_eq!(
        disposition,
        RouteDisposition::Unhandled(MessageChannel::Control)
    );
}

#[test]
fn rejects_duplicate_domain_registration() {
    let mut router = SessionRouter::new();
    router
        .register(Arc::new(RecordingHandler::new(MessageChannel::Control)))
        .expect("first register");
    let error = router
        .register(Arc::new(RecordingHandler::new(MessageChannel::Control)))
        .expect_err("duplicate registration should fail");

    let inner = error
        .downcast_inner::<SessionError>()
        .expect("session error");
    assert!(matches!(
        inner,
        SessionError::HandlerAlreadyRegistered {
            domain: MessageChannel::Control
        }
    ));
}
