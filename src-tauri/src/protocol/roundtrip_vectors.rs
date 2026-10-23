use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{
    ClipboardMessageType, ControlMessageType, MessageEnvelope, MessageType, PROTOCOL_VERSION,
    PairingMessageType,
};

struct EnvelopeVector {
    wire: &'static str,
    message_type: MessageType,
    sequence: u64,
}

const VECTORS: &[EnvelopeVector] = &[
    EnvelopeVector {
        wire: r#"{"v":1,"id":"control-1","t":"ping","sid":"session-1","seq":1,"ts":1792700000000,"body":{"nonce":7}}"#,
        message_type: MessageType::Control(ControlMessageType::Ping),
        sequence: 1,
    },
    EnvelopeVector {
        wire: r#"{"v":1,"id":"pair-1","t":"pair.confirm","sid":"session-1","seq":2,"ts":1792700000001,"body":{"sas":"123456","confirmed":true}}"#,
        message_type: MessageType::Pairing(PairingMessageType::Confirm),
        sequence: 2,
    },
    EnvelopeVector {
        wire: r#"{"v":1,"id":"clipboard-1","t":"clipboard.text","sid":"session-1","seq":3,"ts":1792700000002,"body":{"text":"hello","mime":"text/plain"}}"#,
        message_type: MessageType::Clipboard(ClipboardMessageType::Text),
        sequence: 3,
    },
];

#[derive(Debug, Deserialize, PartialEq, Serialize)]
struct PairingConfirmBody {
    sas: String,
    confirmed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resume_key: Option<String>,
}

#[test]
fn envelope_vectors_decode_and_encode_without_wire_changes() {
    for vector in VECTORS {
        let fixture: Value =
            serde_json::from_str(vector.wire).expect("fixture JSON should be valid");
        let decoded: MessageEnvelope<Value> =
            serde_json::from_value(fixture.clone()).expect("envelope fixture should decode");

        assert_eq!(decoded.v, PROTOCOL_VERSION);
        assert_eq!(decoded.message_type, vector.message_type);
        assert_eq!(decoded.seq, vector.sequence);

        let encoded: Value =
            serde_json::to_value(&decoded).expect("decoded envelope should encode");
        assert_eq!(encoded, fixture);
    }
}

#[test]
fn envelope_vector_accepts_optional_body_fields() {
    let fixture: Value = serde_json::from_str(
        r#"{"v":1,"id":"pair-optional","t":"pair.confirm","sid":"session-2","seq":4,"ts":1792700000003,"body":{"sas":"654321","confirmed":true}}"#,
    )
    .expect("fixture JSON should be valid");

    let decoded: MessageEnvelope<PairingConfirmBody> =
        serde_json::from_value(fixture.clone()).expect("optional body field may be omitted");

    assert_eq!(decoded.body.resume_key, None);
    assert_eq!(
        serde_json::to_value(&decoded).expect("typed envelope should encode"),
        fixture
    );
}
