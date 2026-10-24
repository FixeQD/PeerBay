use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use peerbay_lib::protocol::{
    MessageEnvelope, MessageType, PROTOCOL_VERSION, PhoneMessageType, PrivilegeCancelRequest,
    PrivilegeCapabilities, PrivilegeRequest, PrivilegeStateMessage,
};

const REQUEST_FIXTURE: &str = include_str!("../fixtures/android/phone_privilege_request.json");
const CANCEL_FIXTURE: &str = include_str!("../fixtures/android/phone_privilege_cancel.json");
const NEEDS_ACTION_FIXTURE: &str =
    include_str!("../fixtures/android/phone_privilege_state_needs_user_action.json");
const READY_FIXTURE: &str = include_str!("../fixtures/android/phone_privilege_state_ready.json");
const CAPABILITIES_FIXTURE: &str =
    include_str!("../fixtures/android/phone_privilege_capabilities.json");

fn fixture_value(wire: &str) -> Value {
    serde_json::from_str(wire).expect("Android compatibility fixture should be valid JSON")
}

fn decode_fixture<T>(wire: &str) -> (Value, MessageEnvelope<T>)
where
    T: DeserializeOwned,
{
    let fixture = fixture_value(wire);
    let decoded = serde_json::from_value(fixture.clone())
        .expect("Android compatibility fixture should decode as an envelope");

    (fixture, decoded)
}

fn assert_envelope_metadata(
    fixture: &Value,
    expected_message_type: MessageType,
    expected_sequence: u64,
) {
    assert_eq!(fixture["v"], PROTOCOL_VERSION);
    assert_eq!(fixture["t"], expected_message_type.as_str());
    assert_eq!(fixture["sid"], "session-phone-fixture");
    assert_eq!(fixture["seq"], expected_sequence);
    assert!(fixture["id"].is_string());
    assert!(fixture["ts"].is_u64());
    assert!(fixture["body"].is_object());
}

fn assert_typed_fixture_roundtrips<T>(wire: &str, decoded: &MessageEnvelope<T>)
where
    T: Serialize,
{
    let encoded = serde_json::to_value(decoded).expect("typed envelope should serialize");
    assert_eq!(encoded, fixture_value(wire));
}

#[test]
fn android_fixtures_use_the_versioned_phone_envelope_shape() {
    let fixtures = [
        (
            REQUEST_FIXTURE,
            MessageType::Phone(PhoneMessageType::PrivilegeRequest),
            1,
        ),
        (
            CANCEL_FIXTURE,
            MessageType::Phone(PhoneMessageType::PrivilegeCancel),
            2,
        ),
        (
            NEEDS_ACTION_FIXTURE,
            MessageType::Phone(PhoneMessageType::PrivilegeState),
            3,
        ),
        (
            READY_FIXTURE,
            MessageType::Phone(PhoneMessageType::PrivilegeState),
            4,
        ),
        (
            CAPABILITIES_FIXTURE,
            MessageType::Phone(PhoneMessageType::PrivilegeCapabilities),
            5,
        ),
    ];

    for (wire, message_type, sequence) in fixtures {
        let fixture = fixture_value(wire);
        assert_envelope_metadata(&fixture, message_type, sequence);
        let mut keys = fixture
            .as_object()
            .expect("fixture should be an object")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>();
        keys.sort_unstable();
        assert_eq!(keys, vec!["body", "id", "seq", "sid", "t", "ts", "v"]);
    }
}

#[test]
fn android_privilege_request_fixture_decodes_validates_and_roundtrips() {
    let (fixture, decoded): (Value, MessageEnvelope<PrivilegeRequest>) =
        decode_fixture(REQUEST_FIXTURE);

    decoded
        .body
        .validate()
        .expect("Android request fixture should satisfy Rust validation");
    assert_envelope_metadata(
        &fixture,
        MessageType::Phone(PhoneMessageType::PrivilegeRequest),
        1,
    );
    assert_eq!(decoded.body.request_id, "request-screen-1");
    assert_eq!(decoded.body.capability, "phone.screen.read");
    assert_typed_fixture_roundtrips(REQUEST_FIXTURE, &decoded);
}

#[test]
fn android_privilege_cancel_fixture_decodes_validates_and_roundtrips() {
    let (fixture, decoded): (Value, MessageEnvelope<PrivilegeCancelRequest>) =
        decode_fixture(CANCEL_FIXTURE);

    decoded
        .body
        .validate()
        .expect("Android cancel fixture should satisfy Rust validation");
    assert_envelope_metadata(
        &fixture,
        MessageType::Phone(PhoneMessageType::PrivilegeCancel),
        2,
    );
    assert_eq!(decoded.body.request_id, "request-screen-1");
    assert_typed_fixture_roundtrips(CANCEL_FIXTURE, &decoded);
}

#[test]
fn android_needs_user_action_fixture_preserves_local_escalation_contract() {
    let (fixture, decoded): (Value, MessageEnvelope<PrivilegeStateMessage>) =
        decode_fixture(NEEDS_ACTION_FIXTURE);

    decoded
        .body
        .validate()
        .expect("Android needs-user-action fixture should satisfy Rust validation");
    assert_eq!(decoded.body.capability, "phone.screen.read");
    assert_eq!(decoded.body.reason_code, "open_media_projection_consent");
    assert!(decoded.body.requires_user_action);
    assert_eq!(
        decoded.body.next_action.as_deref(),
        Some("open_media_projection_consent")
    );
    assert!(decoded.body.proof.is_none());
    assert_typed_fixture_roundtrips(NEEDS_ACTION_FIXTURE, &decoded);
    assert_eq!(fixture["body"]["provider"], "media_projection");
    assert_eq!(fixture["body"]["authority"], Value::Null);
}

#[test]
fn android_ready_state_fixture_preserves_safe_probe_metadata() {
    let (fixture, decoded): (Value, MessageEnvelope<PrivilegeStateMessage>) =
        decode_fixture(READY_FIXTURE);

    decoded
        .body
        .validate()
        .expect("Android ready-state fixture should satisfy Rust validation");
    let proof = decoded
        .body
        .proof
        .as_ref()
        .expect("ready fixture should include safe proof metadata");

    assert_eq!(decoded.body.capability, "phone.input.inject");
    assert_eq!(decoded.body.reason_code, "ready");
    assert_eq!(proof.package_name, "com.fixeq.peerbay");
    assert_eq!(proof.uid, Some(10_042));
    assert_eq!(proof.evidence, ["service_connected", "operation_probe_ok"]);
    assert!(!fixture.to_string().contains("private_key"));
    assert!(!fixture.to_string().contains("resume_key"));
    assert_typed_fixture_roundtrips(READY_FIXTURE, &decoded);
}

#[test]
fn android_capabilities_fixture_decodes_all_backends_and_roundtrips() {
    let (fixture, decoded): (Value, MessageEnvelope<PrivilegeCapabilities>) =
        decode_fixture(CAPABILITIES_FIXTURE);

    decoded
        .body
        .validate()
        .expect("Android capability fixture should satisfy Rust validation");
    assert_eq!(decoded.body.backends.len(), 2);
    assert_eq!(decoded.body.backends[0].features[0], "phone.screen.read");
    assert_eq!(
        decoded.body.backends[1].features,
        ["phone.input.accessibility"]
    );
    assert!(decoded.body.backends[1].requires_user_action);
    assert_eq!(
        decoded.body.backends[1].next_action.as_deref(),
        Some("open_accessibility_settings")
    );
    assert!(fixture.to_string().find("root_token").is_none());
    assert!(fixture.to_string().find("private/path").is_none());
    assert_typed_fixture_roundtrips(CAPABILITIES_FIXTURE, &decoded);
}

#[test]
fn android_fixture_message_types_are_preserved_after_typed_decode() {
    let request: MessageEnvelope<PrivilegeRequest> =
        serde_json::from_str(REQUEST_FIXTURE).expect("request fixture should decode");
    let cancel: MessageEnvelope<PrivilegeCancelRequest> =
        serde_json::from_str(CANCEL_FIXTURE).expect("cancel fixture should decode");
    let needs_action: MessageEnvelope<PrivilegeStateMessage> =
        serde_json::from_str(NEEDS_ACTION_FIXTURE).expect("state fixture should decode");
    let capabilities: MessageEnvelope<PrivilegeCapabilities> =
        serde_json::from_str(CAPABILITIES_FIXTURE).expect("capabilities fixture should decode");

    assert_eq!(
        request.message_type,
        MessageType::from_wire("phone.privilege.request".into())
    );
    assert_eq!(
        cancel.message_type,
        MessageType::from_wire("phone.privilege.cancel".into())
    );
    assert_eq!(
        needs_action.message_type,
        MessageType::from_wire("phone.privilege.state".into())
    );
    assert_eq!(
        capabilities.message_type,
        MessageType::from_wire("phone.privilege.capabilities".into())
    );
}
