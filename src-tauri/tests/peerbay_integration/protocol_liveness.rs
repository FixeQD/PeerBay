use serde_json::json;

use peerbay_lib::protocol::{LivenessError, PingBody, PongBody};

#[test]
fn ping_body_serializes_as_empty_object() {
    let body = PingBody::new();
    assert_eq!(serde_json::to_value(&body).expect("serialize"), json!({}));
    body.validate().expect("ping body should validate");
}

#[test]
fn pong_body_roundtrips_and_validates_ping_id() {
    let body = PongBody::new("msg-123", Some(42)).expect("pong body");
    let value = serde_json::to_value(&body).expect("serialize");
    assert_eq!(value, json!({ "ping_id": "msg-123", "ping_seq": 42 }));

    let decoded: PongBody = serde_json::from_value(value).expect("deserialize");
    assert_eq!(decoded, body);
}

#[test]
fn pong_body_rejects_invalid_ping_id() {
    let error = PongBody::new(" bad ", None).expect_err("whitespace should be rejected");
    let inner = error.downcast_inner::<LivenessError>().expect("liveness error");
    assert_eq!(
        inner,
        LivenessError::UnexpectedWhitespace { field: "ping_id" }
    );
}
