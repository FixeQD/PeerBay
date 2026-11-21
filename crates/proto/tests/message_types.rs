use proto::{ControlMessageType, MessageType};

#[test]
fn control_identifiers_keep_their_wire_name() {
    let identifiers = [
        (MessageType::Control(ControlMessageType::Hello), "hello"),
        (MessageType::Control(ControlMessageType::Ping), "ping"),
        (
            MessageType::Control(ControlMessageType::SessionResume),
            "session.resume",
        ),
        (
            MessageType::Control(ControlMessageType::PolicySet),
            "policy.set",
        ),
    ];

    for (identifier, wire_name) in identifiers {
        assert_eq!(identifier.as_str(), wire_name);
        assert_eq!(
            serde_json::to_string(&identifier).expect("identifier should serialize"),
            format!("\"{wire_name}\"")
        );
    }
}

#[test]
fn identifiers_parse_known_control_names_and_preserve_everything_else() {
    let known: MessageType =
        serde_json::from_str("\"session.resume\"").expect("known identifier should parse");
    assert_eq!(
        known,
        MessageType::Control(ControlMessageType::SessionResume)
    );

    for wire_name in ["pair.confirm", "phone.privilege.state", "future.message"] {
        let opaque: MessageType =
            serde_json::from_str(&format!("\"{wire_name}\"")).expect("identifier should parse");
        assert_eq!(opaque, MessageType::Unknown(wire_name.to_owned()));
        assert_eq!(opaque.as_str(), wire_name);
    }
}

#[test]
fn empty_identifier_is_rejected_during_deserialization() {
    let result = serde_json::from_str::<MessageType>("\"\"");

    assert!(result.is_err());
}
