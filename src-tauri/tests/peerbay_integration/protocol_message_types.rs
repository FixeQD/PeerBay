use peerbay_lib::protocol::{
    ClipboardMessageType, ControlMessageType, FileMessageType, InputMessageType, MediaMessageType,
    MessageChannel, MessageType, PairingMessageType,
};

#[test]
fn known_identifiers_keep_their_channel_and_wire_name() {
    let identifiers = [
        (
            MessageType::Control(ControlMessageType::Hello),
            MessageChannel::Control,
            "hello",
        ),
        (
            MessageType::Pairing(PairingMessageType::Confirm),
            MessageChannel::Pairing,
            "pair.confirm",
        ),
        (
            MessageType::Clipboard(ClipboardMessageType::Offer),
            MessageChannel::Clipboard,
            "clipboard.offer",
        ),
        (
            MessageType::Files(FileMessageType::Chunk),
            MessageChannel::Files,
            "file.chunk",
        ),
        (
            MessageType::Input(InputMessageType::KeyDown),
            MessageChannel::Input,
            "input.key_down",
        ),
        (
            MessageType::Media(MediaMessageType::ScreenState),
            MessageChannel::Media,
            "screen.state",
        ),
    ];

    for (identifier, channel, wire_name) in identifiers {
        assert_eq!(identifier.channel(), channel);
        assert_eq!(identifier.as_str(), wire_name);
        assert_eq!(
            serde_json::to_string(&identifier).expect("identifier should serialize"),
            format!("\"{wire_name}\"")
        );
    }
}

#[test]
fn identifiers_parse_known_and_preserve_unknown_wire_names() {
    let known: MessageType =
        serde_json::from_str("\"session.resume\"").expect("known identifier should parse");
    assert_eq!(
        known,
        MessageType::Control(ControlMessageType::SessionResume)
    );

    let unknown: MessageType =
        serde_json::from_str("\"future.message\"").expect("unknown identifier should parse");
    assert_eq!(unknown, MessageType::Unknown("future.message".to_owned()));
    assert_eq!(unknown.channel(), MessageChannel::Unknown);
    assert_eq!(unknown.as_str(), "future.message");
}

#[test]
fn empty_identifier_is_rejected_during_deserialization() {
    let result = serde_json::from_str::<MessageType>("\"\"");

    assert!(result.is_err());
}
