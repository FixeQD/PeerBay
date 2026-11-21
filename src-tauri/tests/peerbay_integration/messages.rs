use peerbay_lib::messages::AppChannel;
use peerbay_lib::messages::{
    AppMessageType, ClipboardMessageType, FileMessageType, InputMessageType, MediaMessageType,
    PairingMessageType, PhoneMessageType,
};
use proto::MessageType;

#[test]
fn feature_message_identifiers_keep_their_channel_and_wire_name() {
    let cases: Vec<(MessageType, AppChannel, &str)> = vec![
        (
            PairingMessageType::Start.into(),
            AppChannel::Pairing,
            "pair.start",
        ),
        (
            ClipboardMessageType::Text.into(),
            AppChannel::Clipboard,
            "clipboard.text",
        ),
        (
            FileMessageType::Chunk.into(),
            AppChannel::Files,
            "file.chunk",
        ),
        (
            InputMessageType::KeyDown.into(),
            AppChannel::Input,
            "input.key_down",
        ),
        (
            MediaMessageType::ScreenState.into(),
            AppChannel::Media,
            "screen.state",
        ),
        (
            PhoneMessageType::PrivilegeState.into(),
            AppChannel::Phone,
            "phone.privilege.state",
        ),
    ];

    for (message, channel, wire_name) in cases {
        assert_eq!(message.as_str(), wire_name);
        assert_eq!(
            AppMessageType::from_wire(wire_name)
                .map(AppMessageType::channel)
                .expect("application should classify its own identifier"),
            channel
        );
        assert_eq!(
            serde_json::to_string(&message).expect("identifier should serialize"),
            format!("\"{wire_name}\"")
        );
        let raw: MessageType =
            serde_json::from_str(&format!("\"{wire_name}\"")).expect("wire name should parse");
        assert_eq!(raw, MessageType::Unknown(wire_name.to_owned()));
        assert_eq!(
            AppMessageType::from_wire(wire_name)
                .map(MessageType::from)
                .expect("application should classify its own identifier"),
            message
        );
    }
}

#[test]
fn every_feature_identifier_roundtrips_through_from_wire() {
    let identifiers = [
        (PairingMessageType::Start.into(), "pair.start"),
        (PairingMessageType::Confirm.into(), "pair.confirm"),
        (PairingMessageType::Cancelled.into(), "pair.cancelled"),
        (ClipboardMessageType::Offer.into(), "clipboard.offer"),
        (ClipboardMessageType::Ack.into(), "clipboard.ack"),
        (FileMessageType::Offer.into(), "file.offer"),
        (FileMessageType::Done.into(), "file.done"),
        (InputMessageType::Layout.into(), "input.layout"),
        (InputMessageType::Gesture.into(), "input.gesture"),
        (MediaMessageType::ScreenOffer.into(), "screen.offer"),
        (MediaMessageType::AudioState.into(), "audio.state"),
        (
            PhoneMessageType::PrivilegeRequest.into(),
            "phone.privilege.request",
        ),
        (
            PhoneMessageType::PrivilegeCapabilities.into(),
            "phone.privilege.capabilities",
        ),
    ];

    for (message, wire_name) in identifiers {
        let classified = AppMessageType::from_wire(wire_name)
            .map(MessageType::from)
            .expect("identifier should be classified by the application");
        assert_eq!(classified, message);
        assert_eq!(
            serde_json::to_string(&classified).expect("identifier should serialize"),
            format!("\"{wire_name}\"")
        );
    }
}

#[test]
fn domain_identifiers_keep_the_channel_supplied_by_the_application() {
    let identifiers = [
        (
            AppMessageType::Pairing(PairingMessageType::Confirm),
            AppChannel::Pairing,
            "pair.confirm",
        ),
        (
            AppMessageType::Clipboard(ClipboardMessageType::Offer),
            AppChannel::Clipboard,
            "clipboard.offer",
        ),
        (
            AppMessageType::Files(FileMessageType::Chunk),
            AppChannel::Files,
            "file.chunk",
        ),
        (
            AppMessageType::Input(InputMessageType::KeyDown),
            AppChannel::Input,
            "input.key_down",
        ),
        (
            AppMessageType::Media(MediaMessageType::ScreenState),
            AppChannel::Media,
            "screen.state",
        ),
        (
            AppMessageType::Phone(PhoneMessageType::PrivilegeCapabilities),
            AppChannel::Phone,
            "phone.privilege.capabilities",
        ),
    ];

    for (app_type, channel, wire_name) in identifiers {
        let message = MessageType::from(app_type);
        assert_eq!(
            AppMessageType::from_wire(wire_name)
                .map(AppMessageType::channel)
                .expect("application should classify its own identifier"),
            channel
        );
        assert_eq!(message.as_str(), wire_name);
        assert_eq!(
            serde_json::to_string(&message).expect("identifier should serialize"),
            format!("\"{wire_name}\"")
        );
    }
}

#[test]
fn application_identifiers_are_unclassified_until_the_application_binds_them() {
    let raw: MessageType =
        serde_json::from_str("\"pair.confirm\"").expect("identifier should parse");
    assert_eq!(raw, MessageType::Unknown("pair.confirm".to_owned()));
    assert!(matches!(raw, MessageType::Unknown(_)));

    let bound = AppMessageType::from_wire(raw.as_str())
        .map(MessageType::from)
        .expect("application should classify its own identifier");
    assert_eq!(
        AppMessageType::from_wire(bound.as_str()).map(AppMessageType::channel),
        Some(AppChannel::Pairing)
    );
    assert_eq!(bound.as_str(), "pair.confirm");
}

#[test]
fn phone_privilege_identifiers_roundtrip_through_application_classification() {
    let identifiers = [
        (PhoneMessageType::PrivilegeState, "phone.privilege.state"),
        (
            PhoneMessageType::PrivilegeRequest,
            "phone.privilege.request",
        ),
        (PhoneMessageType::PrivilegeCancel, "phone.privilege.cancel"),
        (
            PhoneMessageType::PrivilegeCapabilities,
            "phone.privilege.capabilities",
        ),
    ];

    for (identifier, wire_name) in identifiers {
        let message = MessageType::from(identifier);
        assert_eq!(message.as_str(), wire_name);
        assert_eq!(
            AppMessageType::from_wire(wire_name).map(AppMessageType::channel),
            Some(AppChannel::Phone)
        );
        assert_eq!(
            serde_json::to_string(&message).expect("identifier should serialize"),
            format!("\"{wire_name}\"")
        );

        let raw: MessageType = serde_json::from_str(&format!("\"{wire_name}\""))
            .expect("phone privilege identifier should deserialize");
        assert_eq!(raw, MessageType::Unknown(wire_name.to_owned()));
        assert_eq!(
            AppMessageType::from_wire(raw.as_str())
                .map(MessageType::from)
                .expect("application should classify its own identifier"),
            message
        );
    }
}
