use serde_json::json;

use peerbay_lib::protocol::{
    CapabilityDocument, CapabilityError, NegotiatedCapabilities, ProtocolLimitError, ProtocolLimits,
};

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn valid_document() -> CapabilityDocument {
    CapabilityDocument::new(
        "linux",
        "6.12",
        vec![1, 2],
        strings(&["local_network", "loopback"]),
        strings(&["clipboard.text", "files.send", "files.receive"]),
        strings(&["h264", "opus"]),
        8 * 1024 * 1024 * 1024,
        512 * 1024,
        strings(&["mouse", "keyboard"]),
        strings(&["screen.share"]),
        strings(&["audio.pcm"]),
        strings(&["clipboard.read", "clipboard.write"]),
    )
    .expect("fixture capability document should be valid")
}

fn capability_error(result: eros::Result<()>) -> CapabilityError {
    result
        .expect_err("capability validation should fail")
        .downcast_inner::<CapabilityError>()
        .expect("capability error should be preserved")
}

#[test]
fn capability_document_serializes_the_complete_wire_shape() {
    let value = serde_json::to_value(valid_document()).expect("capability document should encode");

    assert_eq!(value["platform"], "linux");
    assert_eq!(value["platform_version"], "6.12");
    assert_eq!(value["protocol_versions"], json!([1, 2]));
    assert_eq!(value["transports"], json!(["local_network", "loopback"]));
    assert_eq!(
        value["features"],
        json!(["clipboard.text", "files.send", "files.receive"])
    );
    assert_eq!(value["codecs"], json!(["h264", "opus"]));
    assert_eq!(value["max_file_size"], 8_u64 * 1024 * 1024 * 1024);
    assert_eq!(value["max_message_size"], 512_u64 * 1024);
    assert_eq!(value["input_modes"], json!(["mouse", "keyboard"]));
    assert_eq!(value["screen_modes"], json!(["screen.share"]));
    assert_eq!(value["audio_modes"], json!(["audio.pcm"]));
    assert_eq!(
        value["permissions"],
        json!(["clipboard.read", "clipboard.write"])
    );
}

#[test]
fn capability_document_roundtrips_without_losing_unknown_future_fields() {
    let mut value = serde_json::to_value(valid_document()).expect("document should encode");
    value["future_capability_field"] = json!({ "enabled": true });

    let decoded: CapabilityDocument =
        serde_json::from_value(value).expect("unknown optional fields should be ignored");

    assert_eq!(decoded, valid_document());
}

#[test]
fn constructor_rejects_an_empty_protocol_version_list() {
    let error = CapabilityDocument::new(
        "linux",
        "6.12",
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        1,
        1,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .expect_err("a peer must advertise at least one protocol version")
    .downcast_inner::<CapabilityError>()
    .expect("capability error should be preserved");

    assert_eq!(
        error,
        CapabilityError::EmptyList {
            field: "protocol_versions"
        }
    );
}

#[test]
fn zero_protocol_version_is_rejected() {
    let mut document = valid_document();
    document.protocol_versions = vec![0, 1];

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::InvalidProtocolVersion { version: 0 }
    );
}

#[test]
fn duplicate_protocol_versions_are_rejected_instead_of_silently_deduplicated() {
    let mut document = valid_document();
    document.protocol_versions = vec![1, 2, 1];

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::DuplicateProtocolVersion { version: 1 }
    );
}

#[test]
fn duplicate_transport_identifiers_are_rejected() {
    let mut document = valid_document();
    document.transports = strings(&["local_network", "local_network"]);

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::DuplicateValue {
            field: "transports",
            value: "local_network".to_owned(),
        }
    );
}

#[test]
fn duplicate_feature_identifiers_are_rejected() {
    let mut document = valid_document();
    document.features = strings(&["clipboard.text", "clipboard.text"]);

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::DuplicateValue {
            field: "features",
            value: "clipboard.text".to_owned(),
        }
    );
}

#[test]
fn duplicate_codec_identifiers_are_rejected() {
    let mut document = valid_document();
    document.codecs = strings(&["h264", "h264"]);

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::DuplicateValue {
            field: "codecs",
            value: "h264".to_owned(),
        }
    );
}

#[test]
fn duplicate_mode_identifiers_are_rejected() {
    let mut document = valid_document();
    document.input_modes = strings(&["mouse", "mouse"]);

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::DuplicateValue {
            field: "input_modes",
            value: "mouse".to_owned(),
        }
    );
}

#[test]
fn duplicate_permission_identifiers_are_rejected() {
    let mut document = valid_document();
    document.permissions = strings(&["clipboard.read", "clipboard.read"]);

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::DuplicateValue {
            field: "permissions",
            value: "clipboard.read".to_owned(),
        }
    );
}

#[test]
fn empty_platform_is_rejected_by_the_shared_protocol_string_limit() {
    let mut document = valid_document();
    document.platform.clear();

    let error = document
        .validate()
        .expect_err("platform is required")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared protocol limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier { field: "platform" }
    );
}

#[test]
fn whitespace_only_platform_version_is_rejected() {
    let mut document = valid_document();
    document.platform_version = "\t  ".to_owned();

    let error = document
        .validate()
        .expect_err("platform version is required")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared protocol limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier {
            field: "platform_version"
        }
    );
}

#[test]
fn surrounding_whitespace_in_a_capability_identifier_is_rejected() {
    let mut document = valid_document();
    document.features = strings(&[" clipboard.text"]);

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::UnexpectedWhitespace {
            field: "features",
            index: Some(0),
        }
    );
}

#[test]
fn control_characters_in_platform_metadata_are_rejected() {
    let mut document = valid_document();
    document.platform_version = "Android\n14".to_owned();

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::ControlCharacter {
            field: "platform_version",
            index: None,
        }
    );
}

#[test]
fn control_characters_in_identifiers_are_rejected() {
    let mut document = valid_document();
    document.codecs = strings(&["h264\u{0000}"]);

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::ControlCharacter {
            field: "codecs",
            index: Some(0),
        }
    );
}

#[test]
fn every_capability_list_obeys_the_shared_batch_limit() {
    let mut document = valid_document();
    document.features = (0..=ProtocolLimits::default().max_batch_items())
        .map(|index| format!("feature.{index}"))
        .collect();

    let error = document
        .validate()
        .expect_err("a capability list over the batch limit must be rejected")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared batch limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::BatchTooLarge {
            field: "features",
            count: ProtocolLimits::default().max_batch_items() + 1,
            max: ProtocolLimits::default().max_batch_items(),
        }
    );
}

#[test]
fn a_custom_protocol_limit_applies_to_platform_metadata_and_entries() {
    let mut document = valid_document();
    document.platform = "linux-desktop".to_owned();
    document.transports = strings(&["local_network"]);
    let limits = ProtocolLimits::new(1024, 1024, 5, 32, 1024);

    let error = document
        .validate_with_limits(limits)
        .expect_err("custom string limit must apply to the whole document")
        .downcast_inner::<ProtocolLimitError>()
        .expect("shared string limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::StringTooLong {
            field: "platform",
            length: 13,
            max: 5,
        }
    );
}

#[test]
fn zero_file_limit_is_rejected() {
    let mut document = valid_document();
    document.max_file_size = 0;

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::ZeroLimit {
            field: "max_file_size"
        }
    );
}

#[test]
fn zero_message_limit_is_rejected() {
    let mut document = valid_document();
    document.max_message_size = 0;

    assert_eq!(
        capability_error(document.validate()),
        CapabilityError::ZeroLimit {
            field: "max_message_size"
        }
    );
}

#[test]
fn future_nonzero_protocol_versions_are_preserved() {
    let mut document = valid_document();
    document.protocol_versions = vec![1, 99];

    document
        .validate()
        .expect("unknown future protocol versions are valid advertisements");
    assert!(document.supports_protocol_version(99));
}

#[test]
fn support_queries_are_exact_and_do_not_treat_prefixes_as_matches() {
    let document = valid_document();

    assert!(document.supports_transport("local_network"));
    assert!(document.supports_feature("clipboard.text"));
    assert!(document.supports_codec("h264"));
    assert!(!document.supports_transport("local"));
    assert!(!document.supports_feature("clipboard"));
    assert!(!document.supports_codec("h264/av1"));
}

#[test]
fn negotiation_selects_the_highest_common_protocol_version() {
    let mut local = valid_document();
    local.protocol_versions = vec![1, 3, 2];
    let mut peer = valid_document();
    peer.protocol_versions = vec![2, 4, 3];

    let negotiated = local
        .negotiate(&peer)
        .expect("a common protocol version should exist");

    assert_eq!(negotiated.protocol_version, 3);
}

#[test]
fn negotiation_intersects_capabilities_in_local_order() {
    let mut local = valid_document();
    local.transports = strings(&["loopback", "local_network", "usb_adb"]);
    local.features = strings(&["files.send", "clipboard.text", "computer.screen.share"]);
    local.codecs = strings(&["opus", "h264", "av1"]);
    local.input_modes = strings(&["keyboard", "touch"]);
    local.screen_modes = strings(&["screen.share", "screen.receive"]);
    local.audio_modes = strings(&["audio.pcm", "audio.opus"]);
    local.permissions = strings(&["clipboard.read", "media_projection"]);

    let mut peer = valid_document();
    peer.transports = strings(&["local_network", "usb_adb"]);
    peer.features = strings(&["clipboard.text", "files.send"]);
    peer.codecs = strings(&["h264", "opus"]);
    peer.input_modes = strings(&["keyboard"]);
    peer.screen_modes = strings(&["screen.receive"]);
    peer.audio_modes = strings(&["audio.opus"]);
    peer.permissions = strings(&["media_projection"]);

    let negotiated = local.negotiate(&peer).expect("documents should negotiate");

    assert_eq!(
        negotiated.transports,
        strings(&["local_network", "usb_adb"])
    );
    assert_eq!(
        negotiated.features,
        strings(&["files.send", "clipboard.text"])
    );
    assert_eq!(negotiated.codecs, strings(&["opus", "h264"]));
    assert_eq!(negotiated.input_modes, strings(&["keyboard"]));
    assert_eq!(negotiated.screen_modes, strings(&["screen.receive"]));
    assert_eq!(negotiated.audio_modes, strings(&["audio.opus"]));
    assert_eq!(negotiated.permissions, strings(&["media_projection"]));
}

#[test]
fn negotiation_uses_the_smallest_peer_limits() {
    let mut local = valid_document();
    local.max_file_size = 1000;
    local.max_message_size = 500;
    let mut peer = valid_document();
    peer.max_file_size = 2000;
    peer.max_message_size = 100;

    let negotiated = local.negotiate(&peer).expect("documents should negotiate");

    assert_eq!(negotiated.max_file_size, 1000);
    assert_eq!(negotiated.max_message_size, 100);
}

#[test]
fn negotiation_allows_empty_optional_intersections() {
    let mut local = valid_document();
    local.features.clear();
    local.codecs.clear();
    local.transports.clear();
    let mut peer = valid_document();
    peer.features = strings(&["phone.screen.read"]);
    peer.codecs = strings(&["av1"]);
    peer.transports = strings(&["bluetooth_le"]);

    let negotiated = local
        .negotiate(&peer)
        .expect("optional feature intersections may be empty");

    assert!(negotiated.features.is_empty());
    assert!(negotiated.codecs.is_empty());
    assert!(negotiated.transports.is_empty());
}

#[test]
fn negotiation_rejects_documents_without_a_common_protocol_version() {
    let mut local = valid_document();
    local.protocol_versions = vec![1];
    let mut peer = valid_document();
    peer.protocol_versions = vec![2];

    let error = local
        .negotiate(&peer)
        .expect_err("different protocol versions cannot negotiate")
        .downcast_inner::<CapabilityError>()
        .expect("capability error should be preserved");

    assert_eq!(error, CapabilityError::NoCommonProtocolVersion);
}

#[test]
fn negotiation_validates_the_local_document_before_intersecting_it() {
    let mut local = valid_document();
    local.features = strings(&["clipboard.text", "clipboard.text"]);

    let error = local
        .negotiate(&valid_document())
        .expect_err("invalid local capability data must not be negotiated")
        .downcast_inner::<CapabilityError>()
        .expect("capability error should be preserved");

    assert_eq!(
        error,
        CapabilityError::DuplicateValue {
            field: "features",
            value: "clipboard.text".to_owned(),
        }
    );
}

#[test]
fn negotiation_validates_the_peer_document_before_intersecting_it() {
    let mut peer = valid_document();
    peer.max_message_size = 0;

    let error = valid_document()
        .negotiate(&peer)
        .expect_err("invalid peer capability data must not be negotiated")
        .downcast_inner::<CapabilityError>()
        .expect("capability error should be preserved");

    assert_eq!(
        error,
        CapabilityError::ZeroLimit {
            field: "max_message_size"
        }
    );
}

#[test]
fn negotiated_capabilities_only_report_technical_intersection() {
    let local = valid_document();
    let peer = valid_document();
    let negotiated = local.negotiate(&peer).expect("documents should negotiate");

    let serialized = serde_json::to_value(&negotiated).expect("negotiated data should encode");

    assert!(serialized.get("user_policy").is_none());
    assert!(serialized.get("session_policy").is_none());
    assert!(serialized.get("trust_token").is_none());
    assert!(serialized.get("certificate").is_none());
}

#[test]
fn negotiated_capability_helpers_report_intersection_membership() {
    let negotiated = NegotiatedCapabilities {
        protocol_version: 1,
        transports: strings(&["local_network"]),
        features: strings(&["clipboard.text"]),
        codecs: strings(&["opus"]),
        max_file_size: 10,
        max_message_size: 20,
        input_modes: Vec::new(),
        screen_modes: Vec::new(),
        audio_modes: Vec::new(),
        permissions: Vec::new(),
    };

    assert!(negotiated.supports_transport("local_network"));
    assert!(negotiated.supports_feature("clipboard.text"));
    assert!(negotiated.supports_codec("opus"));
    assert!(!negotiated.supports_transport("bluetooth_le"));
    assert!(!negotiated.supports_feature("files.send"));
    assert!(!negotiated.supports_codec("h264"));
}
