use peerbay_lib::transport::{
    ChannelKind, PeerEndpoint, Transport, TransportChannel, TransportError, TransportKind,
    TransportMetrics,
};
use serde_json::json;

fn transport_error(result: eros::Result<()>) -> TransportError {
    result
        .expect_err("transport validation should fail")
        .downcast_inner::<TransportError>()
        .expect("transport error should be preserved")
}

#[test]
fn every_transport_and_channel_variant_has_a_stable_wire_name() {
    let transports = [
        (TransportKind::LocalNetwork, "local_network"),
        (TransportKind::UsbAdb, "usb_adb"),
        (TransportKind::BluetoothLe, "bluetooth_le"),
        (TransportKind::WifiDirect, "wifi_direct"),
        (TransportKind::PhoneHotspot, "phone_hotspot"),
        (TransportKind::Loopback, "loopback"),
    ];
    let channels = [
        (ChannelKind::Control, "control"),
        (ChannelKind::Bulk, "bulk"),
        (ChannelKind::Media, "media"),
        (ChannelKind::Input, "input"),
        (ChannelKind::Fallback, "fallback"),
    ];

    for (kind, wire_name) in transports {
        assert_eq!(
            serde_json::to_string(&kind).unwrap(),
            format!("\"{wire_name}\"")
        );
    }
    for (kind, wire_name) in channels {
        assert_eq!(
            serde_json::to_string(&kind).unwrap(),
            format!("\"{wire_name}\"")
        );
    }
}

#[test]
fn peer_endpoint_accepts_public_ipv6_routing_data() {
    let endpoint = PeerEndpoint::new("peer-1", "[fe80::1]:4242", TransportKind::LocalNetwork)
        .expect("public endpoint should be valid");

    assert_eq!(endpoint.device_id, "peer-1");
    assert_eq!(endpoint.address, "[fe80::1]:4242");
}

#[test]
fn transport_endpoint_and_channel_reject_control_or_empty_identifiers() {
    assert!(PeerEndpoint::new("", "127.0.0.1:1", TransportKind::Loopback).is_err());
    assert!(PeerEndpoint::new("peer", "127.0.0.1\n:1", TransportKind::Loopback).is_err());
    assert!(TransportChannel::new("", TransportKind::Loopback, ChannelKind::Control).is_err());
    assert!(
        TransportChannel::new("channel\0id", TransportKind::Loopback, ChannelKind::Control)
            .is_err()
    );
}

#[test]
fn transport_validation_rejects_whitespace_paths_and_unicode_identifiers() {
    assert_eq!(
        transport_error(
            PeerEndpoint::new(" peer", "127.0.0.1:1", TransportKind::Loopback).map(|_| ())
        ),
        TransportError::UnexpectedWhitespace { field: "device_id" }
    );
    assert_eq!(
        transport_error(
            PeerEndpoint::new("peer", " 127.0.0.1:1", TransportKind::Loopback).map(|_| ())
        ),
        TransportError::UnexpectedWhitespace { field: "address" }
    );
    assert_eq!(
        transport_error(
            PeerEndpoint::new("../../peer", "127.0.0.1:1", TransportKind::Loopback).map(|_| ())
        ),
        TransportError::InvalidIdentifierCharacter { field: "device_id" }
    );
    assert_eq!(
        transport_error(
            TransportChannel::new(
                "channel/../id",
                TransportKind::Loopback,
                ChannelKind::Control
            )
            .map(|_| ())
        ),
        TransportError::InvalidIdentifierCharacter {
            field: "channel_id"
        }
    );
    assert!(PeerEndpoint::new("peer", "fe80::1%wlan0:4242", TransportKind::LocalNetwork).is_ok());
    assert!(PeerEndpoint::new("pęer", "127.0.0.1:1", TransportKind::Loopback).is_err());
}

#[test]
fn transport_fields_enforce_the_4k_boundary_without_panicking() {
    let accepted_id = "a".repeat(4 * 1024);
    let rejected_id = "a".repeat(4 * 1024 + 1);
    assert!(PeerEndpoint::new(&accepted_id, "127.0.0.1:1", TransportKind::Loopback).is_ok());
    assert!(PeerEndpoint::new(&rejected_id, "127.0.0.1:1", TransportKind::Loopback).is_err());
    assert!(
        TransportChannel::new(&accepted_id, TransportKind::Loopback, ChannelKind::Control).is_ok()
    );
    assert!(
        TransportChannel::new(&rejected_id, TransportKind::Loopback, ChannelKind::Control).is_err()
    );
}

#[test]
fn endpoint_json_roundtrip_ignores_future_non_secret_fields() {
    let endpoint = PeerEndpoint::new("peer-1", "127.0.0.1:4242", TransportKind::Loopback)
        .expect("endpoint should be valid");
    let mut value = serde_json::to_value(&endpoint).expect("endpoint should serialize");
    value["future_transport_field"] = json!({"not_a_token": true});

    let decoded: PeerEndpoint = serde_json::from_value(value).expect("future field is optional");
    assert_eq!(decoded, endpoint);
}

#[test]
fn shell_like_address_is_data_and_does_not_execute() {
    let directory = tempfile::tempdir().expect("temporary directory should exist");
    let canary = directory.path().join("transport-rce-canary");
    let address = format!("$(touch {})", canary.display());

    let endpoint = PeerEndpoint::new("peer-1", &address, TransportKind::Loopback)
        .expect("routing data should not be interpreted as a command");
    let encoded = serde_json::to_string(&endpoint).expect("endpoint should serialize");
    let decoded: PeerEndpoint = serde_json::from_str(&encoded).expect("endpoint should decode");

    assert_eq!(decoded.address, address);
    assert!(
        !canary.exists(),
        "transport endpoint construction executed RCE payload"
    );
}

struct PortProbe;

impl Transport for PortProbe {
    fn kind(&self) -> TransportKind {
        TransportKind::Loopback
    }

    fn discover(&self) -> eros::Result<Vec<PeerEndpoint>> {
        Ok(Vec::new())
    }

    fn open(&self, _peer: &PeerEndpoint, channel: ChannelKind) -> eros::Result<TransportChannel> {
        TransportChannel::new("loopback-channel", self.kind(), channel)
    }

    fn close(&self, _channel: &TransportChannel) -> eros::Result<()> {
        Ok(())
    }

    fn metrics(&self, _channel: &TransportChannel) -> eros::Result<TransportMetrics> {
        Ok(TransportMetrics::new(Some(1), Some(1024), 0, false))
    }

    fn supports(&self, channel: ChannelKind) -> bool {
        matches!(channel, ChannelKind::Control | ChannelKind::Fallback)
    }

    fn migrate(
        &self,
        channel: &TransportChannel,
        target: TransportKind,
    ) -> eros::Result<TransportChannel> {
        TransportChannel::new("loopback-migrated-channel", target, channel.kind())
    }
}

#[test]
fn transport_port_is_object_safe_and_covers_the_manager_operations() {
    let transport: Box<dyn Transport> = Box::new(PortProbe);
    let peer = PeerEndpoint::new("peer-1", "127.0.0.1:4242", TransportKind::Loopback)
        .expect("peer endpoint should be valid");

    assert_eq!(transport.kind(), TransportKind::Loopback);
    assert!(transport.can_connect(&peer));
    assert!(!transport.can_connect(&PeerEndpoint {
        device_id: "$(touch /tmp/peerbay-transport-can-connect)".to_owned(),
        address: "127.0.0.1:4242".to_owned(),
        transport: TransportKind::Loopback,
    }));
    assert!(transport.discover().unwrap().is_empty());
    assert!(transport.supports(ChannelKind::Control));
    assert!(!transport.supports(ChannelKind::Media));

    let channel = transport
        .open(&peer, ChannelKind::Control)
        .expect("port probe should open a channel");
    assert_eq!(channel.kind(), ChannelKind::Control);
    assert_eq!(channel.transport(), TransportKind::Loopback);
    assert_eq!(channel.id(), "loopback-channel");

    let metrics = transport
        .metrics(&channel)
        .expect("metrics should be available");
    assert_eq!(metrics.rtt_ms, Some(1));
    assert_eq!(metrics.queued_bytes, 0);

    let migrated = transport
        .migrate(&channel, TransportKind::LocalNetwork)
        .expect("migration should return a replacement channel");
    assert_eq!(migrated.transport(), TransportKind::LocalNetwork);
    transport.close(&channel).expect("old channel should close");
}
