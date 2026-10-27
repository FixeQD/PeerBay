use peerbay_lib::transport::{
    ChannelKind, InMemoryConfig, InMemoryTransport, InMemoryTransportError, PeerEndpoint,
    Transport, TransportChannel, TransportError, TransportKind,
};

fn endpoint(device_id: &str) -> PeerEndpoint {
    PeerEndpoint::new(
        device_id,
        format!("memory://{device_id}"),
        TransportKind::Loopback,
    )
    .expect("test endpoint should be valid")
}

#[test]
fn in_memory_discovery_is_local_deterministic_and_secret_free() {
    let first = endpoint("peer-a");
    let second = endpoint("peer-b");
    let (transport_a, _transport_b) =
        InMemoryTransport::pair(first.clone(), second.clone()).expect("pair should be created");

    assert_eq!(transport_a.discover().unwrap(), vec![second]);
    let serialized = serde_json::to_string(&transport_a.discover().unwrap()).unwrap();
    assert!(!serialized.contains("token"));
    assert!(!serialized.contains("secret"));
    assert!(!serialized.contains("private_key"));
}

#[test]
fn in_memory_channel_is_bidirectional_and_reports_queued_bytes() {
    let (transport_a, transport_b) =
        InMemoryTransport::pair(endpoint("peer-a"), endpoint("peer-b")).unwrap();
    let channel_a = transport_a
        .open(&endpoint("peer-b"), ChannelKind::Control)
        .expect("channel should open");
    let channel_b = transport_b
        .accept()
        .expect("accept should succeed")
        .expect("peer should have a pending channel");

    transport_a
        .send(&channel_a, b"hello".to_vec())
        .expect("send should succeed");
    assert_eq!(transport_a.metrics(&channel_a).unwrap().queued_bytes, 5);
    let received = transport_b
        .receive(&channel_b)
        .unwrap()
        .expect("hello should be available");
    assert_eq!(received.as_slice(), b"hello");
    assert_eq!(transport_a.metrics(&channel_a).unwrap().queued_bytes, 0);

    transport_b
        .send(&channel_b, b"world".to_vec())
        .expect("reply should succeed");
    let received = transport_a
        .receive(&channel_a)
        .unwrap()
        .expect("world should be available");
    assert_eq!(received.as_slice(), b"world");
    assert!(transport_b.receive(&channel_b).unwrap().is_none());
}

#[test]
fn in_memory_transport_applies_message_and_queue_limits_without_partial_writes() {
    let config = InMemoryConfig::new(5, 8);
    let (transport_a, transport_b) =
        InMemoryTransport::pair_with_config(endpoint("peer-a"), endpoint("peer-b"), config)
            .unwrap();
    let channel_a = transport_a
        .open(&endpoint("peer-b"), ChannelKind::Bulk)
        .unwrap();
    let channel_b = transport_b.accept().unwrap().unwrap();

    let too_large = transport_a.send(&channel_a, b"123456".to_vec());
    assert!(too_large.is_err());
    assert_eq!(transport_a.metrics(&channel_a).unwrap().queued_bytes, 0);

    transport_a.send(&channel_a, b"12345".to_vec()).unwrap();
    let queue_full = transport_a.send(&channel_a, b"6789".to_vec());
    let queue_full_error = queue_full
        .unwrap_err()
        .downcast_inner::<InMemoryTransportError>()
        .expect("queue error should preserve its type");
    assert_eq!(
        queue_full_error,
        InMemoryTransportError::QueueFull { limit: 8 }
    );
    let received = transport_b
        .receive(&channel_b)
        .unwrap()
        .expect("first bounded message should be available");
    assert_eq!(received.as_slice(), b"12345");

    transport_a.send(&channel_a, b"678".to_vec()).unwrap();
    let received = transport_b
        .receive(&channel_b)
        .unwrap()
        .expect("second bounded message should be available");
    assert_eq!(received.as_slice(), b"678");
}

#[test]
fn in_memory_rejects_unknown_peers_self_connections_and_wrong_channels() {
    let (transport_a, _transport_b) =
        InMemoryTransport::pair(endpoint("peer-a"), endpoint("peer-b")).unwrap();
    let unknown = endpoint("peer-z");

    let unknown_error = transport_a
        .open(&unknown, ChannelKind::Control)
        .unwrap_err()
        .downcast_inner::<InMemoryTransportError>()
        .expect("unknown peer error should preserve its type");
    assert_eq!(unknown_error, InMemoryTransportError::PeerNotFound);
    let self_error = transport_a
        .open(&endpoint("peer-a"), ChannelKind::Control)
        .unwrap_err()
        .downcast_inner::<InMemoryTransportError>()
        .expect("self connection error should preserve its type");
    assert_eq!(self_error, InMemoryTransportError::SelfConnection);
    let mismatch_error = transport_a
        .open(
            &PeerEndpoint::new(
                "peer-b",
                "memory://different-address",
                TransportKind::Loopback,
            )
            .unwrap(),
            ChannelKind::Control,
        )
        .unwrap_err()
        .downcast_inner::<InMemoryTransportError>()
        .expect("endpoint mismatch error should preserve its type");
    assert_eq!(mismatch_error, InMemoryTransportError::PeerEndpointMismatch);

    let channel = transport_a
        .open(&endpoint("peer-b"), ChannelKind::Control)
        .unwrap();
    let spoofed_channel = TransportChannel::new(
        channel.id(),
        TransportKind::LocalNetwork,
        ChannelKind::Control,
    )
    .unwrap();
    assert!(
        transport_a
            .send(&spoofed_channel, b"spoof".to_vec())
            .is_err()
    );
    let wrong_kind = InMemoryTransport::new(PeerEndpoint {
        device_id: "peer-c".to_owned(),
        address: "memory://peer-c".to_owned(),
        transport: TransportKind::LocalNetwork,
    });
    assert!(
        wrong_kind
            .err()
            .expect("wrong transport kind should fail")
            .downcast_inner::<InMemoryTransportError>()
            .is_ok()
    );
}

#[test]
fn in_memory_close_is_safe_and_does_not_leave_payloads_or_channels_open() {
    let (transport_a, transport_b) =
        InMemoryTransport::pair(endpoint("peer-a"), endpoint("peer-b")).unwrap();
    let channel_a = transport_a
        .open(&endpoint("peer-b"), ChannelKind::Control)
        .unwrap();
    let channel_b = transport_b.accept().unwrap().unwrap();
    transport_a
        .send(&channel_a, b"private payload".to_vec())
        .unwrap();

    transport_a.close(&channel_a).unwrap();
    transport_a.close(&channel_a).unwrap();
    assert!(!transport_a.is_open(&channel_a).unwrap());
    assert!(!transport_b.is_open(&channel_b).unwrap());
    assert!(transport_b.receive(&channel_b).unwrap().is_none());
    assert!(
        transport_a
            .send(&channel_a, b"after-close".to_vec())
            .is_err()
    );
}

#[test]
fn in_memory_migration_creates_a_new_pending_channel_and_keeps_payload_opaque() {
    let (transport_a, transport_b) =
        InMemoryTransport::pair(endpoint("peer-a"), endpoint("peer-b")).unwrap();
    let old_channel = transport_a
        .open(&endpoint("peer-b"), ChannelKind::Control)
        .unwrap();
    let _old_remote = transport_b.accept().unwrap().unwrap();

    let migrated = transport_a
        .migrate(&old_channel, TransportKind::LocalNetwork)
        .expect("migration should open a replacement channel");
    assert_ne!(migrated.id(), old_channel.id());
    assert_eq!(migrated.transport(), TransportKind::LocalNetwork);
    assert_eq!(migrated.kind(), ChannelKind::Control);

    let migrated_remote = transport_b.accept().unwrap().unwrap();
    let payload = b"$(touch /tmp/peerbay-in-memory-rce-canary); whoami".to_vec();
    transport_a.send(&migrated, payload.clone()).unwrap();
    let received = transport_b
        .receive(&migrated_remote)
        .unwrap()
        .expect("migrated payload should be available");
    assert_eq!(received.as_slice(), payload.as_slice());
}

#[test]
fn in_memory_validation_errors_do_not_execute_rce_like_endpoint_data() {
    let payload = "$(touch /tmp/peerbay-in-memory-endpoint-rce-canary)";
    let result = PeerEndpoint::new(payload, "memory://peer", TransportKind::Loopback);
    let error = result
        .unwrap_err()
        .downcast_inner::<TransportError>()
        .expect("endpoint error should preserve its type");
    assert_eq!(
        error,
        TransportError::InvalidIdentifierCharacter { field: "device_id" }
    );
    assert!(!std::path::Path::new("/tmp/peerbay-in-memory-endpoint-rce-canary").exists());
}
