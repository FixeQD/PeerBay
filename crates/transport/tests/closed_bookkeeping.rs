use identity::TransportCertificate;
use std::thread;
use std::time::Duration;
use transport::{
    ChannelKind, InMemoryTransport, InMemoryTransportError, PeerEndpoint, TcpTransport,
    TlsTransport, Transport, TransportChannel, TransportKind,
};

const CHURN: usize = 4100;

fn endpoint(id: &str, port: u16) -> PeerEndpoint {
    PeerEndpoint::new(id, format!("127.0.0.1:{}", port), TransportKind::Loopback).unwrap()
}

fn in_memory_endpoint(id: &str) -> PeerEndpoint {
    PeerEndpoint::new(id, "127.0.0.1:9", TransportKind::Loopback).unwrap()
}

fn channel_with_id(id: &str) -> TransportChannel {
    TransportChannel::new(id, TransportKind::Loopback, ChannelKind::Control).unwrap()
}

fn in_memory_pair() -> (InMemoryTransport, InMemoryTransport) {
    InMemoryTransport::pair(
        in_memory_endpoint("00000000-0000-0000-0000-000000000001"),
        in_memory_endpoint("00000000-0000-0000-0000-000000000002"),
    )
    .unwrap()
}

fn wait_for_accept(transport: &TcpTransport) -> TransportChannel {
    for _ in 0..100 {
        if let Some(channel) = transport.accept().unwrap() {
            return channel;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("peer did not accept a channel");
}

fn churn_fake_closes(transport: &TcpTransport) {
    for i in 0..CHURN {
        transport
            .close(&channel_with_id(&format!("tcp-{}", i)))
            .unwrap();
    }
}

#[test]
fn tcp_closed_bookkeeping_is_bounded() {
    let churner = TcpTransport::new(endpoint("peer-tcp-bookkeeping-a", 19254)).unwrap();
    churn_fake_closes(&churner);

    let oldest = channel_with_id("tcp-0");
    let newest = channel_with_id(&format!("tcp-{}", CHURN - 1));
    assert!(
        !churner.metrics(&oldest).unwrap().degraded,
        "oldest closed id must be evicted from the bounded bookkeeping"
    );
    assert!(
        churner.metrics(&newest).unwrap().degraded,
        "most recently closed id must still report closed"
    );

    let (sender, receiver) = TcpTransport::pair(
        endpoint("peer-tcp-bookkeeping-a", 19251),
        endpoint("peer-tcp-bookkeeping-b", 19252),
    )
    .unwrap();
    let channel = sender
        .open(
            &endpoint("peer-tcp-bookkeeping-b", 19252),
            ChannelKind::Control,
        )
        .unwrap();
    let _remote = wait_for_accept(&receiver);
    sender.close(&channel).unwrap();
    sender.close(&channel).unwrap();
    assert!(
        sender.metrics(&channel).unwrap().degraded,
        "a freshly closed channel reports closed"
    );
    assert!(!sender.is_open(&channel).unwrap());
    assert!(sender.send(&channel, b"after close".to_vec()).is_err());
}

#[test]
fn tls_closed_bookkeeping_is_bounded() {
    let id_a = "00000000-0000-0000-0000-0000000000a1";
    let id_b = "00000000-0000-0000-0000-0000000000a2";
    let cert_a = TransportCertificate::generate_for_device(id_a).unwrap();
    let cert_b = TransportCertificate::generate_for_device(id_b).unwrap();

    let client = TlsTransport::with_certificate(
        endpoint(id_a, 19261),
        cert_a,
        Some(cert_b.certificate_der().to_vec()),
    )
    .unwrap();
    let _server = TlsTransport::with_certificate(endpoint(id_b, 19262), cert_b, None).unwrap();

    for i in 0..CHURN {
        client
            .close(&channel_with_id(&format!("tls-{}", i)))
            .unwrap();
    }

    let oldest = channel_with_id("tls-0");
    let newest = channel_with_id(&format!("tls-{}", CHURN - 1));
    assert!(
        !client.metrics(&oldest).unwrap().degraded,
        "oldest closed id must be evicted from the bounded bookkeeping"
    );
    assert!(
        client.metrics(&newest).unwrap().degraded,
        "most recently closed id must still report closed"
    );
    client.close(&oldest).unwrap();
    assert!(
        client.metrics(&oldest).unwrap().degraded,
        "closing an evicted id works again and reports closed"
    );
}

#[test]
fn in_memory_purges_oldest_closed_links_over_cap() {
    let (a, _b) = in_memory_pair();
    let peer = in_memory_endpoint("00000000-0000-0000-0000-000000000002");
    let mut channels = Vec::new();
    for _ in 0..CHURN {
        let channel = a.open(&peer, ChannelKind::Control).unwrap();
        a.close(&channel).unwrap();
        channels.push(channel);
    }

    let oldest = &channels[0];
    let newest = &channels[CHURN - 1];
    assert!(!a.is_open(oldest).unwrap(), "purged link is not open");
    let purged = a
        .metrics(oldest)
        .unwrap_err()
        .downcast_inner::<InMemoryTransportError>();
    assert!(
        matches!(purged, Ok(InMemoryTransportError::ChannelNotFound)),
        "purged link must be gone from bookkeeping, not just flagged"
    );
    assert!(
        !a.is_open(newest).unwrap(),
        "newest closed link is retained"
    );
    assert!(
        a.metrics(newest).unwrap().degraded,
        "newest closed link reports closed"
    );

    let fresh = a.open(&peer, ChannelKind::Control).unwrap();
    assert!(a.is_open(&fresh).unwrap());
}

#[test]
fn tcp_double_close_stays_ok_after_eviction() {
    let transport = TcpTransport::new(endpoint("peer-tcp-double-close", 19253)).unwrap();
    let channel = channel_with_id("tcp-1");
    transport.close(&channel).unwrap();

    for i in 2..CHURN + 2 {
        transport
            .close(&channel_with_id(&format!("tcp-{}", i)))
            .unwrap();
    }

    assert!(
        !transport.metrics(&channel).unwrap().degraded,
        "the id must have been evicted by the churn"
    );
    transport.close(&channel).unwrap();
    assert!(
        transport.metrics(&channel).unwrap().degraded,
        "double close after eviction stays Ok and reports closed again"
    );
}
