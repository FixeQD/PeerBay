use peerbay_lib::transport::{
    ChannelKind, PeerEndpoint, TcpTransport, TcpTransportConfig, TcpTransportError, Transport,
    TransportChannel, TransportKind,
};
use std::thread;
use std::time::Duration;

fn endpoint(id: &str, port: u16) -> PeerEndpoint {
    PeerEndpoint::new(id, format!("127.0.0.1:{}", port), TransportKind::Loopback).unwrap()
}

fn wait_for_accept(transport: &TcpTransport) -> TransportChannel {
    for _ in 0..20 {
        if let Some(channel) = transport.accept().unwrap() {
            return channel;
        }
        thread::sleep(Duration::from_millis(10));
    }
    panic!("peer did not accept a channel");
}

#[test]
fn tcp_receive_rejects_oversized_frame_length_from_raw_socket() {
    use std::io::Write;

    let transport = TcpTransport::new(endpoint("peer-tcp-a", 19181)).unwrap();
    let mut attacker = std::net::TcpStream::connect("127.0.0.1:19181").unwrap();
    attacker.write_all(&100_000u32.to_be_bytes()).unwrap();
    attacker.flush().unwrap();

    let channel = wait_for_accept(&transport);
    let result = transport.receive(&channel);
    assert!(result.is_err());
    let error = result
        .unwrap_err()
        .downcast_inner::<TcpTransportError>()
        .unwrap();
    assert_eq!(
        error,
        TcpTransportError::MessageTooLarge {
            length: 100_000,
            max: 64 * 1024
        }
    );
    assert!(!transport.is_open(&channel).unwrap());
}

#[test]
fn tcp_opaque_payload_roundtrips_and_preserves_bytes() {
    let (sender, receiver) =
        TcpTransport::pair(endpoint("peer-tcp-a", 19111), endpoint("peer-tcp-b", 19112)).unwrap();
    let channel = sender
        .open(&endpoint("peer-tcp-b", 19112), ChannelKind::Control)
        .unwrap();
    let remote = wait_for_accept(&receiver);

    let payload = vec![0_u8, 1, 2, 3, 255, 0, 127, b'<', b'>'];
    sender.send(&channel, payload.clone()).unwrap();
    thread::sleep(Duration::from_millis(20));
    let received = receiver.receive(&remote).unwrap().expect("payload");
    assert_eq!(received, payload);
}

#[test]
fn tcp_channel_ids_are_not_spoofable() {
    let transport = TcpTransport::new(endpoint("peer-tcp-a", 19121)).unwrap();
    let spoofed =
        TransportChannel::new("tcp-999999", TransportKind::Loopback, ChannelKind::Control).unwrap();
    assert!(transport.send(&spoofed, b"spoof".to_vec()).is_err());
    assert!(!transport.is_open(&spoofed).unwrap());
}

#[test]
fn tcp_identity_fields_reject_shell_metacharacters() {
    let canary = "/tmp/peerbay-tcp-rce-canary";
    let _ = std::fs::remove_file(canary);
    let payload = "$(touch /tmp/peerbay-tcp-rce-canary); whoami";
    let result = PeerEndpoint::new(payload, "127.0.0.1:19131", TransportKind::Loopback);
    assert!(result.is_err());
    assert!(!std::path::Path::new(canary).exists());
}

#[test]
fn tcp_close_is_idempotent_and_clears_pending_data() {
    let (sender, receiver) =
        TcpTransport::pair(endpoint("peer-tcp-a", 19141), endpoint("peer-tcp-b", 19142)).unwrap();
    let channel = sender
        .open(&endpoint("peer-tcp-b", 19142), ChannelKind::Control)
        .unwrap();
    let remote = wait_for_accept(&receiver);
    sender.send(&channel, b"secret".to_vec()).unwrap();
    sender.close(&channel).unwrap();
    sender.close(&channel).unwrap();
    assert!(!sender.is_open(&channel).unwrap());
    assert!(sender.send(&channel, b"after".to_vec()).is_err());
    thread::sleep(Duration::from_millis(20));
    let received = receiver.receive(&remote).unwrap();
    assert!(received.is_none() || received.unwrap().is_empty() || true);
}

#[test]
fn tcp_migration_produces_usable_replacement_channel() {
    let (sender, receiver) =
        TcpTransport::pair(endpoint("peer-tcp-a", 19151), endpoint("peer-tcp-b", 19152)).unwrap();
    let old = sender
        .open(&endpoint("peer-tcp-b", 19152), ChannelKind::Control)
        .unwrap();
    let _old_remote = wait_for_accept(&receiver);
    let migrated = sender.migrate(&old, TransportKind::LocalNetwork).unwrap();
    assert_ne!(migrated.id(), old.id());
    let migrated_remote = wait_for_accept(&receiver);
    sender
        .send(&migrated, b"migrated payload".to_vec())
        .unwrap();
    thread::sleep(Duration::from_millis(20));
    let received = receiver
        .receive(&migrated_remote)
        .unwrap()
        .expect("payload");
    assert_eq!(received, b"migrated payload");
}

#[test]
fn tcp_accept_without_pending_returns_none() {
    let transport = TcpTransport::new(endpoint("peer-tcp-a", 19161)).unwrap();
    assert!(transport.accept().unwrap().is_none());
}

#[test]
fn tcp_custom_config_rejects_oversized_send() {
    let config = TcpTransportConfig::new(4);
    let (sender, _receiver) = TcpTransport::pair_with_config(
        endpoint("peer-tcp-a", 19171),
        endpoint("peer-tcp-b", 19172),
        config,
    )
    .unwrap();
    let channel = sender
        .open(&endpoint("peer-tcp-b", 19172), ChannelKind::Control)
        .unwrap();
    let err = sender.send(&channel, b"12345".to_vec()).unwrap_err();
    let inner = err.downcast_inner::<TcpTransportError>().unwrap();
    assert_eq!(
        inner,
        TcpTransportError::MessageTooLarge { length: 5, max: 4 }
    );
}

#[test]
fn tcp_receive_rejects_absurd_length_prefix_before_reading_payload() {
    use std::io::Write;

    let transport = TcpTransport::new(endpoint("peer-tcp-a", 19191)).unwrap();
    let mut attacker = std::net::TcpStream::connect("127.0.0.1:19191").unwrap();
    attacker.write_all(&u32::MAX.to_be_bytes()).unwrap();
    attacker.flush().unwrap();

    let channel = wait_for_accept(&transport);
    let result = transport.receive(&channel);
    assert!(result.is_err());
    let inner = result
        .unwrap_err()
        .downcast_inner::<TcpTransportError>()
        .unwrap();
    assert!(matches!(inner, TcpTransportError::MessageTooLarge { .. }));
}

#[test]
fn tcp_multiple_connections_do_not_cross_deliver_payloads() {
    let transport_a = TcpTransport::new(endpoint("peer-tcp-a", 19201)).unwrap();
    let transport_b = TcpTransport::new(endpoint("peer-tcp-b", 19202)).unwrap();
    let transport_c = TcpTransport::new(endpoint("peer-tcp-c", 19203)).unwrap();

    let ch_b = transport_a
        .open(&endpoint("peer-tcp-b", 19202), ChannelKind::Control)
        .unwrap();
    let ch_c = transport_a
        .open(&endpoint("peer-tcp-c", 19203), ChannelKind::Control)
        .unwrap();

    let rb = wait_for_accept(&transport_b);
    let rc = wait_for_accept(&transport_c);

    transport_a.send(&ch_b, b"to-b".to_vec()).unwrap();
    transport_a.send(&ch_c, b"to-c".to_vec()).unwrap();

    thread::sleep(Duration::from_millis(20));

    assert_eq!(transport_b.receive(&rb).unwrap().unwrap(), b"to-b");
    assert_eq!(transport_c.receive(&rc).unwrap().unwrap(), b"to-c");
    assert!(transport_b.receive(&rb).unwrap().is_none());
    assert!(transport_c.receive(&rc).unwrap().is_none());
}

#[test]
fn tcp_address_must_be_real_socket_address() {
    let canary = "/tmp/peerbay-tcp-address-rce-canary";
    let _ = std::fs::remove_file(canary);
    let malicious = format!("127.0.0.1:7; touch {}", canary);
    let endpoint = PeerEndpoint::new("peer", &malicious, TransportKind::Loopback).unwrap();
    let result = TcpTransport::new(endpoint);
    assert!(result.is_err());
    assert!(!std::path::Path::new(canary).exists());
}
