use peerbay_lib::identity::TransportCertificate;
use peerbay_lib::transport::{
    ChannelKind, PeerEndpoint, TlsTransport, Transport, TransportChannel, TransportKind,
};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

fn endpoint(id: &str, port: u16) -> PeerEndpoint {
    PeerEndpoint::new(id, format!("127.0.0.1:{}", port), TransportKind::Loopback).unwrap()
}

#[test]
fn tls_pinned_certificate_allows_expected_peer() {
    let id_a = "00000000-0000-0000-0000-000000000001";
    let id_b = "00000000-0000-0000-0000-000000000002";

    let cert_a = TransportCertificate::generate_for_device(id_a).unwrap();
    let cert_b = TransportCertificate::generate_for_device(id_b).unwrap();

    let t1 = TlsTransport::with_certificate(
        endpoint(id_a, 19801),
        cert_a,
        Some(cert_b.certificate_der().to_vec()),
    )
    .unwrap();
    let t2 = TlsTransport::with_certificate(endpoint(id_b, 19802), cert_b, None).unwrap();

    let (tx, rx) = mpsc::channel();
    let server = thread::spawn(move || {
        let mut channel = None;
        for _ in 0..100 {
            if let Some(c) = t2.accept().unwrap() {
                channel = Some(c);
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let channel = channel.unwrap();
        thread::sleep(Duration::from_millis(100));
        let received = t2.receive(&channel).unwrap();
        tx.send(received).unwrap();
    });

    let client_channel = t1
        .open(&endpoint(id_b, 19802), ChannelKind::Control)
        .unwrap();
    t1.send(&client_channel, b"pinned hello".to_vec()).unwrap();

    server.join().unwrap();
    let received = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(received.unwrap(), b"pinned hello");
}

fn accept_tls(transport: &TlsTransport) -> Option<TransportChannel> {
    for _ in 0..100 {
        if let Some(channel) = transport.accept().unwrap() {
            return Some(channel);
        }
        thread::sleep(Duration::from_millis(10));
    }
    None
}

#[test]
fn tls_rejects_wrong_pinned_certificate() {
    let id_a = "00000000-0000-0000-0000-000000000011";
    let id_b = "00000000-0000-0000-0000-000000000012";
    let id_c = "00000000-0000-0000-0000-000000000013";

    let cert_a = TransportCertificate::generate_for_device(id_a).unwrap();
    let cert_b = TransportCertificate::generate_for_device(id_b).unwrap();
    let wrong_cert = TransportCertificate::generate_for_device(id_c).unwrap();

    let client = TlsTransport::with_certificate(
        endpoint(id_a, 19811),
        cert_a,
        Some(wrong_cert.certificate_der().to_vec()),
    )
    .unwrap();
    let server = TlsTransport::with_certificate(endpoint(id_b, 19812), cert_b, None).unwrap();

    let server_thread = thread::spawn(move || {
        let channel = accept_tls(&server).expect("server accepts");
        let _ = server.receive(&channel);
    });

    let client_channel = client
        .open(&endpoint(id_b, 19812), ChannelKind::Control)
        .unwrap();
    let result = client.send(&client_channel, b"wrong pin".to_vec());
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .downcast_inner::<peerbay_lib::transport::TlsTransportError>()
            .is_ok()
    );

    let _ = server_thread.join();
}

#[test]
fn tls_rejects_changed_peer_certificate() {
    let id_a = "00000000-0000-0000-0000-000000000021";
    let id_b = "00000000-0000-0000-0000-000000000022";

    let cert_a = TransportCertificate::generate_for_device(id_a).unwrap();
    let trusted_b = TransportCertificate::generate_for_device(id_b).unwrap();
    let rotated_b = TransportCertificate::generate_for_device(id_b).unwrap();

    let client = TlsTransport::with_certificate(
        endpoint(id_a, 19821),
        cert_a,
        Some(trusted_b.certificate_der().to_vec()),
    )
    .unwrap();
    let server = TlsTransport::with_certificate(endpoint(id_b, 19822), rotated_b, None).unwrap();

    let server_thread = thread::spawn(move || {
        let channel = accept_tls(&server).expect("server accepts");
        let _ = server.receive(&channel);
    });

    let client_channel = client
        .open(&endpoint(id_b, 19822), ChannelKind::Control)
        .unwrap();
    let result = client.send(&client_channel, b"changed cert".to_vec());
    assert!(result.is_err());
    let _ = server_thread.join();
}

#[test]
fn tls_requires_pinned_peer_certificate_for_open() {
    let id_a = "00000000-0000-0000-0000-000000000031";
    let id_b = "00000000-0000-0000-0000-000000000032";

    let cert_a = TransportCertificate::generate_for_device(id_a).unwrap();
    let cert_b = TransportCertificate::generate_for_device(id_b).unwrap();

    let client = TlsTransport::with_certificate(endpoint(id_a, 19831), cert_a, None).unwrap();
    let _server = TlsTransport::with_certificate(endpoint(id_b, 19832), cert_b, None).unwrap();

    let result = client.open(&endpoint(id_b, 19832), ChannelKind::Control);
    assert!(result.is_err());
}

#[test]
fn tls_rejects_malformed_pinned_certificate() {
    let id_a = "00000000-0000-0000-0000-000000000041";
    let id_b = "00000000-0000-0000-0000-000000000042";

    let cert_a = TransportCertificate::generate_for_device(id_a).unwrap();
    let cert_b = TransportCertificate::generate_for_device(id_b).unwrap();

    let client = TlsTransport::with_certificate(
        endpoint(id_a, 19841),
        cert_a,
        Some(vec![0_u8, 1, 2, 3]), // malformed root
    );
    assert!(client.is_err());

    let _ = cert_b;
}

#[test]
fn tls_opaque_payload_roundtrips_over_pinned_pair() {
    let id_a = "00000000-0000-0000-0000-000000000051";
    let id_b = "00000000-0000-0000-0000-000000000052";

    let (client, server) =
        TlsTransport::pair(endpoint(id_a, 19851), endpoint(id_b, 19852)).unwrap();

    let (tx, rx) = mpsc::channel();
    let server_thread = thread::spawn(move || {
        let channel = accept_tls(&server).expect("tls accept");
        thread::sleep(Duration::from_millis(100));
        let received = server.receive(&channel).unwrap().unwrap();
        tx.send(received).unwrap();
    });

    let client_channel = client
        .open(&endpoint(id_b, 19852), ChannelKind::Control)
        .unwrap();
    let payload = vec![0_u8, 1, 2, 3, 250, b'<', b'>', b'\\'];
    client.send(&client_channel, payload.clone()).unwrap();

    let received = rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(received, payload);
    server_thread.join().unwrap();
}

#[test]
fn tls_channel_ids_are_not_spoofable() {
    let id_a = "00000000-0000-0000-0000-000000000061";
    let cert_a = TransportCertificate::generate_for_device(id_a).unwrap();
    let transport = TlsTransport::with_certificate(endpoint(id_a, 19861), cert_a, None).unwrap();
    let spoofed =
        TransportChannel::new("tls-999999", TransportKind::Loopback, ChannelKind::Control).unwrap();
    assert!(transport.send(&spoofed, b"spoof".to_vec()).is_err());
    assert!(!transport.is_open(&spoofed).unwrap());
}

#[test]
fn tls_custom_config_rejects_oversized_send() {
    use peerbay_lib::transport::TlsTransportConfig;

    let id_a = "00000000-0000-0000-0000-000000000071";
    let id_b = "00000000-0000-0000-0000-000000000072";
    let (client, _server) = TlsTransport::pair_with_config(
        endpoint(id_a, 19871),
        endpoint(id_b, 19872),
        TlsTransportConfig::new(4),
    )
    .unwrap();
    let channel = client
        .open(&endpoint(id_b, 19872), ChannelKind::Control)
        .unwrap();
    let err = client.send(&channel, b"12345".to_vec()).unwrap_err();
    let inner = err
        .downcast_inner::<peerbay_lib::transport::TlsTransportError>()
        .unwrap();
    assert!(matches!(
        inner,
        peerbay_lib::transport::TlsTransportError::MessageTooLarge { .. }
    ));
}

#[test]
fn tls_identity_fields_reject_shell_metacharacters() {
    let canary = "/tmp/peerbay-tls-rce-canary";
    let _ = std::fs::remove_file(canary);
    let payload = "$(touch /tmp/peerbay-tls-rce-canary); whoami";
    assert!(PeerEndpoint::new(payload, "127.0.0.1:19881", TransportKind::Loopback).is_err());
    assert!(!std::path::Path::new(canary).exists());
}
