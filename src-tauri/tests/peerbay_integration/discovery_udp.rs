use peerbay_lib::discovery::{DiscoveryBeacon, DiscoveryConfig, DiscoveryError, DiscoveryService};
use std::thread;
use std::time::Duration;

#[test]
fn discovery_udp_roundtrips_public_beacon() {
    let port = 19891;
    let config = DiscoveryConfig {
        port,
        target_address: "127.0.0.1".to_owned(),
        ..DiscoveryConfig::default()
    };
    let service = DiscoveryService::new(config.clone()).unwrap();

    let handle = thread::spawn(
        move || match service.clone().receive(Duration::from_secs(2)) {
            Ok(value) => value,
            Err(error) => panic!("receive failed: {}", error),
        },
    );

    let sender_config = DiscoveryConfig {
        port,
        bind_address: "127.0.0.1".to_owned(),
        target_address: "127.0.0.1".to_owned(),
        ..DiscoveryConfig::default()
    };
    let sender = DiscoveryService::new(sender_config).unwrap();
    let beacon = DiscoveryBeacon::new("peer-udp-a".to_owned(), "linux".to_owned(), 18080).unwrap();
    thread::sleep(Duration::from_millis(50));
    sender.announce(&beacon).unwrap();

    let (received, _source) = handle.join().unwrap();
    assert_eq!(received, beacon);
}

#[test]
fn discovery_udp_rejects_malformed_json() {
    use std::net::UdpSocket;

    let port = 19892;
    let config = DiscoveryConfig {
        port,
        ..DiscoveryConfig::default()
    };
    let service = DiscoveryService::new(config).unwrap();

    let handle = thread::spawn(move || {
        let result = service.receive(Duration::from_millis(100));
        assert!(result.is_err());
        assert!(result.unwrap_err() == DiscoveryError::InvalidJson);
    });

    thread::sleep(Duration::from_millis(50));
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    let payload = b"{not json}";
    socket
        .send_to(payload, format!("127.0.0.1:{}", port))
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn discovery_udp_rejects_shell_metacharacters_in_beacon_id() {
    let canary = "/tmp/peerbay-discovery-rce-canary";
    let _ = std::fs::remove_file(canary);
    let result = DiscoveryBeacon::new(
        "$(touch /tmp/peerbay-discovery-rce-canary); whoami".to_owned(),
        "linux".to_owned(),
        18081,
    );
    assert!(result.is_err());
    assert!(!std::path::Path::new(canary).exists());
}

#[test]
fn discovery_rejects_oversized_datagram() {
    use std::net::UdpSocket;

    let port = 19893;
    let config = DiscoveryConfig {
        port,
        target_address: "127.0.0.1".to_owned(),
        bind_address: "127.0.0.1".to_owned(),
        max_message_size: 4,
    };
    let service = DiscoveryService::new(config).unwrap();
    let handle = thread::spawn(move || {
        let result = service.receive(Duration::from_millis(200));
        assert!(matches!(result, Err(DiscoveryError::InvalidSize { .. })));
    });

    thread::sleep(Duration::from_millis(50));
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket
        .send_to(&[0_u8; 100], format!("127.0.0.1:{}", port))
        .unwrap();
    handle.join().unwrap();
}

#[test]
fn discovery_unicode_platform_is_rejected() {
    let result = DiscoveryBeacon::new(
        "peer-unicode".to_owned(),
        String::from("linux\u{202e}"),
        18080,
    );
    assert!(result.is_err());
}

#[test]
fn discovery_config_rejects_non_address() {
    let config = DiscoveryConfig {
        bind_address: "localhost".to_owned(),
        ..DiscoveryConfig::default()
    };
    assert!(DiscoveryService::new(config).is_err());

    let config = DiscoveryConfig {
        target_address: "example.com".to_owned(),
        ..DiscoveryConfig::default()
    };
    assert!(DiscoveryService::new(config).is_err());
}

#[test]
fn discovery_rejects_oversized_configuration() {
    let config = DiscoveryConfig {
        max_message_size: 100_000,
        ..DiscoveryConfig::default()
    };
    assert!(DiscoveryService::new(config).is_err());
}
