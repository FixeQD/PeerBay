use peerbay_lib::discovery::{MdnsAdvertisement, MdnsConfig, MdnsService};
use std::thread;
use std::time::Duration;

#[test]
fn mdns_roundtrips_advertisement() {
    let port = 19901;
    let config = MdnsConfig {
        port,
        target_address: "127.0.0.1".to_owned(),
        bind_address: "127.0.0.1".to_owned(),
        ..MdnsConfig::default()
    };
    let service = MdnsService::new(config.clone()).unwrap();

    let handle = thread::spawn(move || {
        service.clone().browse(Duration::from_secs(2)).unwrap()
    });

    thread::sleep(Duration::from_millis(50));
    let sender = MdnsService::new(config.clone()).unwrap();
    let advertisement = MdnsAdvertisement::new(
        "peer-mdns-a".to_owned(),
        "linux".to_owned(),
        18080,
    )
    .unwrap();
    sender.announce(&advertisement).unwrap();

    let (received, _) = handle.join().unwrap();
    assert_eq!(received, advertisement);
}

#[test]
fn mdns_rejects_malformed_payload() {
    use std::net::UdpSocket;

    let port = 19902;
    let config = MdnsConfig {
        port,
        bind_address: "127.0.0.1".to_owned(),
        ..MdnsConfig::default()
    };
    let service = MdnsService::new(config).unwrap();

    let handle = thread::spawn(move || {
        let result = service.browse(Duration::from_millis(100));
        assert!(result.is_err());
    });

    thread::sleep(Duration::from_millis(50));
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.send_to(b"{not json}", format!("127.0.0.1:{}", port)).unwrap();
    handle.join().unwrap();
}

#[test]
fn mdns_rejects_bad_txt_key() {
    let mut advertisement = MdnsAdvertisement::new(
        "peer-mdns-b".to_owned(),
        "linux".to_owned(),
        18081,
    )
    .unwrap();
    advertisement.text.insert("bad key".to_owned(), "value".to_owned());
    assert!(advertisement.validate().is_err());
}

#[test]
fn mdns_rejects_unicode_metadata() {
    let result = MdnsAdvertisement::new(
        "peer-mdns".to_owned(),
        "linux\u{202e}".to_owned(),
        18082,
    );
    assert!(result.is_err());
}

#[test]
fn mdns_rejects_wrong_service_type() {
    let mut advertisement = MdnsAdvertisement::new(
        "peer-mdns".to_owned(),
        "linux".to_owned(),
        18083,
    )
    .unwrap();
    advertisement.service_type = "_evil._tcp.local".to_owned();
    assert!(advertisement.validate().is_err());
}

#[test]
fn mdns_rejects_port_zero() {
    let result = MdnsAdvertisement::new("peer-mdns".to_owned(), "linux".to_owned(), 0);
    assert!(result.is_err());
}

#[test]
fn mdns_rejects_too_many_txt_entries() {
    let mut advertisement = MdnsAdvertisement::new(
        "peer-mdns".to_owned(),
        "linux".to_owned(),
        18084,
    )
    .unwrap();
    for i in 0..65 {
        advertisement.text.insert(format!("key{}", i), "value".to_owned());
    }
    assert!(advertisement.validate().is_err());
}

#[test]
fn mdns_rejects_oversized_configuration() {
    let config = MdnsConfig {
        max_message_size: 100_000,
        ..MdnsConfig::default()
    };
    assert!(MdnsService::new(config).is_err());
}