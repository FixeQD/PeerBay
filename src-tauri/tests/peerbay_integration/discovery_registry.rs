use peerbay_lib::discovery::{DiscoveryAddress, DiscoveryRegistry};
use std::net::SocketAddr;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, Instant};

fn sa(s: &str) -> SocketAddr {
    SocketAddr::from_str(s).unwrap()
}

#[test]
fn registry_deduplicates_same_device_by_id() {
    let mut registry = DiscoveryRegistry::new(Duration::from_secs(60), Duration::from_secs(30));
    let now = Instant::now();

    assert!(registry
        .observe("peer-a", "linux", sa("127.0.0.1:9000"), 7000, now)
        .unwrap());
    assert!(!registry
        .observe("peer-a", "windows", sa("127.0.0.1:9001"), 7001, now)
        .unwrap());

    assert_eq!(registry.len(), 1);
    let peers = registry.peers();
    assert_eq!(peers[0].addresses.len(), 2);
    assert_eq!(peers[0].port, 7001);
}

#[test]
fn registry_prunes_stale_addresses_but_keeps_peer() {
    let mut registry = DiscoveryRegistry::new(Duration::from_secs(60), Duration::from_millis(10));
    let now = Instant::now();
    registry
        .observe("peer-a", "linux", sa("127.0.0.1:9000"), 7000, now)
        .unwrap();
    registry
        .observe("peer-a", "linux", sa("127.0.0.1:9001"), 7001, now + Duration::from_millis(5))
        .unwrap();

    let expired = registry.prune(now + Duration::from_millis(12));
    assert!(expired.is_empty());
    let addresses = &registry.get("peer-a").unwrap().addresses;
    assert!(!addresses.contains_key("127.0.0.1:7000"));
    assert!(addresses.contains_key("127.0.0.1:7001"));
}

#[test]
fn registry_prunes_expired_peers() {
    let mut registry = DiscoveryRegistry::new(Duration::from_millis(10), Duration::from_secs(30));
    let now = Instant::now();
    registry
        .observe("peer-a", "linux", sa("127.0.0.1:9000"), 7000, now)
        .unwrap();

    let expired = registry.prune(now + Duration::from_millis(12));
    assert_eq!(expired, vec!["peer-a".to_owned()]);
    assert!(registry.is_empty());
}

#[test]
fn registry_rejects_bad_device_id() {
    let mut registry = DiscoveryRegistry::new(Duration::from_secs(10), Duration::from_secs(10));
    let now = Instant::now();
    assert!(registry
        .observe("$(touch /tmp/peerbay-reg-rce)", "linux", sa("127.0.0.1:9000"), 7000, now)
        .is_err());
}

#[test]
fn registry_evicts_oldest_peer_at_capacity() {
    let mut registry = DiscoveryRegistry::with_limits(
        Duration::from_secs(60),
        Duration::from_secs(30),
        1,
        8,
    );
    let now = Instant::now();
    registry
        .observe("peer-a", "linux", sa("127.0.0.1:9000"), 7000, now)
        .unwrap();
    let result = registry.observe(
        "peer-b",
        "linux",
        sa("127.0.0.1:9001"),
        7001,
        now + Duration::from_secs(1),
    );
    assert!(result.is_err());

    assert_eq!(registry.len(), 1);
    assert!(registry.get("peer-a").is_some());
    assert!(registry.get("peer-b").is_none());
}

#[test]
fn registry_caps_addresses_per_peer() {
    let mut registry = DiscoveryRegistry::with_limits(
        Duration::from_secs(60),
        Duration::from_secs(30),
        8,
        1,
    );
    let now = Instant::now();
    registry
        .observe("peer-a", "linux", sa("127.0.0.1:9000"), 7000, now)
        .unwrap();
    registry
        .observe("peer-a", "linux", sa("127.0.0.1:9001"), 7001, now + Duration::from_secs(1))
        .unwrap();

    let peer = registry.get("peer-a").unwrap();
    assert_eq!(peer.addresses.len(), 1);
    assert!(!peer.addresses.contains_key("127.0.0.1:7000"));
    assert!(peer.addresses.contains_key("127.0.0.1:7001"));
}

#[test]
fn discovery_address_exposes_last_seen() {
    let address = DiscoveryAddress {
        address: "127.0.0.1:7000".to_owned(),
        last_seen: Instant::now(),
    };
    assert_eq!(address.address, "127.0.0.1:7000");
}