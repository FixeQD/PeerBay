use std::time::{Duration, Instant};

use peerbay_lib::protocol::PongBody;
use peerbay_lib::session::{Heartbeat, HeartbeatConfig, LivenessStatus};

#[test]
fn heartbeat_starts_alive_and_times_out_without_inbound_traffic() {
    let start = Instant::now();
    let config = HeartbeatConfig::new(Duration::from_secs(5), Duration::from_secs(15));
    let mut heartbeat = Heartbeat::new(config, start);

    assert_eq!(heartbeat.check(start + Duration::from_secs(14)), LivenessStatus::Alive);
    assert_eq!(heartbeat.check(start + Duration::from_secs(15)), LivenessStatus::TimedOut);
    assert!(heartbeat.timed_out());
}

#[test]
fn heartbeat_records_rtt_from_matching_pong() {
    let start = Instant::now();
    let mut heartbeat = Heartbeat::new(HeartbeatConfig::default(), start);

    heartbeat.record_ping_sent("ping-1", 7, start);
    let pong = PongBody::new("ping-1", Some(7)).expect("pong body");
    let sample = heartbeat
        .record_pong(&pong, start + Duration::from_millis(42))
        .expect("matching pong should produce RTT");

    assert!(sample.ping_id_matches);
    assert_eq!(sample.ping_seq, Some(7));
    assert_eq!(sample.rtt, Duration::from_millis(42));
    assert_eq!(heartbeat.latest_rtt_ms(), Some(42));
}

#[test]
fn heartbeat_ignores_unknown_pongs() {
    let start = Instant::now();
    let mut heartbeat = Heartbeat::new(HeartbeatConfig::default(), start);
    let pong = PongBody::new("missing", None).expect("pong body");

    assert!(heartbeat.record_pong(&pong, start + Duration::from_millis(10)).is_none());
    assert_eq!(heartbeat.latest_rtt(), None);
}

#[test]
fn inbound_activity_refreshes_liveness_timeout() {
    let start = Instant::now();
    let config = HeartbeatConfig::new(Duration::from_secs(5), Duration::from_secs(15));
    let mut heartbeat = Heartbeat::new(config, start);

    heartbeat.record_inbound(start + Duration::from_secs(10));
    assert_eq!(heartbeat.check(start + Duration::from_secs(24)), LivenessStatus::Alive);
    assert_eq!(heartbeat.check(start + Duration::from_secs(25)), LivenessStatus::TimedOut);
}

#[test]
fn heartbeat_reports_when_ping_should_be_sent() {
    let start = Instant::now();
    let config = HeartbeatConfig::new(Duration::from_secs(5), Duration::from_secs(15));
    let mut heartbeat = Heartbeat::new(config, start);

    assert!(!heartbeat.should_send_ping(start + Duration::from_secs(4)));
    assert!(heartbeat.should_send_ping(start + Duration::from_secs(5)));
    heartbeat.record_ping_sent("ping-1", 1, start + Duration::from_secs(5));
    assert!(!heartbeat.should_send_ping(start + Duration::from_secs(9)));
    assert!(heartbeat.should_send_ping(start + Duration::from_secs(10)));
}
