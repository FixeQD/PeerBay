use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use crate::protocol::PongBody;

const MAX_PENDING_PINGS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeartbeatConfig {
    pub ping_interval: Duration,
    pub timeout: Duration,
}

impl HeartbeatConfig {
    pub const fn new(ping_interval: Duration, timeout: Duration) -> Self {
        Self {
            ping_interval,
            timeout,
        }
    }
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            ping_interval: Duration::from_secs(15),
            timeout: Duration::from_secs(45),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RttSample {
    pub ping_id_matches: bool,
    pub ping_seq: Option<u64>,
    pub rtt: Duration,
}

impl RttSample {
    pub fn rtt_ms_saturating(self) -> u32 {
        u32::try_from(self.rtt.as_millis()).unwrap_or(u32::MAX)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LivenessStatus {
    Alive,
    TimedOut,
}

#[derive(Debug)]
pub struct Heartbeat {
    config: HeartbeatConfig,
    started_at: Instant,
    last_inbound_at: Instant,
    last_ping_sent_at: Option<Instant>,
    pending_pings: HashMap<String, PendingPing>,
    pending_order: VecDeque<String>,
    latest_rtt: Option<Duration>,
    timed_out: bool,
}

#[derive(Clone, Copy, Debug)]
struct PendingPing {
    seq: u64,
    sent_at: Instant,
}

impl Heartbeat {
    pub fn new(config: HeartbeatConfig, now: Instant) -> Self {
        Self {
            config,
            started_at: now,
            last_inbound_at: now,
            last_ping_sent_at: None,
            pending_pings: HashMap::new(),
            pending_order: VecDeque::new(),
            latest_rtt: None,
            timed_out: false,
        }
    }

    pub fn config(&self) -> HeartbeatConfig {
        self.config
    }

    pub fn latest_rtt(&self) -> Option<Duration> {
        self.latest_rtt
    }

    pub fn latest_rtt_ms(&self) -> Option<u32> {
        self.latest_rtt
            .map(|rtt| u32::try_from(rtt.as_millis()).unwrap_or(u32::MAX))
    }

    pub fn timed_out(&self) -> bool {
        self.timed_out
    }

    pub fn last_inbound_age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_inbound_at)
    }

    pub fn record_inbound(&mut self, now: Instant) {
        self.last_inbound_at = now;
    }

    pub fn should_send_ping(&self, now: Instant) -> bool {
        if self.timed_out {
            return false;
        }
        match self.last_ping_sent_at {
            None => now.saturating_duration_since(self.started_at) >= self.config.ping_interval,
            Some(sent_at) => now.saturating_duration_since(sent_at) >= self.config.ping_interval,
        }
    }

    pub fn record_ping_sent(&mut self, ping_id: impl Into<String>, ping_seq: u64, now: Instant) {
        self.last_ping_sent_at = Some(now);

        let ping_id = ping_id.into();

        // Evict the oldest pending ping when the map is full and this is a new id
        if !self.pending_pings.contains_key(&ping_id)
            && self.pending_pings.len() >= MAX_PENDING_PINGS
        {
            if let Some(oldest) = self.pending_order.pop_front() {
                self.pending_pings.remove(&oldest);
            }
        }

        self.pending_order.retain(|id| id != &ping_id);
        self.pending_order.push_back(ping_id.clone());

        self.pending_pings.insert(
            ping_id,
            PendingPing {
                seq: ping_seq,
                sent_at: now,
            },
        );
    }

    pub fn record_pong(&mut self, pong: &PongBody, now: Instant) -> Option<RttSample> {
        pong.validate().ok()?;

        let pending = self.pending_pings.get(&pong.ping_id).cloned()?;

        if let Some(seq) = pong.ping_seq {
            if seq != pending.seq {
                return None;
            }
        }

        if self.timed_out {
            return None;
        }

        self.pending_pings.remove(&pong.ping_id);
        self.pending_order.retain(|id| id != &pong.ping_id);

        self.record_inbound(now);

        let rtt = now.saturating_duration_since(pending.sent_at);
        self.latest_rtt = Some(rtt);
        self.timed_out = false;
        Some(RttSample {
            ping_id_matches: true,
            ping_seq: Some(pending.seq),
            rtt,
        })
    }

    pub fn check(&mut self, now: Instant) -> LivenessStatus {
        if self.timed_out {
            return LivenessStatus::TimedOut;
        }
        if self.last_inbound_age(now) >= self.config.timeout {
            self.timed_out = true;
            self.pending_pings.clear();
            self.pending_order.clear();
            return LivenessStatus::TimedOut;
        }
        LivenessStatus::Alive
    }

    pub fn reset_timeout(&mut self, now: Instant) {
        self.timed_out = false;
        self.last_inbound_at = now;
        self.pending_pings.clear();
        self.pending_order.clear();
    }
}
