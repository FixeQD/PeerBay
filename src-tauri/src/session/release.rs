use std::fmt::{Debug, Display, Formatter};
use std::sync::Arc;

use crate::transport::{Transport, TransportChannel};

use super::state::SessionState;

pub const MAX_TRACKED_CHANNELS: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelReleaseSummary {
    pub closed: usize,
    pub failed: usize,
    pub already_closed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReleaseError {
    LedgerFull { tracked: usize, max: usize },
    UnknownChannel { id: String },
    SessionAlreadyClosed,
}

impl Display for ReleaseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LedgerFull { tracked, max } => write!(
                formatter,
                "session channel ledger is full: tracks {tracked} channels, cap is {max}"
            ),
            Self::UnknownChannel { id } => {
                write!(
                    formatter,
                    "session channel ledger does not track channel {id:?}"
                )
            }
            Self::SessionAlreadyClosed => {
                write!(
                    formatter,
                    "session is already closed and cannot be released again"
                )
            }
        }
    }
}

impl std::error::Error for ReleaseError {}

struct LedgerEntry {
    transport: Arc<dyn Transport>,
    channel: TransportChannel,
    closed: bool,
}

pub struct SessionChannelLedger {
    entries: Vec<LedgerEntry>,
}

impl Default for SessionChannelLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionChannelLedger {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    pub fn track(
        &mut self,
        transport: Arc<dyn Transport>,
        channel: TransportChannel,
    ) -> eros::Result<()> {
        if self.entries.len() >= MAX_TRACKED_CHANNELS {
            return Err(eros::error!(ReleaseError::LedgerFull {
                tracked: self.entries.len(),
                max: MAX_TRACKED_CHANNELS,
            }));
        }

        self.entries.push(LedgerEntry {
            transport,
            channel,
            closed: false,
        });
        Ok(())
    }

    pub fn close_channel(&mut self, channel_id: &str) -> eros::Result<bool> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.channel.id() == channel_id)
        else {
            return Err(eros::error!(ReleaseError::UnknownChannel {
                id: channel_id.to_owned(),
            }));
        };
        if entry.closed {
            return Ok(false);
        }

        entry
            .transport
            .close(&entry.channel)
            .map_err(|error| error.context("close tracked session channel"))?;
        entry.closed = true;
        Ok(true)
    }

    pub fn close_all(&mut self) -> ChannelReleaseSummary {
        let mut summary = ChannelReleaseSummary {
            closed: 0,
            failed: 0,
            already_closed: 0,
        };
        for entry in &mut self.entries {
            if entry.closed {
                summary.already_closed += 1;
                continue;
            }
            match entry.transport.close(&entry.channel) {
                Ok(()) => {
                    entry.closed = true;
                    summary.closed += 1;
                }
                Err(_) => summary.failed += 1,
            }
        }
        summary
    }

    pub fn tracked_channels(&self) -> usize {
        self.entries.len()
    }

    pub fn open_channels(&self) -> usize {
        self.entries.iter().filter(|entry| !entry.closed).count()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn drain(&mut self) {
        self.entries.retain(|entry| !entry.closed);
    }
}

impl Debug for SessionChannelLedger {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SessionChannelLedger")
            .field("tracked", &self.tracked_channels())
            .field("open", &self.open_channels())
            .finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectTrigger {
    TrustRevoked,
    PolicyRevoked,
    SessionTimeout,
    HeartbeatLost,
    ProtocolViolation,
    BackendShutdown,
    PlatformServiceStopped,
    PeerReleased,
}

pub const ALL_TRIGGERS: [DisconnectTrigger; 8] = [
    DisconnectTrigger::TrustRevoked,
    DisconnectTrigger::PolicyRevoked,
    DisconnectTrigger::SessionTimeout,
    DisconnectTrigger::HeartbeatLost,
    DisconnectTrigger::ProtocolViolation,
    DisconnectTrigger::BackendShutdown,
    DisconnectTrigger::PlatformServiceStopped,
    DisconnectTrigger::PeerReleased,
];

impl DisconnectTrigger {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TrustRevoked => "trust_revoked",
            Self::PolicyRevoked => "policy_revoked",
            Self::SessionTimeout => "session_timeout",
            Self::HeartbeatLost => "heartbeat_lost",
            Self::ProtocolViolation => "protocol_violation",
            Self::BackendShutdown => "backend_shutdown",
            Self::PlatformServiceStopped => "platform_service_stopped",
            Self::PeerReleased => "peer_released",
        }
    }

    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::TrustRevoked
                | Self::BackendShutdown
                | Self::PeerReleased
                | Self::ProtocolViolation
        )
    }

    pub fn release_state(self, current: SessionState) -> eros::Result<SessionState> {
        if current == SessionState::Closed {
            return Err(eros::error!(ReleaseError::SessionAlreadyClosed));
        }
        if current == SessionState::Released || self.is_terminal() {
            return Ok(SessionState::Released);
        }
        if current.is_active() || current == SessionState::Reconnecting {
            return Ok(SessionState::Reconnecting);
        }
        Ok(SessionState::Disconnected)
    }
}
