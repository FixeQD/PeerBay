use std::collections::VecDeque;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use crate::protocol::{
    ChannelMigration, ProtocolLimits, ResumeRejectionReason, SessionChannel, SessionResumeAccepted,
    SessionResumeRejected, SessionResumeRequest,
};
use crate::transport::{ChannelKind, Transport, TransportChannel};

use super::keys::ResumeKeyStore;
use super::{
    MigrationConfig, MigrationError, MigrationRouteState, MigrationTeardownSummary, require_cursor,
    transition_state,
};
use crate::session::state::SessionState;

const MAX_QUARANTINED_RESUMES: usize = 64;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelSeqSnapshot {
    pub channel: SessionChannel,
    pub last_sent_seq: u64,
    pub last_received_seq: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionResumeOutcome {
    Accepted(SessionResumeAccepted),
    Rejected(SessionResumeRejected),
}

struct ActiveResume {
    migration: ChannelMigration,
    fallback_until_ms: u64,
}

struct QuarantinedResume {
    new_channel_id: String,
    expires_at_ms: u64,
}

pub struct TransportMigrationResponder {
    config: MigrationConfig,
    session_id: String,
    channel: SessionChannel,
    baseline_state: SessionState,
    session_state: SessionState,
    keys: ResumeKeyStore,
    accepted: Option<ActiveResume>,
    old_transport: Option<Arc<dyn Transport>>,
    old_channel: Option<TransportChannel>,
    fallback_closed: bool,
    old_channel_lost: bool,
    quarantined: VecDeque<QuarantinedResume>,
}

impl Debug for TransportMigrationResponder {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransportMigrationResponder(<redacted>)")
    }
}

impl TransportMigrationResponder {
    pub fn try_new(
        config: MigrationConfig,
        session_id: impl Into<String>,
        channel: SessionChannel,
        keys: ResumeKeyStore,
        baseline_state: SessionState,
    ) -> eros::Result<Self> {
        let session_id = session_id.into();
        validate_session_identifier(&session_id)?;
        config
            .validate()
            .map_err(|error| eros::error!(MigrationError::Config(error)))?;
        if keys.session_id() != session_id {
            return Err(eros::error!(MigrationError::SessionIdMismatch));
        }
        if !matches!(
            baseline_state,
            SessionState::Connected | SessionState::Degraded
        ) {
            return Err(eros::error!(MigrationError::InvalidBaseline {
                got: baseline_state
            }));
        }

        Ok(Self {
            config,
            session_id,
            channel,
            baseline_state,
            session_state: baseline_state,
            keys,
            accepted: None,
            old_transport: None,
            old_channel: None,
            fallback_closed: false,
            old_channel_lost: false,
            quarantined: VecDeque::new(),
        })
    }

    pub fn config(&self) -> MigrationConfig {
        self.config
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn channel(&self) -> SessionChannel {
        self.channel
    }

    pub fn session_state(&self) -> SessionState {
        self.session_state
    }

    pub fn accepted_migration(&self) -> Option<&ChannelMigration> {
        self.accepted.as_ref().map(|active| &active.migration)
    }

    pub fn fallback_until_ms(&self) -> Option<u64> {
        self.accepted
            .as_ref()
            .map(|active| active.fallback_until_ms)
    }

    pub fn route_state(&self) -> MigrationRouteState {
        match self.accepted {
            Some(ref active) if !self.fallback_closed => MigrationRouteState::NewChannelPrimary {
                old_fallback_until_ms: active.fallback_until_ms,
            },
            Some(_) => MigrationRouteState::Migrated,
            None if self.fallback_closed => MigrationRouteState::Migrated,
            None => MigrationRouteState::OldChannelPrimary,
        }
    }

    pub fn note_local_old_channel(
        &mut self,
        transport: Arc<dyn Transport>,
        channel: TransportChannel,
    ) -> eros::Result<()> {
        if channel.kind() != ChannelKind::from(self.channel) {
            return Err(eros::error!(MigrationError::ChannelKindMismatch));
        }

        self.old_transport = Some(transport);
        self.old_channel = Some(channel);
        Ok(())
    }

    pub fn handle_request(
        &mut self,
        request: &SessionResumeRequest,
        now_ms: u64,
        snapshots: Option<&[ChannelSeqSnapshot]>,
    ) -> eros::Result<SessionResumeOutcome> {
        self.purge_expired_quarantine(now_ms);

        if request.validate_for_session(&self.session_id).is_err() {
            return Ok(self.reject(ResumeRejectionReason::ProtocolViolation));
        }
        if request.migration.channel != self.channel {
            return Ok(self.reject(ResumeRejectionReason::UnknownChannel));
        }
        if request.requested_at_ms > now_ms {
            return Ok(self.reject(ResumeRejectionReason::ProtocolViolation));
        }
        if !(now_ms < request.expires_at_ms) {
            return Ok(self.reject(ResumeRejectionReason::ExpiredResumeKey));
        }
        if request.expires_at_ms > now_ms.saturating_add(self.config.handshake_timeout_ms()) {
            return Ok(self.reject(ResumeRejectionReason::ProtocolViolation));
        }

        let key_matches = self
            .keys
            .current()
            .map(|key| key.as_str() == request.resume_key.as_str())
            .unwrap_or(false);
        if !key_matches {
            return Ok(self.reject(ResumeRejectionReason::InvalidResumeKey));
        }

        if self.accepted.is_some() {
            return Ok(self.reject(ResumeRejectionReason::ChannelAlreadyActive));
        }
        if self
            .quarantined
            .iter()
            .any(|item| item.new_channel_id == request.migration.new_channel_id)
        {
            return Ok(self.reject(ResumeRejectionReason::ChannelAlreadyActive));
        }

        if require_cursor(&request.cursors, request.migration.channel).is_err() {
            return Ok(self.reject(ResumeRejectionReason::UnknownChannel));
        }
        if let Some(snapshot) = snapshots.and_then(|snapshots| {
            snapshots
                .iter()
                .find(|snapshot| snapshot.channel == request.migration.channel)
        }) {
            let cursor = request
                .cursors
                .iter()
                .find(|cursor| cursor.channel == request.migration.channel);
            if let Some(cursor) = cursor {
                if cursor.last_received_seq > snapshot.last_sent_seq
                    || cursor.last_sent_seq > snapshot.last_received_seq
                {
                    return Ok(self.reject(ResumeRejectionReason::SequenceConflict));
                }
            }
        }

        let fallback_until_ms = now_ms.saturating_add(self.config.fallback_ttl_ms());
        let response = SessionResumeAccepted::new(
            self.session_id.as_str(),
            request.migration.clone(),
            request.cursors.clone(),
            now_ms,
            fallback_until_ms,
        )
        .map_err(|error| error.context("build session resume accepted"))?;

        self.quarantined.push_back(QuarantinedResume {
            new_channel_id: request.migration.new_channel_id.clone(),
            expires_at_ms: request.expires_at_ms,
        });
        while self.quarantined.len() > MAX_QUARANTINED_RESUMES {
            self.quarantined.pop_front();
        }
        self.accepted = Some(ActiveResume {
            migration: request.migration.clone(),
            fallback_until_ms,
        });
        self.session_state =
            transition_state(self.session_state, SessionState::MigratingTransport)?;

        Ok(SessionResumeOutcome::Accepted(response))
    }

    pub fn close_expired_fallback(&mut self, now_ms: u64) -> eros::Result<bool> {
        if self.fallback_closed {
            return Ok(false);
        }
        let Some(active) = self.accepted.as_ref() else {
            return Ok(false);
        };
        if now_ms < active.fallback_until_ms && !self.old_channel_lost {
            return Ok(false);
        }

        if let (Some(transport), Some(old_channel)) =
            (self.old_transport.as_ref(), self.old_channel.as_ref())
        {
            transport
                .close(old_channel)
                .map_err(|error| error.context("close fallback channel"))?;
        }
        self.fallback_closed = true;
        self.accepted = None;
        self.session_state = transition_state(self.session_state, self.baseline_state)?;
        Ok(true)
    }

    pub fn note_old_channel_lost(&mut self) {
        self.old_channel_lost = true;
        if self.accepted.is_some() && !self.fallback_closed {
            self.fallback_closed = true;
            self.accepted = None;
            self.session_state = transition_state(self.session_state, self.baseline_state)
                .unwrap_or(self.session_state);
        }
    }

    /// Releases every resource this responder holds
    pub fn teardown(&mut self) -> MigrationTeardownSummary {
        let mut summary = MigrationTeardownSummary::default();
        if !self.fallback_closed {
            if let (Some(transport), Some(old_channel)) =
                (self.old_transport.as_ref(), self.old_channel.as_ref())
            {
                match transport.close(old_channel) {
                    Ok(()) => summary.closed += 1,
                    Err(_) => summary.failed += 1,
                }
            }
            self.fallback_closed = true;
        }

        self.accepted = None;
        self.quarantined.clear();
        self.keys.clear();
        summary
    }

    fn reject(&mut self, reason: ResumeRejectionReason) -> SessionResumeOutcome {
        SessionResumeOutcome::Rejected(
            SessionResumeRejected::new(self.session_id.as_str(), reason, false)
                .expect("session id validated at construction"),
        )
    }

    fn purge_expired_quarantine(&mut self, now_ms: u64) {
        self.quarantined.retain(|item| now_ms < item.expires_at_ms);
        while self.quarantined.len() > MAX_QUARANTINED_RESUMES {
            self.quarantined.pop_front();
        }
    }
}

fn validate_session_identifier(session_id: &str) -> eros::Result<()> {
    ProtocolLimits::default()
        .validate_string("sid", session_id)
        .map_err(|_| eros::error!(MigrationError::InvalidSessionId))?;
    match SessionResumeRejected::new(session_id, ResumeRejectionReason::Unauthorized, false) {
        Ok(_) => Ok(()),
        Err(_) => Err(eros::error!(MigrationError::InvalidSessionId)),
    }
}
