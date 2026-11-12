use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use crate::protocol::{
    ChannelMigration, ChannelResumeCursor, ProtocolLimits, ResumeKey, ResumeRejectionReason,
    SessionChannel, SessionResumeAccepted, SessionResumeRejected, SessionResumeRequest,
};
use crate::transport::{ChannelKind, Transport, TransportChannel, TransportKind};

use crate::session::state::SessionState;

use super::{
    MigrationConfig, MigrationError, MigrationFailure, MigrationPhase, MigrationRouteState,
    MigrationTeardownSummary, cursors_cover, require_cursor, transition_state,
};

pub struct MigrationPlan {
    pub old_transport: Arc<dyn Transport>,
    pub old_channel: TransportChannel,
    pub target: TransportKind,
    pub cursors: Vec<ChannelResumeCursor>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeAcceptOutcome {
    Accepted { fallback_until_ms: u64 },
    Violation(MigrationFailure),
}

pub struct TransportMigrationInitiator {
    config: MigrationConfig,
    session_id: String,
    channel: SessionChannel,
    baseline_state: SessionState,
    session_state: SessionState,
    phase: MigrationPhase,
    migration: Option<ChannelMigration>,
    cursors: Vec<ChannelResumeCursor>,
    old_transport: Option<Arc<dyn Transport>>,
    old_channel: Option<TransportChannel>,
    new_channel: Option<TransportChannel>,
    request: Option<SessionResumeRequest>,
    fallback_until_ms: Option<u64>,
    old_channel_lost: bool,
    old_closed: bool,
}

impl Debug for TransportMigrationInitiator {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("TransportMigrationInitiator(<redacted>)")
    }
}

impl TransportMigrationInitiator {
    pub fn try_new(
        config: MigrationConfig,
        session_id: impl Into<String>,
        channel: SessionChannel,
        baseline_state: SessionState,
    ) -> eros::Result<Self> {
        let session_id = session_id.into();
        validate_session_identifier(&session_id)?;
        config
            .validate()
            .map_err(|error| eros::error!(MigrationError::Config(error)))?;
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
            session_state: baseline_state,
            baseline_state,
            session_id,
            channel,
            phase: MigrationPhase::Idle,
            migration: None,
            cursors: Vec::new(),
            old_transport: None,
            old_channel: None,
            new_channel: None,
            request: None,
            fallback_until_ms: None,
            old_channel_lost: false,
            old_closed: false,
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

    pub fn baseline_state(&self) -> SessionState {
        self.baseline_state
    }

    pub fn phase(&self) -> MigrationPhase {
        self.phase
    }

    pub fn request(&self) -> Option<&SessionResumeRequest> {
        self.request.as_ref()
    }

    pub fn migration(&self) -> Option<&ChannelMigration> {
        self.migration.as_ref()
    }

    /// The channel that currently carries session traffic.
    pub fn primary_channel(&self) -> Option<&TransportChannel> {
        match self.phase {
            MigrationPhase::Resumed | MigrationPhase::Completed => self.new_channel.as_ref(),
            _ => self.old_channel.as_ref(),
        }
    }

    pub fn new_channel(&self) -> Option<TransportChannel> {
        self.new_channel.clone()
    }

    pub fn fallback_until_ms(&self) -> Option<u64> {
        self.fallback_until_ms
    }

    pub fn route_state(&self) -> MigrationRouteState {
        match self.phase {
            MigrationPhase::Resumed => MigrationRouteState::NewChannelPrimary {
                old_fallback_until_ms: self.fallback_until_ms.unwrap_or_default(),
            },
            MigrationPhase::Completed => MigrationRouteState::Migrated,
            MigrationPhase::Failed(_) => MigrationRouteState::RolledBack,
            MigrationPhase::Idle | MigrationPhase::AwaitingAccept => {
                MigrationRouteState::OldChannelPrimary
            }
        }
    }

    /// Opens the new channel through the transport and builds the resume request to send on it
    pub fn begin(
        &mut self,
        plan: MigrationPlan,
        key: ResumeKey,
        now_ms: u64,
    ) -> eros::Result<SessionResumeRequest> {
        if self.old_channel_lost {
            return Err(eros::error!(MigrationError::OldChannelLost));
        }
        match self.phase {
            MigrationPhase::Idle => {}
            MigrationPhase::AwaitingAccept | MigrationPhase::Resumed => {
                return Err(eros::error!(MigrationError::MigrationInProgress));
            }
            got => {
                return Err(eros::error!(MigrationError::UnexpectedPhase {
                    context: "begin",
                    got
                }));
            }
        }

        let expected_kind = ChannelKind::from(self.channel);
        if plan.old_channel.kind() != expected_kind {
            return Err(eros::error!(MigrationError::ChannelKindMismatch));
        }
        if plan.target == plan.old_channel.transport() {
            return Err(eros::error!(MigrationError::TargetTransportSameAsOld));
        }
        require_cursor(&plan.cursors, self.channel)?;

        let new_channel = plan
            .old_transport
            .migrate(&plan.old_channel, plan.target)
            .map_err(|error| error.context("migrate session channel to target transport"))?;
        if new_channel.kind() != expected_kind {
            let _ = plan.old_transport.close(&new_channel);
            return Err(eros::error!(MigrationError::ChannelKindMismatch));
        }
        if new_channel.transport() != plan.target {
            let _ = plan.old_transport.close(&new_channel);
            return Err(eros::error!(MigrationError::TransportLabelMismatch {
                expected: plan.target,
                got: new_channel.transport(),
            }));
        }

        let migration = ChannelMigration::new(
            self.channel,
            plan.old_channel.id(),
            new_channel.id(),
            plan.old_channel.transport().as_str(),
            new_channel.transport().as_str(),
        )
        .map_err(|error| {
            let _ = plan.old_transport.close(&new_channel);
            error.context("build channel migration")
        })?;
        let request = SessionResumeRequest::new(
            self.session_id.as_str(),
            key,
            migration.clone(),
            plan.cursors,
            now_ms,
            now_ms.saturating_add(self.config.handshake_timeout_ms()),
        )
        .map_err(|error| {
            let _ = plan.old_transport.close(&new_channel);
            error.context("build session resume request")
        })?;
        let cursors = request.cursors.clone();

        self.session_state =
            transition_state(self.session_state, SessionState::MigratingTransport)?;
        self.phase = MigrationPhase::AwaitingAccept;
        self.migration = Some(migration);
        self.cursors = cursors;
        self.old_transport = Some(plan.old_transport);
        self.old_channel = Some(plan.old_channel);
        self.new_channel = Some(new_channel);
        self.request = Some(request.clone());

        Ok(request)
    }

    /// Feeds a peer resume acceptance into the attempt
    pub fn resume_accepted(
        &mut self,
        response: &SessionResumeAccepted,
        now_ms: u64,
    ) -> eros::Result<ResumeAcceptOutcome> {
        if self.phase != MigrationPhase::AwaitingAccept {
            return Err(eros::error!(MigrationError::UnexpectedPhase {
                context: "resume_accepted",
                got: self.phase,
            }));
        }

        let violated = self
            .migration
            .as_ref()
            .map(|migration| {
                response.session_id != self.session_id || response.migration != *migration
            })
            .unwrap_or(true)
            || self
                .request
                .as_ref()
                .map(|request| !cursors_cover(&request.cursors, &response.cursors))
                .unwrap_or(true);
        if violated {
            let failure = MigrationFailure::RejectedByPeer {
                reason: ResumeRejectionReason::ProtocolViolation,
            };
            self.end_attempt(failure)?;
            return Ok(ResumeAcceptOutcome::Violation(failure));
        }

        let fallback_until_ms = response
            .fallback_expires_at_ms
            .min(now_ms.saturating_add(self.config.fallback_ttl_ms()))
            .max(now_ms.saturating_add(1));
        self.session_state = transition_state(self.session_state, self.baseline_state)?;
        self.phase = MigrationPhase::Resumed;
        self.fallback_until_ms = Some(fallback_until_ms);

        Ok(ResumeAcceptOutcome::Accepted { fallback_until_ms })
    }

    /// Feeds a peer resume rejection into the attempt and rolls back
    pub fn resume_rejected(
        &mut self,
        response: &SessionResumeRejected,
    ) -> eros::Result<MigrationFailure> {
        if self.phase != MigrationPhase::AwaitingAccept {
            return Err(eros::error!(MigrationError::UnexpectedPhase {
                context: "resume_rejected",
                got: self.phase,
            }));
        }
        if response.session_id != self.session_id {
            return Err(eros::error!(MigrationError::ResponseMismatch {
                field: "session_id",
            }));
        }

        let failure = MigrationFailure::RejectedByPeer {
            reason: response.reason,
        };
        self.end_attempt(failure)?;
        Ok(failure)
    }
    pub fn tick(&mut self, now_ms: u64) -> eros::Result<()> {
        match self.phase {
            MigrationPhase::AwaitingAccept => {
                let expires_at_ms = self
                    .request
                    .as_ref()
                    .map(|request| request.expires_at_ms)
                    .ok_or(eros::error!(MigrationError::UnexpectedPhase {
                        context: "tick",
                        got: self.phase,
                    }))?;
                if now_ms < expires_at_ms {
                    return Ok(());
                }
                self.end_attempt(MigrationFailure::HandshakeTimeout)
            }
            MigrationPhase::Resumed => {
                if self.old_channel_lost {
                    self.old_closed = true;
                    self.phase = MigrationPhase::Completed;
                    self.fallback_until_ms = None;
                    return Ok(());
                }
                let fallback_until_ms = self.fallback_until_ms.ok_or(eros::error!(
                    MigrationError::UnexpectedPhase {
                        context: "tick",
                        got: self.phase,
                    }
                ))?;
                if now_ms < fallback_until_ms {
                    return Ok(());
                }

                let (transport, old_channel) =
                    match (self.old_transport.as_ref(), self.old_channel.as_ref()) {
                        (Some(transport), Some(old_channel)) => (transport, old_channel),
                        _ => {
                            return Err(eros::error!(MigrationError::UnexpectedPhase {
                                context: "tick",
                                got: self.phase,
                            }));
                        }
                    };
                transport
                    .close(old_channel)
                    .map_err(|error| error.context("close fallback channel"))?;
                self.old_closed = true;
                self.phase = MigrationPhase::Completed;
                self.fallback_until_ms = None;
                self.request = None;
                Ok(())
            }
            MigrationPhase::Idle | MigrationPhase::Completed | MigrationPhase::Failed(_) => Ok(()),
        }
    }

    pub fn note_old_channel_lost(&mut self) {
        self.old_channel_lost = true;
        if self.phase == MigrationPhase::Resumed {
            self.old_closed = true;
            self.phase = MigrationPhase::Completed;
            self.fallback_until_ms = None;
        }
    }

    /// Closes every channel this initiator still holds
    pub fn abandon(&mut self) -> MigrationTeardownSummary {
        let mut summary = MigrationTeardownSummary::default();
        if self.phase == MigrationPhase::Idle {
            return summary;
        }

        if let (Some(transport), Some(new_channel)) =
            (self.old_transport.as_ref(), self.new_channel.as_ref())
        {
            match transport.close(new_channel) {
                Ok(()) => summary.closed += 1,
                Err(_) => summary.failed += 1,
            }
        }
        self.new_channel = None;

        if !self.old_closed
            && !self.old_channel_lost
            && let (Some(transport), Some(old_channel)) =
                (self.old_transport.as_ref(), self.old_channel.as_ref())
        {
            match transport.close(old_channel) {
                Ok(()) => {
                    summary.closed += 1;
                    self.old_closed = true;
                }
                Err(_) => summary.failed += 1,
            }
        }

        self.request = None;
        self.cursors = Vec::new();
        self.migration = None;
        self.fallback_until_ms = None;
        if matches!(
            self.phase,
            MigrationPhase::AwaitingAccept | MigrationPhase::Resumed
        ) {
            self.phase = MigrationPhase::Failed(MigrationFailure::SessionReleased);
        }
        summary
    }

    pub fn reset(&mut self) -> eros::Result<()> {
        match self.phase {
            MigrationPhase::Idle => return Ok(()),
            MigrationPhase::Completed | MigrationPhase::Failed(_) => {}
            got => {
                return Err(eros::error!(MigrationError::UnexpectedPhase {
                    context: "reset",
                    got
                }));
            }
        }

        self.phase = MigrationPhase::Idle;
        self.migration = None;
        self.cursors = Vec::new();
        self.new_channel = None;
        self.request = None;
        self.fallback_until_ms = None;
        Ok(())
    }

    fn end_attempt(&mut self, failure: MigrationFailure) -> eros::Result<()> {
        if let (Some(transport), Some(new_channel)) =
            (self.old_transport.as_ref(), self.new_channel.as_ref())
        {
            transport
                .close(new_channel)
                .map_err(|error| error.context("close migrated channel"))?;
        }

        self.new_channel = None;
        let next = if self.old_channel_lost {
            SessionState::Reconnecting
        } else {
            self.baseline_state
        };
        self.session_state = transition_state(self.session_state, next)?;
        self.request = None;
        self.phase = MigrationPhase::Failed(failure);
        Ok(())
    }
}

fn validate_session_identifier(session_id: &str) -> eros::Result<()> {
    ProtocolLimits::default()
        .validate_string("sid", session_id)
        .map_err(|_| eros::error!(MigrationError::InvalidSessionId))?;
    if SessionResumeRejected::new(session_id, ResumeRejectionReason::Unauthorized, false).is_ok() {
        Ok(())
    } else {
        Err(eros::error!(MigrationError::InvalidSessionId))
    }
}
