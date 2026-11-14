use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use std::time::Instant;

use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::protocol::{
    ControlMessageType, MessageChannel, MessageEnvelope, MessageType, PingBody, PongBody,
    ProtocolLimits, SequenceTracker,
};
use crate::transport::{Transport, TransportChannel};

use super::errors::SessionError;
use super::heartbeat::{Heartbeat, HeartbeatConfig, RttSample};
use super::release::{
    DisconnectTrigger, SessionChannelLedger, SessionReleaseReport, SessionResources,
};
use super::state::{InvalidSessionTransition, SessionState};

const CONNECT_PATH: [SessionState; 4] = [
    SessionState::ResolvingPeer,
    SessionState::OpeningTransport,
    SessionState::Authenticating,
    SessionState::NegotiatingCapabilities,
];

pub struct PeerSession {
    session_id: String,
    started_at: Instant,
    state: SessionState,
    resources: SessionResources,
    tracker: SequenceTracker,
    transport: Option<Arc<dyn Transport>>,
    channel: Option<TransportChannel>,
    next_seq: u64,
}

impl PeerSession {
    pub fn new(session_id: impl Into<String>, now: Instant) -> eros::Result<Self> {
        let tracker = SequenceTracker::new(session_id)?;
        let resources = SessionResources {
            channels: SessionChannelLedger::default(),
            initiator: None,
            responder: None,
            heartbeat: Some(Heartbeat::new(HeartbeatConfig::default(), now)),
            backoff: None,
        };

        Ok(Self {
            session_id: tracker.session_id().to_owned(),
            started_at: now,
            state: SessionState::Disconnected,
            resources,
            tracker,
            transport: None,
            channel: None,
            next_seq: 0,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn state(&self) -> SessionState {
        self.state
    }

    pub fn resources(&self) -> &SessionResources {
        &self.resources
    }

    pub fn resources_mut(&mut self) -> &mut SessionResources {
        &mut self.resources
    }

    pub fn open_channel(
        &mut self,
        transport: Arc<dyn Transport>,
        channel: TransportChannel,
    ) -> eros::Result<()> {
        if self.state == SessionState::Closed {
            return Err(eros::error!(SessionError::Closed).context("attach session channel"));
        }
        if let Some(previous) = self.channel.take() {
            self.resources.channels.close_channel(previous.id())?;
        }
        self.transport = None;
        self.resources
            .channels
            .track(transport.clone(), channel.clone())?;
        self.transport = Some(transport);
        self.channel = Some(channel);
        self.connect()
    }

    pub fn send_envelope<T: Serialize>(
        &mut self,
        message_type: MessageType,
        body: T,
        now_ms: u64,
    ) -> eros::Result<()> {
        let id = format!("m-{}", self.next_seq);
        self.send_with_id(id, message_type, body, now_ms)
    }

    pub fn receive_envelope<T: DeserializeOwned>(
        &mut self,
    ) -> eros::Result<Option<MessageEnvelope<T>>> {
        if self.state == SessionState::Closed {
            return Err(eros::error!(SessionError::Closed).context("receive session envelope"));
        }
        let payload = self.receive_payload()?;
        let Some(payload) = payload else {
            return Ok(None);
        };

        let envelope: MessageEnvelope<T> = serde_json::from_slice(&payload)
            .map_err(|error| eros::error!(error).context("decode session envelope"))?;
        ProtocolLimits::default()
            .validate_envelope(&envelope)
            .map_err(|error| error.context("validate session envelope"))?;
        self.tracker
            .accept(&envelope)
            .map_err(|error| error.context("accept session envelope"))?;
        Ok(Some(envelope))
    }

    pub fn send_ping(&mut self, now: Instant) -> eros::Result<u64> {
        let ping_id = format!("m-{}", self.next_seq);
        let seq = self.next_seq;
        if let Some(heartbeat) = self.resources.heartbeat.as_mut() {
            heartbeat.record_ping_sent(ping_id.clone(), seq, now);
        }
        self.send_with_id(
            ping_id,
            MessageType::Control(ControlMessageType::Ping),
            PingBody::new(),
            self.elapsed_ms(now),
        )?;
        Ok(seq)
    }

    pub fn handle_liveness(&mut self, ping: &MessageEnvelope<PingBody>) -> eros::Result<()> {
        let pong = PongBody::new(ping.id.clone(), Some(ping.seq))?;
        self.send_with_id(
            format!("m-{}", self.next_seq),
            MessageType::Control(ControlMessageType::Pong),
            pong,
            ping.timestamp_ms,
        )
    }

    pub fn on_pong(&mut self, pong: &MessageEnvelope<PongBody>, now: Instant) -> Option<RttSample> {
        self.resources
            .heartbeat
            .as_mut()
            .and_then(|heartbeat| heartbeat.record_pong(&pong.body, now))
    }

    pub fn disconnect(&mut self, trigger: DisconnectTrigger) -> eros::Result<SessionReleaseReport> {
        let report = self.resources.release(trigger, &mut self.state)?;
        self.transport = None;
        self.channel = None;
        Ok(report)
    }

    pub fn adopt_primary(
        &mut self,
        transport: Arc<dyn Transport>,
        channel: TransportChannel,
    ) -> eros::Result<()> {
        if self.state == SessionState::Closed {
            return Err(eros::error!(SessionError::Closed).context("adopt primary session channel"));
        }
        self.resources
            .channels
            .track(transport.clone(), channel.clone())?;
        self.transport = Some(transport);
        self.channel = Some(channel);
        Ok(())
    }

    pub fn last_sent_seq(&self) -> Option<u64> {
        self.next_seq.checked_sub(1)
    }

    pub fn last_received_seq(&self, channel: MessageChannel) -> Option<u64> {
        self.tracker.last_accepted(channel)
    }

    fn send_with_id<T: Serialize>(
        &mut self,
        id: String,
        message_type: MessageType,
        body: T,
        now_ms: u64,
    ) -> eros::Result<()> {
        if self.state == SessionState::Closed {
            return Err(eros::error!(SessionError::Closed).context("send session envelope"));
        }
        let seq = self.next_seq;
        let envelope =
            MessageEnvelope::new(id, message_type, self.session_id.clone(), seq, now_ms, body);

        let limits = ProtocolLimits::default();
        limits
            .validate_envelope(&envelope)
            .map_err(|error| error.context("validate session envelope"))?;
        let payload = serde_json::to_vec(&envelope)
            .map_err(|error| eros::error!(error).context("encode session envelope"))?;
        limits
            .validate_json_size(payload.len())
            .map_err(|error| error.context("encode session envelope"))?;

        let (Some(transport), Some(channel)) = (&self.transport, &self.channel) else {
            return Err(
                eros::error!(SessionError::ChannelNotAttached).context("send session envelope")
            );
        };
        transport
            .send(channel, payload)
            .map_err(|error| error.context("send session envelope"))?;
        self.next_seq = seq.saturating_add(1);
        Ok(())
    }

    fn receive_payload(&mut self) -> eros::Result<Option<Zeroizing<Vec<u8>>>> {
        let (Some(transport), Some(channel)) = (&self.transport, &self.channel) else {
            return Err(
                eros::error!(SessionError::ChannelNotAttached).context("receive session envelope")
            );
        };
        transport
            .receive(channel)
            .map_err(|error| error.context("receive session envelope"))
    }

    fn connect(&mut self) -> eros::Result<()> {
        if self.state == SessionState::Connected {
            return Ok(());
        }
        for next in CONNECT_PATH {
            if self.state == next {
                continue;
            }
            if !self.state.can_transition(next) {
                return Err(eros::error!(SessionError::InvalidTransition(
                    InvalidSessionTransition {
                        from: self.state,
                        to: next,
                    }
                ))
                .context("attach session channel"));
            }
            self.state = next;
        }
        if !self.state.can_transition(SessionState::Connected) {
            return Err(
                eros::error!(SessionError::InvalidTransition(InvalidSessionTransition {
                    from: self.state,
                    to: SessionState::Connected,
                }))
                .context("attach session channel"),
            );
        }
        self.state = SessionState::Connected;
        Ok(())
    }

    fn elapsed_ms(&self, now: Instant) -> u64 {
        now.saturating_duration_since(self.started_at).as_millis() as u64
    }
}

impl Debug for PeerSession {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PeerSession")
            .field("session_id", &self.session_id)
            .field("state", &self.state)
            .field("tracked", &self.resources.channels.tracked_channels())
            .field("open", &self.resources.channels.open_channels())
            .finish()
    }
}
