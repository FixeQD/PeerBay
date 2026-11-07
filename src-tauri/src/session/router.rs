use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::protocol::{MessageChannel, MessageEnvelope, MessageType, ProtocolLimits};

use super::SessionError;

struct RegisteredHandler {
    domain: MessageChannel,
    handler: Arc<dyn SessionMessageHandler>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutedMessage {
    pub domain: MessageChannel,
    pub message_type: MessageType,
    pub session_id: String,
    pub message_id: String,
    pub sequence: u64,
}

impl RoutedMessage {
    pub fn from_envelope(envelope: &MessageEnvelope<Value>) -> Self {
        Self {
            domain: envelope.message_type.channel(),
            message_type: envelope.message_type.clone(),
            session_id: envelope.session_id.clone(),
            message_id: envelope.id.clone(),
            sequence: envelope.seq,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDisposition {
    Handled(MessageChannel),
    IgnoredUnknown,
    Unhandled(MessageChannel),
}

pub trait SessionMessageHandler: Send + Sync {
    fn domain(&self) -> MessageChannel;
    fn handle(&self, message: &RoutedMessage, body: &Value) -> eros::Result<()>;
}

#[derive(Default)]
pub struct SessionRouter {
    handlers: HashMap<MessageChannel, RegisteredHandler>,
}

impl SessionRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, handler: Arc<dyn SessionMessageHandler>) -> eros::Result<()> {
        let domain = handler.domain();
        if domain == MessageChannel::Unknown {
            return Err(eros::error!(SessionError::UnsupportedDomain { domain })
                .context("register session message handler"));
        }

        if self.handlers.contains_key(&domain) {
            return Err(
                eros::error!(SessionError::HandlerAlreadyRegistered { domain })
                    .context("register session message handler"),
            );
        }

        self.handlers
            .insert(domain, RegisteredHandler { domain, handler });
        Ok(())
    }

    pub fn replace(&mut self, handler: Arc<dyn SessionMessageHandler>) {
        let domain = handler.domain();
        if domain == MessageChannel::Unknown {
            return;
        }

        self.handlers
            .insert(domain, RegisteredHandler { domain, handler });
    }

    pub fn route(&self, envelope: &MessageEnvelope<Value>) -> eros::Result<RouteDisposition> {
        ProtocolLimits::default().validate_envelope(envelope)?;

        let message = RoutedMessage::from_envelope(envelope);

        if message.domain == MessageChannel::Unknown {
            return Ok(RouteDisposition::IgnoredUnknown);
        }

        let Some(registered) = self.handlers.get(&message.domain) else {
            return Ok(RouteDisposition::Unhandled(message.domain));
        };

        if registered.domain != message.domain {
            return Err(eros::error!(SessionError::HandlerDomainMismatch {
                expected: message.domain,
                got: registered.domain,
            })
            .context("dispatch session message"));
        }

        registered
            .handler
            .handle(&message, &envelope.body)
            .map_err(|error| error.context("session message handler failed"))?;
        Ok(RouteDisposition::Handled(message.domain))
    }

    pub fn has_handler(&self, domain: MessageChannel) -> bool {
        self.handlers.contains_key(&domain)
    }
}
