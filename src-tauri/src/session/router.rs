use std::collections::HashMap;
use std::sync::Arc;

use serde_json::Value;

use crate::messages::{AppChannel, AppMessageType};
use proto::{MessageEnvelope, MessageType, ProtocolLimits};

use super::SessionError;

struct RegisteredHandler {
    domain: AppChannel,
    handler: Arc<dyn SessionMessageHandler>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutedMessage {
    pub domain: AppChannel,
    pub message_type: MessageType,
    pub session_id: String,
    pub message_id: String,
    pub sequence: u64,
}

impl RoutedMessage {
    pub fn from_envelope(envelope: &MessageEnvelope<Value>) -> Self {
        Self {
            domain: match &envelope.message_type {
                MessageType::Control(_) => AppChannel::Control,
                MessageType::Unknown(_) => {
                    AppMessageType::from_wire(envelope.message_type.as_str())
                        .map(AppMessageType::channel)
                        .unwrap_or(AppChannel::Unknown)
                }
            },
            message_type: envelope.message_type.clone(),
            session_id: envelope.session_id.clone(),
            message_id: envelope.id.clone(),
            sequence: envelope.seq,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteDisposition {
    Handled(AppChannel),
    IgnoredUnknown,
    Unhandled(AppChannel),
}

pub trait SessionMessageHandler: Send + Sync {
    fn domain(&self) -> AppChannel;
    fn handle(&self, message: &RoutedMessage, body: &Value) -> eros::Result<()>;
}

#[derive(Default)]
pub struct SessionRouter {
    handlers: HashMap<AppChannel, RegisteredHandler>,
}

impl SessionRouter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, handler: Arc<dyn SessionMessageHandler>) -> eros::Result<()> {
        let domain = handler.domain();
        if domain == AppChannel::Unknown {
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
        if domain == AppChannel::Unknown {
            return;
        }

        self.handlers
            .insert(domain, RegisteredHandler { domain, handler });
    }

    pub fn route(&self, envelope: &MessageEnvelope<Value>) -> eros::Result<RouteDisposition> {
        ProtocolLimits::default().validate_envelope(envelope)?;

        let message = RoutedMessage::from_envelope(envelope);

        if message.domain == AppChannel::Unknown {
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

    pub fn has_handler(&self, domain: AppChannel) -> bool {
        self.handlers.contains_key(&domain)
    }
}
