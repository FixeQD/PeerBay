use super::{ChannelKind, TransportKind, errors::validate_transport_identifier};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportChannel {
    id: String,
    transport: TransportKind,
    kind: ChannelKind,
}

impl TransportChannel {
    pub fn new(
        id: impl Into<String>,
        transport: TransportKind,
        kind: ChannelKind,
    ) -> eros::Result<Self> {
        let channel = Self {
            id: id.into(),
            transport,
            kind,
        };
        channel.validate()?;
        Ok(channel)
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub const fn transport(&self) -> TransportKind {
        self.transport
    }

    pub const fn kind(&self) -> ChannelKind {
        self.kind
    }

    fn validate(&self) -> eros::Result<()> {
        validate_transport_identifier("channel_id", &self.id)
    }
}
