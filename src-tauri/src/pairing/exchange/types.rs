#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingRole {
    Initiator,
    Responder,
}

impl PairingRole {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairingExchangeState {
    Idle,
    Started,
    Committed,
    Revealing,
    Revealed,
    Completed,
    Rejected,
    Cancelled,
    TimedOut,
}

impl PairingExchangeState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Started => "started",
            Self::Committed => "committed",
            Self::Revealing => "revealing",
            Self::Revealed => "revealed",
            Self::Completed => "completed",
            Self::Rejected => "rejected",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
        }
    }
}

#[derive(PartialEq, Eq)]
pub struct PairingSas {
    pub code: String,
    pub initiator_nonce_hex: String,
    pub responder_nonce_hex: String,
}

impl std::fmt::Debug for PairingSas {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairingSas")
            .field("code", &self.code)
            .field("initiator_nonce_hex", &"<redacted>")
            .field("responder_nonce_hex", &"<redacted>")
            .finish()
    }
}
