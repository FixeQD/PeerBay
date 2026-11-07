use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SessionState {
    Disconnected,
    ResolvingPeer,
    OpeningTransport,
    Authenticating,
    NegotiatingCapabilities,
    Connected,
    MigratingTransport,
    Degraded,
    Reconnecting,
    Released,
    Closed,
}

impl SessionState {
    pub fn can_transition(self, next: Self) -> bool {
        if self == next {
            return false;
        }

        matches!(
            (self, next),
            (Self::Disconnected, Self::ResolvingPeer | Self::Closed)
                | (
                    Self::ResolvingPeer,
                    Self::OpeningTransport | Self::Disconnected | Self::Released | Self::Closed
                )
                | (
                    Self::OpeningTransport,
                    Self::Authenticating
                        | Self::ResolvingPeer
                        | Self::Reconnecting
                        | Self::Disconnected
                        | Self::Released
                        | Self::Closed
                )
                | (
                    Self::Authenticating,
                    Self::NegotiatingCapabilities
                        | Self::OpeningTransport
                        | Self::Reconnecting
                        | Self::Disconnected
                        | Self::Released
                        | Self::Closed
                )
                | (
                    Self::NegotiatingCapabilities,
                    Self::Connected
                        | Self::Degraded
                        | Self::Reconnecting
                        | Self::Disconnected
                        | Self::Released
                        | Self::Closed
                )
                | (
                    Self::Connected,
                    Self::MigratingTransport
                        | Self::Degraded
                        | Self::Reconnecting
                        | Self::Released
                        | Self::Closed
                )
                | (
                    Self::MigratingTransport,
                    Self::Connected
                        | Self::Degraded
                        | Self::Reconnecting
                        | Self::Released
                        | Self::Closed
                )
                | (
                    Self::Degraded,
                    Self::Connected
                        | Self::MigratingTransport
                        | Self::Reconnecting
                        | Self::Released
                        | Self::Closed
                )
                | (
                    Self::Reconnecting,
                    Self::ResolvingPeer
                        | Self::OpeningTransport
                        | Self::Authenticating
                        | Self::NegotiatingCapabilities
                        | Self::Connected
                        | Self::Degraded
                        | Self::Disconnected
                        | Self::Released
                        | Self::Closed
                )
                | (Self::Released, Self::Closed)
        )
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Closed)
    }

    pub const fn is_active(self) -> bool {
        matches!(
            self,
            Self::Connected | Self::MigratingTransport | Self::Degraded
        )
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Disconnected => "disconnected",
            Self::ResolvingPeer => "resolving_peer",
            Self::OpeningTransport => "opening_transport",
            Self::Authenticating => "authenticating",
            Self::NegotiatingCapabilities => "negotiating_capabilities",
            Self::Connected => "connected",
            Self::MigratingTransport => "migrating_transport",
            Self::Degraded => "degraded",
            Self::Reconnecting => "reconnecting",
            Self::Released => "released",
            Self::Closed => "closed",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSessionTransition {
    pub from: SessionState,
    pub to: SessionState,
}

impl Display for InvalidSessionTransition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid session transition: {} -> {}",
            self.from.as_str(),
            self.to.as_str()
        )
    }
}

impl std::error::Error for InvalidSessionTransition {}
