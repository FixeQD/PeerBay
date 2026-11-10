//! Peer-session boundary.

pub mod errors;
pub mod heartbeat;
pub mod reconnect;
pub mod router;
pub mod state;

pub use errors::SessionError;
pub use heartbeat::{Heartbeat, HeartbeatConfig, LivenessStatus, RttSample};
pub use reconnect::{
    ReconnectBackoff, ReconnectBackoffConfig, ReconnectConfigError, ReconnectDecision,
};
pub use router::{RouteDisposition, RoutedMessage, SessionMessageHandler, SessionRouter};
pub use state::{InvalidSessionTransition, SessionState};
