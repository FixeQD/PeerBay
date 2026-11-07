//! Peer-session boundary.

pub mod errors;
pub mod router;
pub mod state;

pub use errors::SessionError;
pub use router::{RouteDisposition, RoutedMessage, SessionMessageHandler, SessionRouter};
pub use state::{InvalidSessionTransition, SessionState};
