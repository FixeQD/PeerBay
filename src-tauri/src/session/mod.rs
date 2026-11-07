//! Peer-session boundary.

pub mod errors;
pub mod state;

pub use errors::SessionError;
pub use state::{InvalidSessionTransition, SessionState};
