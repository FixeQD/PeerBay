//! Flaky transport double that simulates delay, drop, reorder, duplication and limited bandwidth.

pub use config::FlakyConfig;
pub use errors::FlakyTransportError;
pub use transport::FlakyTransport;

pub mod config;
pub mod errors;
pub mod transport;
