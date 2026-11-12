//! Peer-session boundary.

pub mod errors;
pub mod heartbeat;
pub mod migration;
pub mod reconnect;
pub mod release;
pub mod router;
pub mod state;

pub use errors::SessionError;
pub use heartbeat::{Heartbeat, HeartbeatConfig, LivenessStatus, RttSample};
pub use migration::{
    ChannelSeqSnapshot, MigrationConfig, MigrationConfigError, MigrationError, MigrationFailure,
    MigrationPhase, MigrationPlan, MigrationRouteState, MigrationTeardownSummary,
    ResumeAcceptOutcome, ResumeKeyStore, SessionResumeOutcome, TransportMigrationInitiator,
    TransportMigrationResponder,
};
pub use reconnect::{
    ReconnectBackoff, ReconnectBackoffConfig, ReconnectConfigError, ReconnectDecision,
};
pub use release::{
    ALL_TRIGGERS, ChannelReleaseSummary, DisconnectTrigger, MAX_TRACKED_CHANNELS, ReleaseError,
    SessionChannelLedger, SessionReleaseReport, SessionResources,
};
pub use router::{RouteDisposition, RoutedMessage, SessionMessageHandler, SessionRouter};
pub use state::{InvalidSessionTransition, SessionState};
