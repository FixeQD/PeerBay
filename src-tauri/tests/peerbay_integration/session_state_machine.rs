use peerbay_lib::session::{InvalidSessionTransition, SessionError, SessionState};

#[test]
fn session_starts_disconnected_and_follows_connect_path() {
    let mut state = SessionState::Disconnected;

    for next in [
        SessionState::ResolvingPeer,
        SessionState::OpeningTransport,
        SessionState::Authenticating,
        SessionState::NegotiatingCapabilities,
        SessionState::Connected,
    ] {
        assert!(
            state.can_transition(next),
            "{state:?} should allow {next:?}"
        );
        state = next;
    }

    assert!(state.is_active());
    assert!(!state.is_terminal());
}

#[test]
fn session_allows_degraded_connected_migration_and_reconnect_paths() {
    assert!(SessionState::NegotiatingCapabilities.can_transition(SessionState::Degraded));
    assert!(SessionState::Connected.can_transition(SessionState::Degraded));
    assert!(SessionState::Connected.can_transition(SessionState::MigratingTransport));
    assert!(SessionState::MigratingTransport.can_transition(SessionState::Connected));
    assert!(SessionState::MigratingTransport.can_transition(SessionState::Degraded));
    assert!(SessionState::Degraded.can_transition(SessionState::Connected));
    assert!(SessionState::Degraded.can_transition(SessionState::Reconnecting));
    assert!(SessionState::Connected.can_transition(SessionState::Reconnecting));
    assert!(SessionState::Reconnecting.can_transition(SessionState::ResolvingPeer));
    assert!(SessionState::Reconnecting.can_transition(SessionState::Connected));
    assert!(SessionState::Reconnecting.can_transition(SessionState::Degraded));
}

#[test]
fn session_can_be_released_or_closed_from_active_states() {
    for state in [
        SessionState::Connected,
        SessionState::MigratingTransport,
        SessionState::Degraded,
        SessionState::Reconnecting,
    ] {
        assert!(state.can_transition(SessionState::Released));
        assert!(state.can_transition(SessionState::Closed));
    }

    assert!(SessionState::Released.can_transition(SessionState::Closed));
    assert!(SessionState::Closed.is_terminal());
}

#[test]
fn session_rejects_invalid_and_terminal_transitions() {
    assert!(!SessionState::Disconnected.can_transition(SessionState::Connected));
    assert!(!SessionState::Authenticating.can_transition(SessionState::Connected));
    assert!(!SessionState::Connected.can_transition(SessionState::Disconnected));
    assert!(!SessionState::Closed.can_transition(SessionState::Disconnected));
    assert!(!SessionState::Released.can_transition(SessionState::Connected));
    assert!(!SessionState::Connected.can_transition(SessionState::Connected));
}

#[test]
fn session_error_wraps_invalid_transition() {
    let invalid = InvalidSessionTransition {
        from: SessionState::Disconnected,
        to: SessionState::Connected,
    };
    let error = SessionError::from(invalid);

    assert_eq!(
        error.to_string(),
        "invalid session transition: disconnected -> connected"
    );
}

#[test]
fn session_state_wire_names_are_stable() {
    assert_eq!(SessionState::Disconnected.as_str(), "disconnected");
    assert_eq!(SessionState::ResolvingPeer.as_str(), "resolving_peer");
    assert_eq!(SessionState::OpeningTransport.as_str(), "opening_transport");
    assert_eq!(SessionState::Authenticating.as_str(), "authenticating");
    assert_eq!(
        SessionState::NegotiatingCapabilities.as_str(),
        "negotiating_capabilities"
    );
    assert_eq!(SessionState::Connected.as_str(), "connected");
    assert_eq!(
        SessionState::MigratingTransport.as_str(),
        "migrating_transport"
    );
    assert_eq!(SessionState::Degraded.as_str(), "degraded");
    assert_eq!(SessionState::Reconnecting.as_str(), "reconnecting");
    assert_eq!(SessionState::Released.as_str(), "released");
    assert_eq!(SessionState::Closed.as_str(), "closed");
}
