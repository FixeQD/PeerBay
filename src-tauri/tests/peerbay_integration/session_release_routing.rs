use peerbay_lib::session::SessionState;
use peerbay_lib::session::{ALL_TRIGGERS, DisconnectTrigger, ReleaseError};

fn routing_rule(trigger: DisconnectTrigger, current: SessionState) -> SessionState {
    if trigger.is_terminal() {
        return SessionState::Released;
    }
    if current.is_active() || current == SessionState::Reconnecting {
        return SessionState::Reconnecting;
    }
    SessionState::Disconnected
}

#[test]
fn release_routing_matches_state_machine_for_every_state_and_trigger() {
    let states = [
        SessionState::Disconnected,
        SessionState::ResolvingPeer,
        SessionState::OpeningTransport,
        SessionState::Authenticating,
        SessionState::NegotiatingCapabilities,
        SessionState::Connected,
        SessionState::MigratingTransport,
        SessionState::Degraded,
        SessionState::Reconnecting,
        SessionState::Released,
    ];

    for current in states {
        for trigger in ALL_TRIGGERS {
            let target = trigger
                .release_state(current)
                .expect("non-closed states always route");

            if target == current {
                assert!(
                    current == SessionState::Released
                        || (!trigger.is_terminal()
                            && matches!(
                                current,
                                SessionState::Disconnected | SessionState::Reconnecting
                            )),
                    "same-state routing is only expected for Released and reconnectable triggers in Disconnected/Reconnecting"
                );
                continue;
            }

            assert!(
                current.can_transition(target),
                "routing {current:?} + {trigger:?} must produce a legal transition, got {target:?}"
            );
            assert_eq!(
                target,
                routing_rule(trigger, current),
                "routing {current:?} + {trigger:?} must follow the trigger mapping"
            );
        }
    }
}

#[test]
fn release_state_refuses_closed_sessions() {
    for trigger in ALL_TRIGGERS {
        let error = trigger
            .release_state(SessionState::Closed)
            .expect_err("a closed session cannot be released again");
        assert!(
            matches!(
                error.downcast_inner::<ReleaseError>(),
                Ok(ReleaseError::SessionAlreadyClosed)
            ),
            "closed sessions must fail with SessionAlreadyClosed"
        );
    }
}

#[test]
fn trigger_labels_and_terminal_flags_match_the_plan() {
    let expected = [
        ("trust_revoked", true),
        ("policy_revoked", false),
        ("session_timeout", false),
        ("heartbeat_lost", false),
        ("protocol_violation", true),
        ("backend_shutdown", true),
        ("platform_service_stopped", false),
        ("peer_released", true),
    ];
    assert_eq!(ALL_TRIGGERS.len(), expected.len());

    for (trigger, (label, terminal)) in ALL_TRIGGERS.iter().zip(expected) {
        assert_eq!(trigger.as_str(), label);
        assert_eq!(trigger.is_terminal(), terminal);
    }
}
