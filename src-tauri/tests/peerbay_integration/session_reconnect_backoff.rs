use std::time::Duration;

use peerbay_lib::session::reconnect::{MIN_INITIAL_DELAY, ReconnectConfigError};
use peerbay_lib::session::{ReconnectBackoff, ReconnectBackoffConfig, ReconnectDecision};

fn backoff(
    initial_ms: u64,
    multiplier: u32,
    max_delay: Duration,
    max_attempts: u32,
) -> ReconnectBackoff {
    ReconnectBackoff::try_new(ReconnectBackoffConfig::new(
        Duration::from_millis(initial_ms),
        multiplier,
        max_delay,
        max_attempts,
    ))
    .expect("valid reconnect config")
}

fn retry(attempt: u32, delay: Duration) -> ReconnectDecision {
    ReconnectDecision::Retry { attempt, delay }
}

#[test]
fn reconnect_backoff_grows_exponentially_until_max_delay() {
    let mut backoff = backoff(100, 2, Duration::from_secs(1), 6);

    for (attempt, delay_ms) in [(1, 100), (2, 200), (3, 400), (4, 800), (5, 1000), (6, 1000)] {
        assert_eq!(
            backoff.next_decision(),
            retry(attempt, Duration::from_millis(delay_ms))
        );
    }
}

#[test]
fn reconnect_backoff_stops_after_max_attempts_and_stays_given_up() {
    let mut backoff = backoff(50, 2, Duration::from_secs(1), 3);

    for attempt in 1..=3 {
        assert!(matches!(
            backoff.next_decision(),
            ReconnectDecision::Retry { attempt: got, .. } if got == attempt
        ));
    }
    assert!(backoff.is_exhausted());

    for _ in 0..3 {
        assert_eq!(
            backoff.next_decision(),
            ReconnectDecision::GiveUp { attempts: 3 }
        );
    }
    assert_eq!(backoff.attempts(), 3);
}

#[test]
fn reconnect_backoff_allows_single_attempt() {
    let mut backoff = backoff(100, 2, Duration::from_secs(1), 1);

    assert_eq!(
        backoff.next_decision(),
        retry(1, Duration::from_millis(100))
    );
    assert_eq!(
        backoff.next_decision(),
        ReconnectDecision::GiveUp { attempts: 1 }
    );
}

#[test]
fn reconnect_backoff_with_multiplier_one_keeps_constant_delay() {
    let mut backoff = backoff(100, 1, Duration::from_secs(1), 3);

    for attempt in 1..=3 {
        assert_eq!(
            backoff.next_decision(),
            retry(attempt, Duration::from_millis(100))
        );
    }
}

#[test]
fn reconnect_backoff_saturates_instead_of_overflowing() {
    let mut backoff = backoff(100, u32::MAX, Duration::MAX, 4);

    assert_eq!(
        backoff.next_decision(),
        retry(1, Duration::from_millis(100))
    );
    for _ in 0..3 {
        assert!(matches!(
            backoff.next_decision(),
            ReconnectDecision::Retry { .. }
        ));
    }
    assert!(backoff.is_exhausted());
}

#[test]
fn reconnect_backoff_resets_to_initial_delay_and_attempts() {
    let mut backoff = backoff(100, 2, Duration::from_secs(5), 3);

    let _ = backoff.next_decision();
    let _ = backoff.next_decision();
    assert_eq!(
        backoff.next_decision(),
        retry(3, Duration::from_millis(400))
    );
    assert!(backoff.is_exhausted());

    backoff.reset();
    assert_eq!(backoff.attempts(), 0);
    assert!(!backoff.is_exhausted());
    assert_eq!(
        backoff.next_decision(),
        retry(1, Duration::from_millis(100))
    );
}

#[test]
fn reconnect_backoff_jitter_adjusts_delay_without_changing_schedule() {
    let mut backoff = backoff(100, 2, Duration::from_secs(1), 4);

    assert_eq!(
        backoff.next_decision_with_jitter(|delay| delay / 2),
        retry(1, Duration::from_millis(50))
    );
    assert_eq!(
        backoff.next_decision(),
        retry(2, Duration::from_millis(200))
    );
}

#[test]
fn reconnect_backoff_caps_jittered_delay_at_max_delay() {
    let mut backoff = backoff(100, 2, Duration::from_secs(1), 2);

    assert_eq!(
        backoff.next_decision_with_jitter(|delay| delay * 100),
        retry(1, Duration::from_secs(1))
    );
}

#[test]
fn reconnect_backoff_rejects_invalid_config() {
    let valid = ReconnectBackoffConfig::default();
    assert!(ReconnectBackoff::try_new(valid).is_ok());

    let cases = [
        (
            ReconnectBackoffConfig {
                max_attempts: 0,
                ..valid
            },
            ReconnectConfigError::ZeroMaxAttempts,
        ),
        (
            ReconnectBackoffConfig {
                multiplier: 0,
                ..valid
            },
            ReconnectConfigError::ZeroMultiplier,
        ),
        (
            ReconnectBackoffConfig {
                initial_delay: Duration::ZERO,
                ..valid
            },
            ReconnectConfigError::InitialDelayTooShort {
                got: Duration::ZERO,
                min: MIN_INITIAL_DELAY,
            },
        ),
        (
            ReconnectBackoffConfig {
                initial_delay: Duration::from_secs(10),
                max_delay: Duration::from_secs(1),
                ..valid
            },
            ReconnectConfigError::MaxDelayBelowInitial {
                initial: Duration::from_secs(10),
                max: Duration::from_secs(1),
            },
        ),
    ];

    for (config, expected) in cases {
        assert_eq!(config.validate(), Err(expected));
        assert!(ReconnectBackoff::try_new(config).is_err());
    }
}

#[test]
fn reconnect_backoff_default_config_is_valid_and_bounded() {
    let config = ReconnectBackoffConfig::default();

    assert_eq!(config.initial_delay, Duration::from_millis(500));
    assert_eq!(config.multiplier, 2);
    assert_eq!(config.max_delay, Duration::from_secs(30));
    assert_eq!(config.max_attempts, 8);
    assert_eq!(config.validate(), Ok(()));
}
