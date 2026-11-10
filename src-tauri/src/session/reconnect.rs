use std::fmt::{Display, Formatter};
use std::time::Duration;

pub const MIN_INITIAL_DELAY: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconnectBackoffConfig {
    pub initial_delay: Duration,
    pub multiplier: u32,
    pub max_delay: Duration,
    pub max_attempts: u32,
}

impl ReconnectBackoffConfig {
    pub const fn new(
        initial_delay: Duration,
        multiplier: u32,
        max_delay: Duration,
        max_attempts: u32,
    ) -> Self {
        Self {
            initial_delay,
            multiplier,
            max_delay,
            max_attempts,
        }
    }

    pub fn validate(&self) -> Result<(), ReconnectConfigError> {
        if self.max_attempts == 0 {
            return Err(ReconnectConfigError::ZeroMaxAttempts);
        }
        if self.multiplier == 0 {
            return Err(ReconnectConfigError::ZeroMultiplier);
        }
        if self.initial_delay < MIN_INITIAL_DELAY {
            return Err(ReconnectConfigError::InitialDelayTooShort {
                got: self.initial_delay,
                min: MIN_INITIAL_DELAY,
            });
        }
        if self.max_delay < self.initial_delay {
            return Err(ReconnectConfigError::MaxDelayBelowInitial {
                initial: self.initial_delay,
                max: self.max_delay,
            });
        }

        Ok(())
    }
}

impl Default for ReconnectBackoffConfig {
    fn default() -> Self {
        Self {
            initial_delay: Duration::from_millis(500),
            multiplier: 2,
            max_delay: Duration::from_secs(30),
            max_attempts: 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconnectConfigError {
    ZeroMaxAttempts,
    ZeroMultiplier,
    InitialDelayTooShort { got: Duration, min: Duration },
    MaxDelayBelowInitial { initial: Duration, max: Duration },
}

impl Display for ReconnectConfigError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMaxAttempts => write!(formatter, "reconnect max_attempts must be at least 1"),
            Self::ZeroMultiplier => write!(formatter, "reconnect multiplier must be at least 1"),
            Self::InitialDelayTooShort { got, min } => write!(
                formatter,
                "reconnect initial_delay {got:?} is below the minimum {min:?}"
            ),
            Self::MaxDelayBelowInitial { initial, max } => write!(
                formatter,
                "reconnect max_delay {max:?} is below initial_delay {initial:?}"
            ),
        }
    }
}

impl std::error::Error for ReconnectConfigError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReconnectDecision {
    Retry { attempt: u32, delay: Duration },
    GiveUp { attempts: u32 },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconnectBackoff {
    config: ReconnectBackoffConfig,
    attempts: u32,
    next_delay: Duration,
}

impl ReconnectBackoff {
    pub fn try_new(config: ReconnectBackoffConfig) -> eros::Result<Self> {
        config
            .validate()
            .map_err(|error| eros::error!(error).context("validate reconnect backoff config"))?;

        Ok(Self {
            config,
            attempts: 0,
            next_delay: config.initial_delay,
        })
    }

    pub fn config(&self) -> ReconnectBackoffConfig {
        self.config
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn is_exhausted(&self) -> bool {
        self.attempts >= self.config.max_attempts
    }

    pub fn reset(&mut self) {
        self.attempts = 0;
        self.next_delay = self.config.initial_delay;
    }

    pub fn next_decision(&mut self) -> ReconnectDecision {
        self.next_decision_with_jitter(|delay| delay)
    }

    pub fn next_decision_with_jitter(
        &mut self,
        jitter: impl FnOnce(Duration) -> Duration,
    ) -> ReconnectDecision {
        if self.is_exhausted() {
            return ReconnectDecision::GiveUp {
                attempts: self.attempts,
            };
        }

        self.attempts += 1;
        let base = self.next_delay;
        self.next_delay = base
            .saturating_mul(self.config.multiplier)
            .min(self.config.max_delay);

        ReconnectDecision::Retry {
            attempt: self.attempts,
            delay: jitter(base).min(self.config.max_delay),
        }
    }
}
