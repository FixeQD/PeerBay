use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleState {
    Created,
    LoadingIdentity,
    LoadingStore,
    StartingPlatform,
    StartingDiscovery,
    Ready,
    ShuttingDown,
    Stopped,
}

impl LifecycleState {
    pub fn can_transition(self, next: Self) -> bool {
        matches!(
            (self, next),
            (Self::Created, Self::LoadingIdentity | Self::ShuttingDown)
                | (
                    Self::LoadingIdentity,
                    Self::LoadingStore | Self::ShuttingDown
                )
                | (
                    Self::LoadingStore,
                    Self::StartingPlatform | Self::ShuttingDown
                )
                | (
                    Self::StartingPlatform,
                    Self::StartingDiscovery | Self::ShuttingDown
                )
                | (Self::StartingDiscovery, Self::Ready | Self::ShuttingDown)
                | (Self::Ready, Self::ShuttingDown)
                | (Self::ShuttingDown, Self::Stopped)
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidTransition {
    pub from: LifecycleState,
    pub to: LifecycleState,
}

impl Display for InvalidTransition {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "invalid application lifecycle transition: {:?} -> {:?}",
            self.from, self.to
        )
    }
}

impl std::error::Error for InvalidTransition {}
