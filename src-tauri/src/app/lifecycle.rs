use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LifecycleState {
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
    pub(crate) fn can_transition(self, next: Self) -> bool {
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
pub(crate) struct InvalidTransition {
    pub(crate) from: LifecycleState,
    pub(crate) to: LifecycleState,
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
