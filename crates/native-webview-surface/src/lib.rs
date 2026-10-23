//! Native WebView and media-surface lifecycle boundary.

use std::fmt::{Display, Formatter};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceId(u64);

impl SurfaceId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bounds {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

impl Bounds {
    pub const fn new(x: i32, y: i32, width: u32, height: u32) -> Self {
        Self {
            x,
            y,
            width,
            height,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SurfaceDescriptor {
    pub id: SurfaceId,
    pub bounds: Bounds,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceState {
    Created,
    Visible,
    Hidden,
    Destroyed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceCommand {
    Show,
    Hide,
    Resize(Bounds),
    Destroy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SurfaceError {
    InvalidTransition {
        state: SurfaceState,
        command: SurfaceCommand,
    },
}

impl Display for SurfaceError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidTransition { state, command } => {
                write!(
                    formatter,
                    "cannot apply {command:?} while surface is {state:?}"
                )
            }
        }
    }
}

impl std::error::Error for SurfaceError {}

pub struct SurfaceLifecycle {
    descriptor: SurfaceDescriptor,
    state: SurfaceState,
}

impl SurfaceLifecycle {
    pub const fn new(descriptor: SurfaceDescriptor) -> Self {
        Self {
            descriptor,
            state: SurfaceState::Created,
        }
    }

    pub const fn descriptor(&self) -> SurfaceDescriptor {
        self.descriptor
    }

    pub const fn state(&self) -> SurfaceState {
        self.state
    }

    pub fn apply(&mut self, command: SurfaceCommand) -> Result<(), SurfaceError> {
        match (self.state, command) {
            (SurfaceState::Created, SurfaceCommand::Show)
            | (SurfaceState::Hidden, SurfaceCommand::Show) => {
                self.state = SurfaceState::Visible;
            }
            (SurfaceState::Created, SurfaceCommand::Hide)
            | (SurfaceState::Visible, SurfaceCommand::Hide) => {
                self.state = SurfaceState::Hidden;
            }
            (
                SurfaceState::Created | SurfaceState::Visible | SurfaceState::Hidden,
                SurfaceCommand::Resize(bounds),
            ) => {
                self.descriptor.bounds = bounds;
            }
            (
                SurfaceState::Created | SurfaceState::Visible | SurfaceState::Hidden,
                SurfaceCommand::Destroy,
            ) => {
                self.state = SurfaceState::Destroyed;
            }
            _ => {
                return Err(SurfaceError::InvalidTransition {
                    state: self.state,
                    command,
                });
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifecycle_supports_backend_independent_surface_commands() {
        let descriptor = SurfaceDescriptor {
            id: SurfaceId::new(7),
            bounds: Bounds::new(0, 0, 800, 600),
        };
        let mut lifecycle = SurfaceLifecycle::new(descriptor);

        lifecycle
            .apply(SurfaceCommand::Show)
            .expect("surface should show");
        lifecycle
            .apply(SurfaceCommand::Resize(Bounds::new(10, 20, 640, 480)))
            .expect("surface should resize");
        lifecycle
            .apply(SurfaceCommand::Hide)
            .expect("surface should hide");
        lifecycle
            .apply(SurfaceCommand::Destroy)
            .expect("surface should destroy");

        assert_eq!(lifecycle.state(), SurfaceState::Destroyed);
        assert_eq!(lifecycle.descriptor().id.get(), 7);
    }

    #[test]
    fn destroyed_surface_rejects_new_commands() {
        let descriptor = SurfaceDescriptor {
            id: SurfaceId::new(1),
            bounds: Bounds::new(0, 0, 1, 1),
        };
        let mut lifecycle = SurfaceLifecycle::new(descriptor);
        lifecycle
            .apply(SurfaceCommand::Destroy)
            .expect("destroy should work");

        assert!(lifecycle.apply(SurfaceCommand::Show).is_err());
    }
}
