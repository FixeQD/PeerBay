use std::fmt::{Display, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub enum StorageDirectoryError {
    EmptyRoot { kind: &'static str },
    RelativeRoot { kind: &'static str },
    ParentTraversal { kind: &'static str },
    PlatformPathUnavailable { kind: &'static str },
    CreateDirectoryFailed { kind: &'static str },
    PathIsNotDirectory { kind: &'static str },
    PathIsSymlink { kind: &'static str },
    InvalidPeerId,
}

impl Display for StorageDirectoryError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyRoot { kind } => write!(formatter, "{kind} storage root is empty"),
            Self::RelativeRoot { kind } => write!(formatter, "{kind} storage root is not absolute"),
            Self::ParentTraversal { kind } => {
                write!(formatter, "{kind} storage root contains parent traversal")
            }
            Self::PlatformPathUnavailable { kind } => {
                write!(formatter, "platform path unavailable for {kind} storage")
            }
            Self::CreateDirectoryFailed { kind } => {
                write!(formatter, "could not create {kind} storage directory")
            }
            Self::PathIsNotDirectory { kind } => {
                write!(formatter, "{kind} storage path is not a directory")
            }
            Self::PathIsSymlink { kind } => {
                write!(formatter, "{kind} storage path must not be a symlink")
            }
            Self::InvalidPeerId => write!(formatter, "peer storage identifier is invalid"),
        }
    }
}

impl std::error::Error for StorageDirectoryError {}
