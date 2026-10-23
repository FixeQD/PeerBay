//! Target-neutral description of the platform adapter boundary.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PlatformTarget {
    Linux,
    Windows,
    Android,
    Unsupported,
}

impl PlatformTarget {
    pub(crate) const fn current() -> Self {
        if cfg!(target_os = "linux") {
            Self::Linux
        } else if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "android") {
            Self::Android
        } else {
            Self::Unsupported
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PlatformDescriptor {
    target: PlatformTarget,
}

impl PlatformDescriptor {
    pub(crate) const fn current() -> Self {
        Self {
            target: PlatformTarget::current(),
        }
    }

    #[cfg(test)]
    pub(crate) const fn target(self) -> PlatformTarget {
        self.target
    }
}

#[cfg(test)]
mod tests {
    use super::{PlatformDescriptor, PlatformTarget};

    #[test]
    fn descriptor_matches_compilation_target() {
        let expected = if cfg!(target_os = "linux") {
            PlatformTarget::Linux
        } else if cfg!(target_os = "windows") {
            PlatformTarget::Windows
        } else if cfg!(target_os = "android") {
            PlatformTarget::Android
        } else {
            PlatformTarget::Unsupported
        };

        assert_eq!(PlatformDescriptor::current().target(), expected);
    }
}
