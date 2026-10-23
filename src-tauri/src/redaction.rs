//! Boundary for removing secrets and private data before view-model emission.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RedactionPolicy {
    allow_private_paths: bool,
    allow_private_payloads: bool,
}

impl RedactionPolicy {
    pub(crate) const fn privacy_safe() -> Self {
        Self {
            allow_private_paths: false,
            allow_private_payloads: false,
        }
    }

    #[cfg(test)]
    pub(crate) const fn is_privacy_safe(self) -> bool {
        !self.allow_private_paths && !self.allow_private_payloads
    }
}

impl Default for RedactionPolicy {
    fn default() -> Self {
        Self::privacy_safe()
    }
}
