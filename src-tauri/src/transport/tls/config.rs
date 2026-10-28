#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsTransportConfig {
    pub max_message_size: usize,
}

impl Default for TlsTransportConfig {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024,
        }
    }
}

impl TlsTransportConfig {
    pub fn new(max_message_size: usize) -> Self {
        Self { max_message_size }
    }

    const MAX: usize = 16 * 1024 * 1024;
    pub fn validate(&self) -> eros::Result<()> {
        if self.max_message_size == 0 {
            return Err(eros::error!(
                super::errors::TlsTransportError::MessageTooLarge { length: 0, max: 0 }
            ));
        }
        if self.max_message_size > Self::MAX {
            return Err(eros::error!(
                super::errors::TlsTransportError::MessageTooLarge {
                    length: self.max_message_size,
                    max: Self::MAX,
                }
            ));
        }
        Ok(())
    }
}
