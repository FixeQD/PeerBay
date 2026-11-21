#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpTransportConfig {
    pub max_message_size: usize,
}

impl Default for TcpTransportConfig {
    fn default() -> Self {
        Self {
            max_message_size: 64 * 1024,
        }
    }
}

const MAX_TCP_MESSAGE_SIZE: usize = 16 * 1024 * 1024;

impl TcpTransportConfig {
    pub fn new(max_message_size: usize) -> Self {
        Self { max_message_size }
    }

    pub fn validate(&self) -> eros::Result<()> {
        if self.max_message_size == 0 {
            return Err(eros::error!(
                super::errors::TcpTransportError::MessageTooLarge { length: 0, max: 0 }
            ));
        }
        if self.max_message_size > MAX_TCP_MESSAGE_SIZE {
            return Err(eros::error!(
                super::errors::TcpTransportError::MessageTooLarge {
                    length: self.max_message_size,
                    max: MAX_TCP_MESSAGE_SIZE,
                }
            ));
        }
        Ok(())
    }
}
