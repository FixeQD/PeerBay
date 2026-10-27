use super::errors::InMemoryTransportError;

const DEFAULT_MAX_MESSAGE_SIZE: usize = 512 * 1024;
const DEFAULT_MAX_QUEUE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InMemoryConfig {
    pub(super) max_message_size: usize,
    pub(super) max_queue_bytes: usize,
}

impl Default for InMemoryConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            max_queue_bytes: DEFAULT_MAX_QUEUE_BYTES,
        }
    }
}

impl InMemoryConfig {
    pub const fn new(max_message_size: usize, max_queue_bytes: usize) -> Self {
        Self {
            max_message_size,
            max_queue_bytes,
        }
    }

    pub const fn max_message_size(self) -> usize {
        self.max_message_size
    }

    pub const fn max_queue_bytes(self) -> usize {
        self.max_queue_bytes
    }

    pub(super) fn validate(self) -> eros::Result<()> {
        if self.max_message_size == 0 {
            return Err(eros::error!(InMemoryTransportError::InvalidLimit {
                field: "max_message_size"
            }));
        }
        if self.max_queue_bytes == 0 {
            return Err(eros::error!(InMemoryTransportError::InvalidLimit {
                field: "max_queue_bytes"
            }));
        }
        if self.max_message_size > self.max_queue_bytes {
            return Err(eros::error!(
                InMemoryTransportError::MessageLimitExceedsQueue {
                    message_limit: self.max_message_size,
                    queue_limit: self.max_queue_bytes,
                }
            ));
        }
        Ok(())
    }
}
