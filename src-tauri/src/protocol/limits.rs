#![allow(dead_code)]

use std::fmt::{Display, Formatter};

use super::envelope::MessageEnvelope;

pub const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
pub const DEFAULT_MAX_JSON_SIZE: usize = 256 * 1024;
pub const DEFAULT_MAX_STRING_LENGTH: usize = 4 * 1024;
pub const DEFAULT_MAX_BATCH_ITEMS: usize = 256;
pub const DEFAULT_MAX_PAYLOAD_SIZE: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProtocolLimits {
    max_frame_size: usize,
    max_json_size: usize,
    max_string_length: usize,
    max_batch_items: usize,
    max_payload_size: usize,
}

impl ProtocolLimits {
    pub const fn new(
        max_frame_size: usize,
        max_json_size: usize,
        max_string_length: usize,
        max_batch_items: usize,
        max_payload_size: usize,
    ) -> Self {
        Self {
            max_frame_size,
            max_json_size,
            max_string_length,
            max_batch_items,
            max_payload_size,
        }
    }

    pub const fn max_frame_size(self) -> usize {
        self.max_frame_size
    }

    pub const fn max_json_size(self) -> usize {
        self.max_json_size
    }

    pub const fn max_string_length(self) -> usize {
        self.max_string_length
    }

    pub const fn max_batch_items(self) -> usize {
        self.max_batch_items
    }

    pub const fn max_payload_size(self) -> usize {
        self.max_payload_size
    }

    pub fn validate_frame_size(self, size: usize) -> eros::Result<()> {
        if size > self.max_frame_size {
            return Err(eros::error!(ProtocolLimitError::FrameTooLarge {
                size,
                max: self.max_frame_size,
            }));
        }

        Ok(())
    }

    pub fn validate_json_size(self, size: usize) -> eros::Result<()> {
        if size > self.max_json_size {
            return Err(eros::error!(ProtocolLimitError::JsonTooLarge {
                size,
                max: self.max_json_size,
            }));
        }

        Ok(())
    }

    pub fn validate_string(self, field: &'static str, value: &str) -> eros::Result<()> {
        if value.trim().is_empty() {
            return Err(eros::error!(ProtocolLimitError::InvalidIdentifier {
                field
            }));
        }

        let length = value.len();
        if length > self.max_string_length {
            return Err(eros::error!(ProtocolLimitError::StringTooLong {
                field,
                length,
                max: self.max_string_length,
            }));
        }

        Ok(())
    }

    pub fn validate_batch(self, field: &'static str, count: usize) -> eros::Result<()> {
        if count > self.max_batch_items {
            return Err(eros::error!(ProtocolLimitError::BatchTooLarge {
                field,
                count,
                max: self.max_batch_items,
            }));
        }

        Ok(())
    }

    pub fn validate_payload_size(self, size: usize) -> eros::Result<()> {
        if size > self.max_payload_size {
            return Err(eros::error!(ProtocolLimitError::PayloadTooLarge {
                size,
                max: self.max_payload_size,
            }));
        }

        Ok(())
    }

    pub fn validate_envelope<T>(self, envelope: &MessageEnvelope<T>) -> eros::Result<()> {
        for (field, value) in [
            ("id", envelope.id.as_str()),
            ("t", envelope.message_type.as_str()),
            ("sid", envelope.session_id.as_str()),
        ] {
            if value != value.trim() || value.chars().any(char::is_control) {
                return Err(eros::error!(ProtocolLimitError::InvalidIdentifier {
                    field
                }));
            }
        }

        self.validate_string("id", &envelope.id)?;
        self.validate_string("t", envelope.message_type.as_str())?;
        self.validate_string("sid", &envelope.session_id)
    }
}

impl Default for ProtocolLimits {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_FRAME_SIZE,
            DEFAULT_MAX_JSON_SIZE,
            DEFAULT_MAX_STRING_LENGTH,
            DEFAULT_MAX_BATCH_ITEMS,
            DEFAULT_MAX_PAYLOAD_SIZE,
        )
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProtocolLimitError {
    FrameTooLarge {
        size: usize,
        max: usize,
    },
    JsonTooLarge {
        size: usize,
        max: usize,
    },
    StringTooLong {
        field: &'static str,
        length: usize,
        max: usize,
    },
    BatchTooLarge {
        field: &'static str,
        count: usize,
        max: usize,
    },
    PayloadTooLarge {
        size: usize,
        max: usize,
    },
    InvalidIdentifier {
        field: &'static str,
    },
}

impl Display for ProtocolLimitError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooLarge { size, max } => {
                write!(
                    formatter,
                    "protocol frame is too large: {size} bytes, limit is {max}"
                )
            }
            Self::JsonTooLarge { size, max } => {
                write!(
                    formatter,
                    "protocol JSON is too large: {size} bytes, limit is {max}"
                )
            }
            Self::StringTooLong { field, length, max } => write!(
                formatter,
                "protocol string field {field} is too long: {length} bytes, limit is {max}"
            ),
            Self::BatchTooLarge { field, count, max } => write!(
                formatter,
                "protocol batch {field} is too large: {count} items, limit is {max}"
            ),
            Self::PayloadTooLarge { size, max } => write!(
                formatter,
                "protocol payload is too large: {size} bytes, limit is {max}"
            ),
            Self::InvalidIdentifier { field } => {
                write!(formatter, "protocol identifier {field} must not be empty")
            }
        }
    }
}

impl std::error::Error for ProtocolLimitError {}
