#![allow(dead_code)]

use std::fmt::{Display, Formatter};

use super::envelope::MessageEnvelope;

pub(crate) const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
pub(crate) const DEFAULT_MAX_JSON_SIZE: usize = 256 * 1024;
pub(crate) const DEFAULT_MAX_STRING_LENGTH: usize = 4 * 1024;
pub(crate) const DEFAULT_MAX_BATCH_ITEMS: usize = 256;
pub(crate) const DEFAULT_MAX_PAYLOAD_SIZE: usize = 512 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProtocolLimits {
    max_frame_size: usize,
    max_json_size: usize,
    max_string_length: usize,
    max_batch_items: usize,
    max_payload_size: usize,
}

impl ProtocolLimits {
    pub(crate) const fn new(
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

    pub(crate) const fn max_frame_size(self) -> usize {
        self.max_frame_size
    }

    pub(crate) const fn max_json_size(self) -> usize {
        self.max_json_size
    }

    pub(crate) const fn max_string_length(self) -> usize {
        self.max_string_length
    }

    pub(crate) const fn max_batch_items(self) -> usize {
        self.max_batch_items
    }

    pub(crate) const fn max_payload_size(self) -> usize {
        self.max_payload_size
    }

    pub(crate) fn validate_frame_size(self, size: usize) -> eros::Result<()> {
        if size > self.max_frame_size {
            return Err(eros::error!(ProtocolLimitError::FrameTooLarge {
                size,
                max: self.max_frame_size,
            }));
        }

        Ok(())
    }

    pub(crate) fn validate_json_size(self, size: usize) -> eros::Result<()> {
        if size > self.max_json_size {
            return Err(eros::error!(ProtocolLimitError::JsonTooLarge {
                size,
                max: self.max_json_size,
            }));
        }

        Ok(())
    }

    pub(crate) fn validate_string(self, field: &'static str, value: &str) -> eros::Result<()> {
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

    pub(crate) fn validate_batch(self, field: &'static str, count: usize) -> eros::Result<()> {
        if count > self.max_batch_items {
            return Err(eros::error!(ProtocolLimitError::BatchTooLarge {
                field,
                count,
                max: self.max_batch_items,
            }));
        }

        Ok(())
    }

    pub(crate) fn validate_payload_size(self, size: usize) -> eros::Result<()> {
        if size > self.max_payload_size {
            return Err(eros::error!(ProtocolLimitError::PayloadTooLarge {
                size,
                max: self.max_payload_size,
            }));
        }

        Ok(())
    }

    pub(crate) fn validate_envelope<T>(self, envelope: &MessageEnvelope<T>) -> eros::Result<()> {
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
pub(crate) enum ProtocolLimitError {
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
        }
    }
}

impl std::error::Error for ProtocolLimitError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ControlMessageType, MessageType};

    #[test]
    fn default_limits_match_the_protocol_budget() {
        let limits = ProtocolLimits::default();

        assert_eq!(limits.max_frame_size(), DEFAULT_MAX_FRAME_SIZE);
        assert_eq!(limits.max_json_size(), DEFAULT_MAX_JSON_SIZE);
        assert_eq!(limits.max_string_length(), DEFAULT_MAX_STRING_LENGTH);
        assert_eq!(limits.max_batch_items(), DEFAULT_MAX_BATCH_ITEMS);
        assert_eq!(limits.max_payload_size(), DEFAULT_MAX_PAYLOAD_SIZE);
    }

    #[test]
    fn limits_accept_the_boundary_and_reject_the_next_byte_or_item() {
        let limits = ProtocolLimits::new(4, 4, 4, 2, 4);

        limits
            .validate_frame_size(4)
            .expect("frame boundary is valid");
        limits
            .validate_json_size(4)
            .expect("JSON boundary is valid");
        limits
            .validate_string("name", "1234")
            .expect("string boundary is valid");
        limits
            .validate_batch("items", 2)
            .expect("batch boundary is valid");
        limits
            .validate_payload_size(4)
            .expect("payload boundary is valid");

        assert!(limits.validate_frame_size(5).is_err());
        assert!(limits.validate_json_size(5).is_err());
        assert!(limits.validate_string("name", "12345").is_err());
        assert!(limits.validate_batch("items", 3).is_err());
        assert!(limits.validate_payload_size(5).is_err());
    }

    #[test]
    fn envelope_limit_validation_covers_wire_string_fields() {
        let limits = ProtocolLimits::new(64, 64, 4, 2, 32);
        let envelope = MessageEnvelope::new(
            "12345",
            MessageType::Control(ControlMessageType::Ping),
            "sid",
            1,
            2,
            (),
        );

        let error = envelope
            .validate_limits(limits)
            .expect_err("oversized message ID must be rejected")
            .downcast_inner::<ProtocolLimitError>()
            .expect("limit error should be preserved");

        assert_eq!(
            error,
            ProtocolLimitError::StringTooLong {
                field: "id",
                length: 5,
                max: 4,
            }
        );
    }
}
