#![allow(dead_code)]

use std::io::{Read, Write};

use eros::Context;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::limits::ProtocolLimits;

const FRAME_HEADER_SIZE: usize = std::mem::size_of::<u32>();

pub(crate) fn write_json_frame<W, T>(
    writer: &mut W,
    value: &T,
    limits: ProtocolLimits,
) -> eros::Result<()>
where
    W: Write,
    T: Serialize,
{
    let json = encode_json(value, limits)?;
    let frame_limits = framed_ipc::FrameLimits::new(limits.max_payload_size())
        .context("create JSON frame limits")?;

    framed_ipc::write_frame(writer, &json, frame_limits).context("write JSON protocol frame")
}

pub(crate) fn read_json_frame<R, T>(reader: &mut R, limits: ProtocolLimits) -> eros::Result<T>
where
    R: Read,
    T: DeserializeOwned,
{
    let frame_limits = framed_ipc::FrameLimits::new(limits.max_payload_size())
        .context("create JSON frame limits")?;
    let json = framed_ipc::read_frame(reader, frame_limits).context("read JSON protocol frame")?;

    limits
        .validate_frame_size(FRAME_HEADER_SIZE + json.len())
        .context("validate JSON frame size")?;
    limits
        .validate_json_size(json.len())
        .context("validate JSON payload size")?;
    limits
        .validate_payload_size(json.len())
        .context("validate JSON frame payload")?;

    serde_json::from_slice(&json)
        .map_err(|error| eros::error!(error).context("decode JSON protocol frame"))
}

fn encode_json<T>(value: &T, limits: ProtocolLimits) -> eros::Result<Vec<u8>>
where
    T: Serialize,
{
    let json = serde_json::to_vec(value)
        .map_err(|error| eros::error!(error).context("encode JSON protocol frame"))?;

    limits
        .validate_frame_size(FRAME_HEADER_SIZE + json.len())
        .context("validate JSON frame size")?;
    limits
        .validate_json_size(json.len())
        .context("validate JSON payload size")?;
    limits
        .validate_payload_size(json.len())
        .context("validate JSON frame payload")?;

    Ok(json)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use serde_json::json;

    use super::*;
    use crate::protocol::{
        ClipboardMessageType, MessageEnvelope, MessageType, PROTOCOL_VERSION, ProtocolLimits,
    };

    fn test_limits() -> ProtocolLimits {
        ProtocolLimits::new(256, 128, 64, 8, 128)
    }

    #[test]
    fn json_frames_roundtrip_a_versioned_envelope() {
        let original = MessageEnvelope::new(
            "message-1",
            MessageType::Clipboard(ClipboardMessageType::Text),
            "session-1",
            3,
            1_792_700_000_000,
            json!({ "text": "hello" }),
        );
        let mut bytes = Vec::new();

        write_json_frame(&mut bytes, &original, test_limits()).expect("frame should be written");
        let payload_length = u32::from_be_bytes(
            bytes[..4]
                .try_into()
                .expect("JSON frame should have a four-byte header"),
        ) as usize;
        assert_eq!(payload_length, bytes.len() - 4);

        let decoded: MessageEnvelope<serde_json::Value> =
            read_json_frame(&mut Cursor::new(bytes), test_limits()).expect("frame should be read");

        assert_eq!(decoded.v, PROTOCOL_VERSION);
        assert_eq!(decoded, original);
    }

    #[test]
    fn json_frames_reject_payloads_over_the_protocol_budget() {
        let limits = ProtocolLimits::new(64, 16, 64, 8, 16);
        let value = json!({ "text": "this payload is too large" });
        let mut bytes = Vec::new();

        let error = write_json_frame(&mut bytes, &value, limits)
            .expect_err("oversized JSON should be rejected")
            .to_string();

        assert!(error.contains("protocol JSON is too large") || error.contains("protocol payload"));
        assert!(bytes.is_empty());
    }

    #[test]
    fn json_frames_reject_malformed_payloads() {
        let mut bytes = Vec::new();
        framed_ipc::write_frame(
            &mut bytes,
            br#"{"v":1,"id":"broken""#,
            framed_ipc::FrameLimits::new(128).expect("frame limits should be valid"),
        )
        .expect("malformed frame should still be writable");

        let result =
            read_json_frame::<_, serde_json::Value>(&mut Cursor::new(bytes), test_limits());

        assert!(result.is_err());
    }
}
