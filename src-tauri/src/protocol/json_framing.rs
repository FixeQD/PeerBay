#![allow(dead_code)]

use std::io::{Read, Write};

use eros::Context;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::limits::ProtocolLimits;

const FRAME_HEADER_SIZE: usize = std::mem::size_of::<u32>();

pub fn write_json_frame<W, T>(writer: &mut W, value: &T, limits: ProtocolLimits) -> eros::Result<()>
where
    W: Write,
    T: Serialize,
{
    let json = encode_json(value, limits)?;
    let frame_limits = framed_ipc::FrameLimits::new(limits.max_payload_size())
        .context("create JSON frame limits")?;

    framed_ipc::write_frame(writer, &json, frame_limits).context("write JSON protocol frame")
}

pub fn read_json_frame<R, T>(reader: &mut R, limits: ProtocolLimits) -> eros::Result<T>
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
