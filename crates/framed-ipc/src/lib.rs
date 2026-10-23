//! Bounded length-delimited framing for local helper IPC.

use std::fmt::{Display, Formatter};
use std::io::{self, Read, Write};

pub const DEFAULT_MAX_FRAME_SIZE: usize = 1024 * 1024;
const HEADER_SIZE: usize = std::mem::size_of::<u32>();

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameLimits {
    max_frame_size: usize,
}

impl FrameLimits {
    pub const fn new(max_frame_size: usize) -> Result<Self, FrameError> {
        if max_frame_size > u32::MAX as usize {
            return Err(FrameError::InvalidLimit { max_frame_size });
        }

        Ok(Self { max_frame_size })
    }

    pub const fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_MAX_FRAME_SIZE,
        }
    }

    pub const fn max_frame_size(self) -> usize {
        self.max_frame_size
    }
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self::default()
    }
}

#[derive(Debug)]
pub enum FrameError {
    Io(io::Error),
    InvalidLimit { max_frame_size: usize },
    FrameTooLarge { length: usize, max: usize },
    TruncatedHeader,
    TruncatedPayload { expected: usize, received: usize },
}

impl Display for FrameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "IPC framing I/O error: {error}"),
            Self::InvalidLimit { max_frame_size } => {
                write!(formatter, "IPC frame limit is too large: {max_frame_size}")
            }
            Self::FrameTooLarge { length, max } => {
                write!(
                    formatter,
                    "IPC frame is too large: {length} bytes, limit is {max}"
                )
            }
            Self::TruncatedHeader => write!(formatter, "IPC frame header is truncated"),
            Self::TruncatedPayload { expected, received } => write!(
                formatter,
                "IPC frame payload is truncated: expected {expected} bytes, received {received}"
            ),
        }
    }
}

impl std::error::Error for FrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for FrameError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn encode_frame(payload: &[u8], limits: FrameLimits) -> Result<Vec<u8>, FrameError> {
    validate_length(payload.len(), limits)?;

    let mut frame = Vec::with_capacity(HEADER_SIZE + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub fn write_frame<W: Write>(
    writer: &mut W,
    payload: &[u8],
    limits: FrameLimits,
) -> Result<(), FrameError> {
    let frame = encode_frame(payload, limits)?;
    writer.write_all(&frame)?;
    Ok(())
}

pub fn read_frame<R: Read>(reader: &mut R, limits: FrameLimits) -> Result<Vec<u8>, FrameError> {
    let mut header = [0; HEADER_SIZE];
    let mut header_bytes = 0;

    while header_bytes < HEADER_SIZE {
        let read = reader.read(&mut header[header_bytes..])?;
        if read == 0 {
            if header_bytes == 0 {
                return Err(FrameError::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "end of stream",
                )));
            }
            return Err(FrameError::TruncatedHeader);
        }
        header_bytes += read;
    }

    let length = u32::from_be_bytes(header) as usize;
    validate_length(length, limits)?;

    let mut payload = vec![0; length];
    let mut received = 0;
    while received < length {
        let read = reader.read(&mut payload[received..])?;
        if read == 0 {
            return Err(FrameError::TruncatedPayload {
                expected: length,
                received,
            });
        }
        received += read;
    }

    Ok(payload)
}

fn validate_length(length: usize, limits: FrameLimits) -> Result<(), FrameError> {
    if length > limits.max_frame_size {
        return Err(FrameError::FrameTooLarge {
            length,
            max: limits.max_frame_size,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_empty_and_non_empty_frames() {
        let limits = FrameLimits::new(16).expect("valid limit");
        for payload in [b"".as_slice(), b"hello".as_slice()] {
            let frame = encode_frame(payload, limits).expect("frame should encode");
            assert_eq!(
                read_frame(&mut frame.as_slice(), limits).expect("frame should decode"),
                payload
            );
        }
    }

    #[test]
    fn rejects_frames_over_limit_before_writing() {
        let limits = FrameLimits::new(4).expect("valid limit");
        let error = encode_frame(b"12345", limits).expect_err("frame must be rejected");
        assert!(matches!(
            error,
            FrameError::FrameTooLarge { length: 5, max: 4 }
        ));
    }

    #[test]
    fn rejects_truncated_payload() {
        let limits = FrameLimits::new(16).expect("valid limit");
        let error = read_frame(&mut &[0, 0, 0, 5, b'a'][..], limits)
            .expect_err("truncated payload must fail");
        assert!(matches!(
            error,
            FrameError::TruncatedPayload {
                expected: 5,
                received: 1
            }
        ));
    }
}
