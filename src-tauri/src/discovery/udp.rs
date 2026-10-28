use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use super::{DiscoveryConfig, DiscoveryError};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DiscoveryBeacon {
    pub device_id: String,
    pub platform: String,
    pub port: u16,
}

impl DiscoveryBeacon {
    pub fn new(device_id: String, platform: String, port: u16) -> Result<Self, DiscoveryError> {
        let beacon = Self {
            device_id,
            platform,
            port,
        };
        beacon.validate()?;
        Ok(beacon)
    }

    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.device_id.trim().is_empty() || self.device_id != self.device_id.trim() {
            return Err(DiscoveryError::InvalidBeacon);
        }
        if self.device_id.chars().any(|character| {
            !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-' | ':')
        }) {
            return Err(DiscoveryError::InvalidBeacon);
        }
        if self.platform.trim().is_empty()
            || self.platform != self.platform.trim()
            || self.platform.chars().any(char::is_control)
            || self.platform.chars().any(is_disallowed_format_character)
            || self.platform.chars().any(|character| matches!(character, '\u{2028}' | '\u{2029}'))
            || self.platform.len() > 128
            || self.device_id.len() > 256
        {
            return Err(DiscoveryError::InvalidBeacon);
        }
        Ok(())
    }
}

fn is_disallowed_format_character(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{206f}'
            | '\u{feff}'
    )
}

#[derive(Clone, Debug)]
pub struct DiscoveryService {
    config: DiscoveryConfig,
}

impl DiscoveryService {
    pub fn new(config: DiscoveryConfig) -> Result<Self, DiscoveryError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn announce(&self, beacon: &DiscoveryBeacon) -> Result<(), DiscoveryError> {
        beacon.validate()?;
        let bytes = serde_json::to_vec(beacon).map_err(|_| DiscoveryError::InvalidJson)?;
        if bytes.len() > self.config.max_message_size {
            return Err(DiscoveryError::InvalidSize {
                length: bytes.len(),
                max: self.config.max_message_size,
            });
        }
        let socket = UdpSocket::bind(format!("0.0.0.0:0")).map_err(|_| DiscoveryError::BindFailed)?;
        socket
            .set_broadcast(true)
            .map_err(|_| DiscoveryError::Io)?;
        socket
            .send_to(&bytes, self.target())
            .map_err(|_| DiscoveryError::Io)?;
        Ok(())
    }

    pub fn receive(&self, timeout: Duration) -> Result<(DiscoveryBeacon, SocketAddr), DiscoveryError> {
        let socket = UdpSocket::bind(format!("{}:{}", self.config.bind_address, self.config.port))
            .map_err(|_| DiscoveryError::BindFailed)?;
        socket
            .set_read_timeout(Some(timeout))
            .map_err(|_| DiscoveryError::Io)?;
        let mut buffer = vec![0_u8; self.config.max_message_size + 1];
        let (size, source) = socket.recv_from(&mut buffer).map_err(|error| {
            if error.kind() == std::io::ErrorKind::TimedOut
                || error.kind() == std::io::ErrorKind::WouldBlock
            {
                DiscoveryError::ReceiveTimeout
            } else {
                DiscoveryError::Io
            }
        })?;
        if size > self.config.max_message_size {
            return Err(DiscoveryError::InvalidSize {
                length: size,
                max: self.config.max_message_size,
            });
        }
        let beacon: DiscoveryBeacon = serde_json::from_slice(&buffer[..size])
            .map_err(|_| DiscoveryError::InvalidJson)?;
        beacon.validate()?;
        Ok((beacon, source))
    }

    fn target(&self) -> String {
        format!("{}:{}", self.config.target_address, self.config.port)
    }
}
