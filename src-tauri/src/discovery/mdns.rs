use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::{IpAddr, UdpSocket};
use std::time::Duration;

use super::DiscoveryError;

#[derive(Clone, Debug)]
pub struct MdnsConfig {
    pub port: u16,
    pub group: String,
    pub bind_address: String,
    pub target_address: String,
    pub max_message_size: usize,
}

impl Default for MdnsConfig {
    fn default() -> Self {
        Self {
            port: 5353,
            group: "224.0.0.251".to_owned(),
            bind_address: "0.0.0.0".to_owned(),
            target_address: "224.0.0.251".to_owned(),
            max_message_size: 64 * 1024,
        }
    }
}

impl MdnsConfig {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.max_message_size == 0 || self.max_message_size > 64 * 1024 {
            return Err(DiscoveryError::InvalidSize {
                length: self.max_message_size,
                max: 64 * 1024,
            });
        }
        if self.bind_address.trim().is_empty()
            || self.target_address.trim().is_empty()
            || self.group.trim().is_empty()
        {
            return Err(DiscoveryError::InvalidAddress);
        }
        if !is_ip_address(&self.bind_address)
            || !is_ip_address(&self.target_address)
            || !is_ip_address(&self.group)
        {
            return Err(DiscoveryError::InvalidAddress);
        }
        Ok(())
    }
}

fn is_ip_address(value: &str) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && !value.chars().any(char::is_control)
        && value.len() <= 253
        && value.parse::<IpAddr>().is_ok()
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MdnsAdvertisement {
    pub service_type: String,
    pub instance_name: String,
    pub platform: String,
    pub port: u16,
    pub text: BTreeMap<String, String>,
}

impl MdnsAdvertisement {
    pub fn new(
        instance_name: String,
        platform: String,
        port: u16,
    ) -> Result<Self, DiscoveryError> {
        let advertisement = Self {
            service_type: "_peerbay._tcp.local".to_owned(),
            instance_name,
            platform,
            port,
            text: BTreeMap::new(),
        };
        advertisement.validate()?;
        Ok(advertisement)
    }

    pub fn validate(&self) -> Result<(), DiscoveryError> {
        if self.service_type != "_peerbay._tcp.local"
            || self.instance_name.trim().is_empty()
            || self.instance_name != self.instance_name.trim()
            || self.instance_name.chars().any(char::is_control)
            || self.instance_name.chars().any(is_disallowed_format_character)
            || self.platform.trim().is_empty()
            || self.platform != self.platform.trim()
            || self.platform.chars().any(char::is_control)
            || self.platform.chars().any(is_disallowed_format_character)
            || self.service_type.chars().any(is_disallowed_format_character)
        {
            return Err(DiscoveryError::InvalidBeacon);
        }
        if self.service_type.len() > 255
            || self.instance_name.len() > 255
            || self.platform.len() > 255
        {
            return Err(DiscoveryError::InvalidBeacon);
        }
        if self.port == 0 {
            return Err(DiscoveryError::InvalidBeacon);
        }
        if self.text.len() > 64 {
            return Err(DiscoveryError::InvalidBeacon);
        }
        for (key, value) in &self.text {
            if key.trim().is_empty()
                || key != key.trim()
                || key.len() > 64
                || !key.chars().all(|character| {
                    character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
                })
                || value.chars().any(char::is_control)
                || value.chars().any(is_disallowed_format_character)
                || value.len() > 256
            {
                return Err(DiscoveryError::InvalidBeacon);
            }
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
pub struct MdnsService {
    config: MdnsConfig,
}

impl MdnsService {
    pub fn new(config: MdnsConfig) -> Result<Self, DiscoveryError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn announce(&self, advertisement: &MdnsAdvertisement) -> Result<(), DiscoveryError> {
        advertisement.validate()?;
        let payload = serde_json::to_vec(advertisement).map_err(|_| DiscoveryError::InvalidJson)?;
        if payload.len() > self.config.max_message_size {
            return Err(DiscoveryError::InvalidSize {
                length: payload.len(),
                max: self.config.max_message_size,
            });
        }

        let socket = UdpSocket::bind(format!("{}:0", self.config.bind_address))
            .map_err(|_| DiscoveryError::BindFailed)?;
        if self.config.group.parse::<IpAddr>().map_or(false, |ip| ip.is_multicast()) {
            socket
                .set_multicast_ttl_v4(1)
                .map_err(|_| DiscoveryError::Io)?;
        }
        socket
            .send_to(&payload, format!("{}:{}", self.config.target_address, self.config.port))
            .map_err(|_| DiscoveryError::Io)?;
        Ok(())
    }

    pub fn browse(&self, timeout: Duration) -> Result<(MdnsAdvertisement, std::net::SocketAddr), DiscoveryError> {
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
        let advertisement: MdnsAdvertisement = serde_json::from_slice(&buffer[..size])
            .map_err(|_| DiscoveryError::InvalidJson)?;
        advertisement.validate()?;
        Ok((advertisement, source))
    }
}

