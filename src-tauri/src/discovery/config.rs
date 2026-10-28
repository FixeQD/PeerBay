const DEFAULT_PORT: u16 = 45901;
const DEFAULT_MAX_MESSAGE_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryConfig {
    pub port: u16,
    pub bind_address: String,
    pub target_address: String,
    pub max_message_size: usize,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            port: DEFAULT_PORT,
            bind_address: "0.0.0.0".to_owned(),
            target_address: "255.255.255.255".to_owned(),
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
        }
    }
}

impl DiscoveryConfig {
    pub fn new(port: u16) -> Self {
        Self {
            port,
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), super::errors::DiscoveryError> {
        if self.max_message_size == 0 || self.max_message_size > 64 * 1024 {
            return Err(super::errors::DiscoveryError::InvalidSize {
                length: self.max_message_size,
                max: 64 * 1024,
            });
        }
        if self.bind_address.trim().is_empty() || self.target_address.trim().is_empty() {
            return Err(super::errors::DiscoveryError::InvalidAddress);
        }
        Ok(())
    }
}
