//! Local device identity boundary.

use std::env;
use std::fmt::{Debug, Display, Formatter};

use ed25519_dalek::SigningKey;
use rand::rng;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

pub const MAX_DEVICE_NAME_LENGTH: usize = 128;
pub const IDENTITY_PRIVATE_KEY_LENGTH: usize = 32;
pub const IDENTITY_PUBLIC_KEY_LENGTH: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceIdentity {
    device_id: String,
    display_name: String,
}

impl DeviceIdentity {
    pub fn generate() -> Self {
        Self {
            device_id: Uuid::new_v4().to_string(),
            display_name: default_display_name(),
        }
    }

    pub fn new(
        device_id: impl Into<String>,
        display_name: impl Into<String>,
    ) -> eros::Result<Self> {
        let identity = Self {
            device_id: device_id.into(),
            display_name: display_name.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    pub fn with_display_name(&self, display_name: impl Into<String>) -> eros::Result<Self> {
        Self::new(self.device_id.clone(), display_name)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_device_id(&self.device_id)?;
        validate_display_name(&self.display_name)
    }
}

impl Serialize for DeviceIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct IdentityWire<'a> {
            device_id: &'a str,
            display_name: &'a str,
        }

        IdentityWire {
            device_id: &self.device_id,
            display_name: &self.display_name,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeviceIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct IdentityWire {
            device_id: String,
            display_name: String,
        }

        let wire = IdentityWire::deserialize(deserializer)?;
        Self::new(wire.device_id, wire.display_name)
            .map_err(|error| serde::de::Error::custom(error.to_string()))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DeviceIdentityError {
    InvalidDeviceId,
    InvalidDeviceIdFormat,
    NilDeviceId,
    EmptyDisplayName,
    DisplayNameTooLong { length: usize, max: usize },
    DisplayNameUnexpectedWhitespace,
    DisplayNameControlCharacter,
    DisplayNameFormatCharacter,
    DisplayNameLineSeparator,
}

impl Display for DeviceIdentityError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDeviceId => write!(formatter, "device ID must not be empty"),
            Self::InvalidDeviceIdFormat => {
                write!(formatter, "device ID must be a canonical lowercase UUID")
            }
            Self::NilDeviceId => write!(formatter, "device ID must not be the nil UUID"),
            Self::EmptyDisplayName => write!(formatter, "device display name must not be empty"),
            Self::DisplayNameTooLong { length, max } => write!(
                formatter,
                "device display name is too long: {length} bytes, limit is {max}"
            ),
            Self::DisplayNameUnexpectedWhitespace => write!(
                formatter,
                "device display name must not have surrounding whitespace"
            ),
            Self::DisplayNameControlCharacter => {
                write!(
                    formatter,
                    "device display name contains a control character"
                )
            }
            Self::DisplayNameFormatCharacter => {
                write!(
                    formatter,
                    "device display name contains a Unicode format character"
                )
            }
            Self::DisplayNameLineSeparator => {
                write!(
                    formatter,
                    "device display name contains a Unicode line separator"
                )
            }
        }
    }
}

impl std::error::Error for DeviceIdentityError {}

pub struct IdentityKeyPair {
    private_key: Zeroizing<[u8; IDENTITY_PRIVATE_KEY_LENGTH]>,
    public_key: [u8; IDENTITY_PUBLIC_KEY_LENGTH],
}

impl IdentityKeyPair {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rng());
        Self::from_private_bytes(signing_key.to_bytes())
    }

    pub fn from_private_bytes(private_key: [u8; IDENTITY_PRIVATE_KEY_LENGTH]) -> Self {
        let signing_key = SigningKey::from_bytes(&private_key);
        let public_key = signing_key.verifying_key().to_bytes();

        Self {
            private_key: Zeroizing::new(private_key),
            public_key,
        }
    }

    pub fn public_key_bytes(&self) -> [u8; IDENTITY_PUBLIC_KEY_LENGTH] {
        self.public_key
    }

    pub fn with_private_key<R>(
        &self,
        callback: impl FnOnce(&[u8; IDENTITY_PRIVATE_KEY_LENGTH]) -> R,
    ) -> R {
        callback(&self.private_key)
    }

    pub fn private_key_bytes(&self) -> PrivateKeyBytes {
        PrivateKeyBytes(self.private_key.clone())
    }

    pub fn validate(&self) -> eros::Result<()> {
        let signing_key = SigningKey::from_bytes(&self.private_key);
        if signing_key.verifying_key().to_bytes() != self.public_key {
            return Err(eros::error!(IdentityKeyPairError::PublicKeyMismatch));
        }

        Ok(())
    }
}

impl Debug for IdentityKeyPair {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("IdentityKeyPair")
            .field("private_key", &"<redacted>")
            .field("public_key", &"<redacted>")
            .finish()
    }
}

impl Drop for IdentityKeyPair {
    fn drop(&mut self) {
        self.public_key.zeroize();
    }
}

pub struct PrivateKeyBytes(Zeroizing<[u8; IDENTITY_PRIVATE_KEY_LENGTH]>);

impl PrivateKeyBytes {
    pub fn as_bytes(&self) -> &[u8; IDENTITY_PRIVATE_KEY_LENGTH] {
        &self.0
    }
}

impl Debug for PrivateKeyBytes {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PrivateKeyBytes(<redacted>)")
    }
}

impl Drop for PrivateKeyBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Default)]
pub struct IdentityKeyStore {
    keypair: Option<IdentityKeyPair>,
}

impl IdentityKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn generated() -> Self {
        let mut store = Self::new();
        store.save(IdentityKeyPair::generate());
        store
    }

    pub fn save(&mut self, keypair: IdentityKeyPair) {
        self.keypair = Some(keypair);
    }

    pub fn load(&self) -> eros::Result<&IdentityKeyPair> {
        self.keypair
            .as_ref()
            .ok_or_else(|| eros::error!(IdentityKeyStoreError::MissingKeyPair))
    }

    pub fn take(&mut self) -> Option<IdentityKeyPair> {
        self.keypair.take()
    }

    pub fn clear(&mut self) {
        self.keypair.take();
    }

    pub fn is_empty(&self) -> bool {
        self.keypair.is_none()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityKeyPairError {
    PublicKeyMismatch,
}

impl Display for IdentityKeyPairError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicKeyMismatch => {
                write!(
                    formatter,
                    "identity keypair public key does not match private key"
                )
            }
        }
    }
}

impl std::error::Error for IdentityKeyPairError {}

#[derive(Debug, PartialEq, Eq)]
pub enum IdentityKeyStoreError {
    MissingKeyPair,
}

impl Display for IdentityKeyStoreError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingKeyPair => write!(formatter, "identity keypair is not available"),
        }
    }
}

impl std::error::Error for IdentityKeyStoreError {}

fn validate_device_id(value: &str) -> eros::Result<()> {
    if value.trim().is_empty() {
        return Err(eros::error!(DeviceIdentityError::InvalidDeviceId));
    }

    let parsed = Uuid::parse_str(value)
        .map_err(|_| eros::error!(DeviceIdentityError::InvalidDeviceIdFormat))?;
    if parsed.is_nil() {
        return Err(eros::error!(DeviceIdentityError::NilDeviceId));
    }
    if parsed.to_string() != value {
        return Err(eros::error!(DeviceIdentityError::InvalidDeviceIdFormat));
    }

    Ok(())
}

fn validate_display_name(value: &str) -> eros::Result<()> {
    if value.trim().is_empty() {
        return Err(eros::error!(DeviceIdentityError::EmptyDisplayName));
    }
    if value != value.trim() {
        return Err(eros::error!(
            DeviceIdentityError::DisplayNameUnexpectedWhitespace
        ));
    }
    if value.len() > MAX_DEVICE_NAME_LENGTH {
        return Err(eros::error!(DeviceIdentityError::DisplayNameTooLong {
            length: value.len(),
            max: MAX_DEVICE_NAME_LENGTH,
        }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(
            DeviceIdentityError::DisplayNameControlCharacter
        ));
    }
    if value.chars().any(is_disallowed_format_character) {
        return Err(eros::error!(
            DeviceIdentityError::DisplayNameFormatCharacter
        ));
    }
    if value
        .chars()
        .any(|character| matches!(character, '\u{2028}' | '\u{2029}'))
    {
        return Err(eros::error!(DeviceIdentityError::DisplayNameLineSeparator));
    }

    Ok(())
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

fn default_display_name() -> String {
    env::var("HOSTNAME")
        .ok()
        .filter(|hostname| validate_display_name(hostname).is_ok())
        .unwrap_or_else(|| format!("PeerBay {}", platform_label()))
}

const fn platform_label() -> &'static str {
    if cfg!(target_os = "android") {
        "Android"
    } else if cfg!(target_os = "windows") {
        "Windows"
    } else if cfg!(target_os = "linux") {
        "Linux"
    } else {
        "Device"
    }
}
