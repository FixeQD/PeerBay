use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use super::validation::{default_display_name, validate_device_id, validate_display_name};

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
