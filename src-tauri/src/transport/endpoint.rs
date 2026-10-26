use serde::{Deserialize, Serialize};

use super::{TransportKind, errors::validate_transport_identifier};

/// Public peer address discovered or supplied to a transport
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PeerEndpoint {
    pub device_id: String,
    pub address: String,
    pub transport: TransportKind,
}

impl PeerEndpoint {
    pub fn new(
        device_id: impl Into<String>,
        address: impl Into<String>,
        transport: TransportKind,
    ) -> eros::Result<Self> {
        let endpoint = Self {
            device_id: device_id.into(),
            address: address.into(),
            transport,
        };
        endpoint.validate()?;
        Ok(endpoint)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_transport_identifier("device_id", &self.device_id)?;
        super::errors::validate_transport_string("address", &self.address)
    }
}
