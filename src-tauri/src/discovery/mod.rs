mod config;
mod errors;
mod mdns;
mod registry;
mod udp;

pub use config::DiscoveryConfig;
pub use errors::DiscoveryError;
pub use mdns::{MdnsAdvertisement, MdnsConfig, MdnsService};
pub use registry::{DiscoveryAddress, DiscoveredPeer, DiscoveryRegistry};
pub use udp::{DiscoveryBeacon, DiscoveryService};
