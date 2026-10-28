use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use super::DiscoveryError;

const MAX_PEERS: usize = 1024;
const MAX_ADDRESSES_PER_PEER: usize = 64;

#[derive(Clone, Debug)]
pub struct DiscoveryAddress {
    pub address: String,
    pub last_seen: Instant,
}

#[derive(Clone, Debug)]
pub struct DiscoveredPeer {
    pub device_id: String,
    pub platform: String,
    pub port: u16,
    pub addresses: BTreeMap<String, DiscoveryAddress>,
    pub last_seen: Instant,
}

#[derive(Clone, Debug)]
pub struct DiscoveryRegistry {
    peers: BTreeMap<String, DiscoveredPeer>,
    device_timeout: Duration,
    address_timeout: Duration,
    max_peers: usize,
    max_addresses_per_peer: usize,
}

impl DiscoveryRegistry {
    pub fn new(device_timeout: Duration, address_timeout: Duration) -> Self {
        Self {
            peers: BTreeMap::new(),
            device_timeout: if device_timeout.is_zero() {
                Duration::from_secs(60)
            } else {
                device_timeout
            },
            address_timeout: if address_timeout.is_zero() {
                Duration::from_secs(30)
            } else {
                address_timeout
            },
            max_peers: MAX_PEERS,
            max_addresses_per_peer: MAX_ADDRESSES_PER_PEER,
        }
    }

    pub fn with_limits(
        device_timeout: Duration,
        address_timeout: Duration,
        max_peers: usize,
        max_addresses_per_peer: usize,
    ) -> Self {
        let mut registry = Self::new(device_timeout, address_timeout);
        if max_peers > 0 {
            registry.max_peers = max_peers;
        }
        if max_addresses_per_peer > 0 {
            registry.max_addresses_per_peer = max_addresses_per_peer;
        }
        registry
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    pub fn get(&self, device_id: &str) -> Option<&DiscoveredPeer> {
        self.peers.get(device_id)
    }

    pub fn peers(&self) -> Vec<DiscoveredPeer> {
        self.peers.values().cloned().collect()
    }

    pub fn observe(
        &mut self,
        device_id: &str,
        platform: &str,
        source: SocketAddr,
        port: u16,
        now: Instant,
    ) -> Result<bool, DiscoveryError> {
        validate_device_id(device_id)?;
        validate_platform(platform)?;
        if port == 0 {
            return Err(DiscoveryError::InvalidBeacon);
        }
        let address = SocketAddr::new(source.ip(), port).to_string();
        if address.parse::<SocketAddr>().is_err() {
            return Err(DiscoveryError::InvalidAddress);
        }

        let inserted = !self.peers.contains_key(device_id);

        if let Some(existing) = self.peers.get(device_id)
            && now < existing.last_seen
        {
            return Ok(false);
        }

        // Avoid identity-flood eviction starvation, reject rather than silently replacing.
        if self.peers.len() >= self.max_peers && inserted {
            return Err(DiscoveryError::TooManyPeers);
        }

        let peer = self
            .peers
            .entry(device_id.to_owned())
            .or_insert_with(|| DiscoveredPeer {
                device_id: device_id.to_owned(),
                platform: platform.to_owned(),
                port,
                addresses: BTreeMap::new(),
                last_seen: now,
            });

        peer.platform = platform.to_owned();
        peer.port = port;
        peer.last_seen = now;

        if peer.addresses.len() >= self.max_addresses_per_peer
            && !peer.addresses.contains_key(&address)
        {
            evict_oldest_address(peer);
        }
        peer.addresses.insert(
            address.clone(),
            DiscoveryAddress {
                address,
                last_seen: now,
            },
        );

        Ok(inserted)
    }

    pub fn prune(&mut self, now: Instant) -> Vec<String> {
        let mut expired_peers = Vec::new();

        let mut device_ids: Vec<String> = self.peers.keys().cloned().collect();
        for device_id in device_ids.drain(..) {
            let expired = {
                let Some(peer) = self.peers.get_mut(&device_id) else {
                    continue;
                };
                // Drop only addresses that have gone stale preserving recently observed ones
                peer.addresses
                    .retain(|_, address| address.last_seen.checked_add(self.address_timeout).is_some_and(|deadline| now <= deadline));

                let device_expired = peer.last_seen.checked_add(self.device_timeout).is_none_or(|deadline| now > deadline);
                device_expired || peer.addresses.is_empty()
            };
            if expired {
                self.peers.remove(&device_id);
                expired_peers.push(device_id);
            }
        }
        expired_peers
    }

    pub fn retain_address(&mut self, device_id: &str, address: &str, keep: bool) -> bool {
        if keep {
            return self.peers.contains_key(device_id);
        }
        if let Some(peer) = self.peers.get_mut(device_id) {
            let removed = peer.addresses.remove(address).is_some();
            if peer.addresses.is_empty() && self.should_remove_empty_peer() {
                self.peers.remove(device_id);
            }
            return removed;
        }
        false
    }

    fn should_remove_empty_peer(&self) -> bool {
        true
    }

}

fn evict_oldest_address(peer: &mut DiscoveredPeer) {
    let oldest = peer
        .addresses
        .iter()
        .min_by_key(|(_, address)| address.last_seen)
        .map(|(key, _)| key.clone());
    if let Some(key) = oldest {
        peer.addresses.remove(&key);
    }
}

fn validate_device_id(value: &str) -> Result<(), DiscoveryError> {
    if value.trim().is_empty() || value != value.trim() || value.len() > 256 {
        return Err(DiscoveryError::InvalidBeacon);
    }
    if value.chars().any(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-' | ':')
    }) {
        return Err(DiscoveryError::InvalidBeacon);
    }
    Ok(())
}

fn validate_platform(value: &str) -> Result<(), DiscoveryError> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.chars().any(char::is_control)
        || value.chars().any(is_disallowed_format_character)
        || value
            .chars()
            .any(|character| matches!(character, '\u{2028}' | '\u{2029}'))
        || value.len() > 128
    {
        return Err(DiscoveryError::InvalidBeacon);
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

