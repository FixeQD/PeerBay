use std::collections::{BTreeMap, VecDeque};

use crate::PeerEndpoint;

pub(crate) const MAX_CLOSED_CHANNEL_IDS: usize = 4096;

#[derive(Debug)]
pub(crate) struct ClosedChannelIds {
    entries: VecDeque<String>,
}

impl ClosedChannelIds {
    pub(crate) fn new() -> Self {
        Self {
            entries: VecDeque::new(),
        }
    }

    pub(crate) fn insert(&mut self, id: String) {
        if self.contains(&id) {
            return;
        }
        if self.entries.len() >= MAX_CLOSED_CHANNEL_IDS {
            self.entries.pop_front();
        }
        self.entries.push_back(id);
    }

    pub(crate) fn contains(&self, id: &str) -> bool {
        self.entries.iter().any(|entry| entry == id)
    }
}

pub(crate) struct TcpTransportState {
    pub(crate) next_id: u64,
    pub(crate) connections: BTreeMap<String, std::net::TcpStream>,
    pub(crate) closed: ClosedChannelIds,
    pub(crate) peer_endpoints: BTreeMap<String, PeerEndpoint>,
    pub(crate) read_buffers: BTreeMap<String, Vec<u8>>,
}

impl TcpTransportState {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            connections: BTreeMap::new(),
            closed: ClosedChannelIds::new(),
            peer_endpoints: BTreeMap::new(),
            read_buffers: BTreeMap::new(),
        }
    }
}
