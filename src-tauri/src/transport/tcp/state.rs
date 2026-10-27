use std::collections::{BTreeMap, BTreeSet};

use crate::transport::{PeerEndpoint, TransportChannel};

pub(crate) struct TcpTransportState {
    pub(crate) next_id: u64,
    pub(crate) connections: BTreeMap<String, std::net::TcpStream>,
    pub(crate) closed: BTreeSet<String>,
    pub(crate) peer_endpoints: BTreeMap<String, PeerEndpoint>,
    pub(crate) read_buffers: BTreeMap<String, Vec<u8>>,
}

impl TcpTransportState {
    pub(crate) fn new() -> Self {
        Self {
            next_id: 1,
            connections: BTreeMap::new(),
            closed: BTreeSet::new(),
            peer_endpoints: BTreeMap::new(),
            read_buffers: BTreeMap::new(),
        }
    }
}
