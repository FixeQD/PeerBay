use std::collections::{BTreeMap, BTreeSet};
use std::net::TcpStream;

use rustls::{ClientConnection, ServerConnection, StreamOwned};

use crate::transport::PeerEndpoint;
use crate::transport::TransportChannel;

#[derive(Debug)]
pub(crate) enum TlsStream {
    Client(StreamOwned<ClientConnection, TcpStream>),
    Server(StreamOwned<ServerConnection, TcpStream>),
}

impl std::io::Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Client(stream) => stream.read(buf),
            Self::Server(stream) => stream.read(buf),
        }
    }
}

impl TlsStream {
    pub(crate) fn complete_io(&mut self) -> std::io::Result<()> {
        match self {
            Self::Client(stream) => stream.conn.complete_io(&mut stream.sock).map(|_| ()),
            Self::Server(stream) => stream.conn.complete_io(&mut stream.sock).map(|_| ()),
        }
    }
}

impl std::io::Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Client(stream) => stream.write(buf),
            Self::Server(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Client(stream) => stream.flush(),
            Self::Server(stream) => stream.flush(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct TlsTransportState {
    pub(crate) next_id: u64,
    pub(crate) connections: BTreeMap<String, TlsStream>,
    pub(crate) closed: BTreeSet<String>,
    pub(crate) peer_endpoints: BTreeMap<String, PeerEndpoint>,
    pub(crate) read_buffers: BTreeMap<String, Vec<u8>>,
}

impl TlsTransportState {
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

#[allow(dead_code)]
pub(crate) fn _channel_marker(_: &TransportChannel) {}
