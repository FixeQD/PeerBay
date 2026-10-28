use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::DigitallySignedStruct;
use rustls::Error as RustlsError;
use rustls::SignatureScheme;
use rustls::client::danger::ServerCertVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, StreamOwned};

use super::{
    config::TlsTransportConfig, errors::TlsTransportError, state::TlsStream,
    transport::TlsTransport, verifier::NoServerVerifier,
};
use crate::transport::{
    ChannelKind, PeerEndpoint, Transport, TransportChannel, TransportKind, TransportMetrics,
};

impl TlsTransport {
    pub fn accept(&self) -> eros::Result<Option<TransportChannel>> {
        match self.listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).map_err(|_| {
                    eros::error!(TlsTransportError::Io {
                        operation: "accept"
                    })
                })?;
                stream
                    .set_read_timeout(Some(Duration::from_millis(1)))
                    .map_err(|_| {
                        eros::error!(TlsTransportError::Io {
                            operation: "accept"
                        })
                    })?;
                let conn = ServerConnection::new(self.server_config.clone()).map_err(|e| {
                    eros::error!(TlsTransportError::Tls {
                        detail: e.to_string()
                    })
                })?;
                let tls_stream = TlsStream::Server(StreamOwned::new(conn, stream));
                let mut state = self.state.lock().map_err(|_| {
                    eros::error!(TlsTransportError::Io {
                        operation: "accept"
                    })
                })?;
                let channel_id = format!("tls-{}", state.next_id);
                state.next_id = state.next_id.saturating_add(1);
                state.connections.insert(channel_id.clone(), tls_stream);
                state.read_buffers.insert(channel_id.clone(), Vec::new());
                let peer_endpoint =
                    PeerEndpoint::new("remote", "127.0.0.1:0", TransportKind::Loopback)
                        .unwrap_or_else(|_| self.local.clone());
                state
                    .peer_endpoints
                    .insert(channel_id.clone(), peer_endpoint);
                TransportChannel::new(channel_id, TransportKind::Loopback, ChannelKind::Control)
                    .map(Some)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(eros::error!(TlsTransportError::Io {
                operation: "accept"
            })),
        }
    }

    pub fn send(&self, channel: &TransportChannel, payload: Vec<u8>) -> eros::Result<()> {
        if payload.len() > self.config.max_message_size {
            return Err(eros::error!(TlsTransportError::MessageTooLarge {
                length: payload.len(),
                max: self.config.max_message_size,
            }));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| eros::error!(TlsTransportError::Io { operation: "send" }))?;
        if state.closed.contains(channel.id()) {
            return Err(eros::error!(TlsTransportError::ChannelClosed));
        }
        let stream = state
            .connections
            .get_mut(channel.id())
            .ok_or_else(|| eros::error!(TlsTransportError::ChannelNotFound))?;
        if let Err(error) = stream.complete_io() {
            if error.kind() != std::io::ErrorKind::WouldBlock
                && error.kind() != std::io::ErrorKind::TimedOut
            {
                return Err(eros::error!(TlsTransportError::Tls {
                    detail: error.to_string()
                }));
            }
        }
        let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        stream.write_all(&length.to_be_bytes()).map_err(|_| {
            eros::error!(TlsTransportError::Io {
                operation: "send length"
            })
        })?;
        stream.write_all(&payload).map_err(|_| {
            eros::error!(TlsTransportError::Io {
                operation: "send payload"
            })
        })?;
        stream.flush().map_err(|_| {
            eros::error!(TlsTransportError::Io {
                operation: "send flush"
            })
        })?;
        Ok(())
    }

    pub fn receive(&self, channel: &TransportChannel) -> eros::Result<Option<Vec<u8>>> {
        let id = channel.id().to_owned();
        loop {
            let buffer_len = {
                let state = self.state.lock().map_err(|_| {
                    eros::error!(TlsTransportError::Io {
                        operation: "receive"
                    })
                })?;
                if state.closed.contains(&id) {
                    return Ok(None);
                }
                if !state.connections.contains_key(&id) {
                    return Err(eros::error!(TlsTransportError::ChannelNotFound));
                }
                state.read_buffers.get(&id).map(|b| b.len()).unwrap_or(0)
            };
            if buffer_len >= 4 {
                break;
            }
            let needed = 4 - buffer_len;
            let mut chunk = vec![0_u8; needed];
            let read_result = {
                let mut state = self.state.lock().map_err(|_| {
                    eros::error!(TlsTransportError::Io {
                        operation: "receive"
                    })
                })?;
                match state.connections.get_mut(&id) {
                    Some(stream) => stream.read(&mut chunk),
                    None => return Err(eros::error!(TlsTransportError::ChannelNotFound)),
                }
            };
            match read_result {
                Ok(0) => {
                    let mut state = self.state.lock().map_err(|_| {
                        eros::error!(TlsTransportError::Io {
                            operation: "receive"
                        })
                    })?;
                    state.closed.insert(id.clone());
                    return Ok(None);
                }
                Ok(read) => {
                    let mut state = self.state.lock().map_err(|_| {
                        eros::error!(TlsTransportError::Io {
                            operation: "receive"
                        })
                    })?;
                    if let Some(buffer) = state.read_buffers.get_mut(&id) {
                        buffer.extend_from_slice(&chunk[..read]);
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(None);
                }
                Err(_) => {
                    return Err(eros::error!(TlsTransportError::Io {
                        operation: "receive"
                    }));
                }
            }
        }
        let length = {
            let state = self.state.lock().map_err(|_| {
                eros::error!(TlsTransportError::Io {
                    operation: "receive"
                })
            })?;
            let buffer = state
                .read_buffers
                .get(&id)
                .ok_or_else(|| eros::error!(TlsTransportError::ChannelNotFound))?;
            u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize
        };
        if length > self.config.max_message_size {
            let mut state = self.state.lock().map_err(|_| {
                eros::error!(TlsTransportError::Io {
                    operation: "receive"
                })
            })?;
            state.closed.insert(id.clone());
            return Err(eros::error!(TlsTransportError::MessageTooLarge {
                length,
                max: self.config.max_message_size
            }));
        }
        let total = 4 + length;
        loop {
            let buffer_len = {
                let state = self.state.lock().map_err(|_| {
                    eros::error!(TlsTransportError::Io {
                        operation: "receive"
                    })
                })?;
                state.read_buffers.get(&id).map(|b| b.len()).unwrap_or(0)
            };
            if buffer_len >= total {
                break;
            }
            let needed = total - buffer_len;
            let mut chunk = vec![0_u8; needed];
            let read_result = {
                let mut state = self.state.lock().map_err(|_| {
                    eros::error!(TlsTransportError::Io {
                        operation: "receive"
                    })
                })?;
                match state.connections.get_mut(&id) {
                    Some(stream) => stream.read(&mut chunk),
                    None => return Err(eros::error!(TlsTransportError::ChannelNotFound)),
                }
            };
            match read_result {
                Ok(0) => {
                    let mut state = self.state.lock().map_err(|_| {
                        eros::error!(TlsTransportError::Io {
                            operation: "receive"
                        })
                    })?;
                    state.closed.insert(id.clone());
                    return Ok(None);
                }
                Ok(read) => {
                    let mut state = self.state.lock().map_err(|_| {
                        eros::error!(TlsTransportError::Io {
                            operation: "receive"
                        })
                    })?;
                    if let Some(buffer) = state.read_buffers.get_mut(&id) {
                        buffer.extend_from_slice(&chunk[..read]);
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(None);
                }
                Err(_) => {
                    return Err(eros::error!(TlsTransportError::Io {
                        operation: "receive"
                    }));
                }
            }
        }
        let mut state = self.state.lock().map_err(|_| {
            eros::error!(TlsTransportError::Io {
                operation: "receive"
            })
        })?;
        let buffer = state
            .read_buffers
            .get_mut(&id)
            .ok_or_else(|| eros::error!(TlsTransportError::ChannelNotFound))?;
        let payload = buffer[4..total].to_vec();
        buffer.drain(..total);
        Ok(Some(payload))
    }

    pub fn is_open(&self, channel: &TransportChannel) -> eros::Result<bool> {
        let state = self.state.lock().map_err(|_| {
            eros::error!(TlsTransportError::Io {
                operation: "is_open"
            })
        })?;
        Ok(state.connections.contains_key(channel.id()) && !state.closed.contains(channel.id()))
    }
}

impl Transport for TlsTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Loopback
    }

    fn discover(&self) -> eros::Result<Vec<PeerEndpoint>> {
        Ok(Vec::new())
    }

    fn open(&self, peer: &PeerEndpoint, channel: ChannelKind) -> eros::Result<TransportChannel> {
        peer.validate()?;
        if peer.transport != TransportKind::Loopback {
            return Err(eros::error!(TlsTransportError::WrongTransportKind {
                expected: TransportKind::Loopback,
                received: peer.transport,
            }));
        }
        if !self.supports(channel) {
            return Err(eros::error!(TlsTransportError::UnsupportedChannel {
                channel
            }));
        }
        if peer.device_id == self.local.device_id {
            return Err(eros::error!(TlsTransportError::SelfConnection));
        }
        let peer_addr = peer
            .address
            .parse::<std::net::SocketAddr>()
            .map_err(|_| eros::error!(TlsTransportError::InvalidLocalAddress))?;
        let stream = TcpStream::connect(peer_addr).map_err(|_| {
            eros::error!(TlsTransportError::ConnectFailed {
                address: peer.address.clone()
            })
        })?;
        stream
            .set_read_timeout(Some(Duration::from_millis(1)))
            .map_err(|_| eros::error!(TlsTransportError::Io { operation: "open" }))?;
        let server_name = ServerName::try_from("localhost").map_err(|e| {
            eros::error!(TlsTransportError::Tls {
                detail: e.to_string()
            })
        })?;
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerVerifier))
            .with_no_client_auth();
        let conn = ClientConnection::new(Arc::new(client_config), server_name).map_err(|e| {
            eros::error!(TlsTransportError::Tls {
                detail: e.to_string()
            })
        })?;
        let tls_stream = TlsStream::Client(StreamOwned::new(conn, stream));

        let mut state = self
            .state
            .lock()
            .map_err(|_| eros::error!(TlsTransportError::Io { operation: "open" }))?;
        let channel_id = format!("tls-{}", state.next_id);
        state.next_id = state.next_id.saturating_add(1);
        state.connections.insert(channel_id.clone(), tls_stream);
        state.read_buffers.insert(channel_id.clone(), Vec::new());
        state
            .peer_endpoints
            .insert(channel_id.clone(), peer.clone());
        TransportChannel::new(channel_id, TransportKind::Loopback, channel)
    }

    fn close(&self, channel: &TransportChannel) -> eros::Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| eros::error!(TlsTransportError::Io { operation: "close" }))?;
        let _ = state.connections.remove(channel.id());
        state.closed.insert(channel.id().to_owned());
        state.read_buffers.remove(channel.id());
        state.peer_endpoints.remove(channel.id());
        Ok(())
    }

    fn metrics(&self, channel: &TransportChannel) -> eros::Result<TransportMetrics> {
        let state = self.state.lock().map_err(|_| {
            eros::error!(TlsTransportError::Io {
                operation: "metrics"
            })
        })?;
        Ok(TransportMetrics::new(
            Some(0),
            None,
            0,
            state.closed.contains(channel.id()),
        ))
    }

    fn supports(&self, _channel: ChannelKind) -> bool {
        true
    }

    fn migrate(
        &self,
        channel: &TransportChannel,
        target: TransportKind,
    ) -> eros::Result<TransportChannel> {
        let peer = {
            let state = self.state.lock().map_err(|_| {
                eros::error!(TlsTransportError::Io {
                    operation: "migrate"
                })
            })?;
            state
                .peer_endpoints
                .get(channel.id())
                .cloned()
                .ok_or_else(|| eros::error!(TlsTransportError::ChannelNotFound))?
        };
        if {
            let state = self.state.lock().map_err(|_| {
                eros::error!(TlsTransportError::Io {
                    operation: "migrate"
                })
            })?;
            state.closed.contains(channel.id())
        } {
            return Err(eros::error!(TlsTransportError::ChannelClosed));
        }
        let stream = TcpStream::connect(
            peer.address
                .parse::<std::net::SocketAddr>()
                .map_err(|_| eros::error!(TlsTransportError::InvalidLocalAddress))?,
        )
        .map_err(|_| {
            eros::error!(TlsTransportError::ConnectFailed {
                address: peer.address.clone()
            })
        })?;
        stream
            .set_read_timeout(Some(Duration::from_millis(1)))
            .map_err(|_| {
                eros::error!(TlsTransportError::Io {
                    operation: "migrate"
                })
            })?;
        let server_name = ServerName::try_from("localhost").map_err(|e| {
            eros::error!(TlsTransportError::Tls {
                detail: e.to_string()
            })
        })?;
        let client_config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoServerVerifier))
            .with_no_client_auth();
        let conn = ClientConnection::new(Arc::new(client_config), server_name).map_err(|e| {
            eros::error!(TlsTransportError::Tls {
                detail: e.to_string()
            })
        })?;
        let tls_stream = TlsStream::Client(StreamOwned::new(conn, stream));
        let mut state = self.state.lock().map_err(|_| {
            eros::error!(TlsTransportError::Io {
                operation: "migrate"
            })
        })?;
        let channel_id = format!("tls-{}", state.next_id);
        state.next_id = state.next_id.saturating_add(1);
        state.connections.insert(channel_id.clone(), tls_stream);
        state.read_buffers.insert(channel_id.clone(), Vec::new());
        state.peer_endpoints.insert(channel_id.clone(), peer);
        TransportChannel::new(channel_id, target, channel.kind())
    }
}

