use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use super::{
    config::TcpTransportConfig, errors::TcpTransportError, state::TcpTransportState,
    transport::TcpTransport,
};
use crate::transport::{
    ChannelKind, PeerEndpoint, Transport, TransportChannel, TransportKind, TransportMetrics,
};

impl TcpTransport {
    pub fn accept(&self) -> eros::Result<Option<TransportChannel>> {
        match self.listener.accept() {
            Ok((stream, _remote)) => {
                stream.set_nonblocking(false).map_err(|_| {
                    eros::error!(TcpTransportError::Io {
                        operation: "accept"
                    })
                })?;
                stream
                    .set_read_timeout(Some(Duration::from_millis(1)))
                    .map_err(|_| {
                        eros::error!(TcpTransportError::Io {
                            operation: "accept"
                        })
                    })?;
                let mut state = self.state.lock().map_err(|_| {
                    eros::error!(TcpTransportError::Io {
                        operation: "accept"
                    })
                })?;
                let channel_id = format!("tcp-{}", state.next_id);
                state.next_id += 1;
                state.peer_endpoints.insert(
                    channel_id.clone(),
                    PeerEndpoint::new(
                        "remote",
                        stream
                            .peer_addr()
                            .map(|address| address.to_string())
                            .unwrap_or_else(|_| "127.0.0.1:0".to_owned()),
                        TransportKind::Loopback,
                    )
                    .unwrap_or_else(|_| self.local.clone()),
                );
                state.connections.insert(channel_id.clone(), stream);
                state.read_buffers.insert(channel_id.clone(), Vec::new());
                TransportChannel::new(channel_id, TransportKind::Loopback, ChannelKind::Control)
                    .map(Some)
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(_) => Err(eros::error!(TcpTransportError::Io {
                operation: "accept"
            })),
        }
    }

    pub fn send(&self, channel: &TransportChannel, payload: Vec<u8>) -> eros::Result<()> {
        if payload.len() > self.config.max_message_size {
            return Err(eros::error!(TcpTransportError::MessageTooLarge {
                length: payload.len(),
                max: self.config.max_message_size,
            }));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| eros::error!(TcpTransportError::Io { operation: "send" }))?;
        if state.closed.contains(channel.id()) {
            return Err(eros::error!(TcpTransportError::ChannelClosed));
        }
        let stream = state
            .connections
            .get_mut(channel.id())
            .ok_or_else(|| eros::error!(TcpTransportError::ChannelNotFound))?;
        let length = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        stream.write_all(&length.to_be_bytes()).map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "send length"
            })
        })?;
        stream.write_all(&payload).map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "send payload"
            })
        })?;
        stream.flush().map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "send flush"
            })
        })?;
        Ok(())
    }

    pub fn receive(&self, channel: &TransportChannel) -> eros::Result<Option<Vec<u8>>> {
        let mut stream = {
            let mut state = self.state.lock().map_err(|_| {
                eros::error!(TcpTransportError::Io {
                    operation: "receive"
                })
            })?;
            if state.closed.contains(channel.id()) {
                return Ok(None);
            }
            if !state.connections.contains_key(channel.id()) {
                return Err(eros::error!(TcpTransportError::ChannelNotFound));
            }
            state
                .connections
                .get(channel.id())
                .unwrap()
                .try_clone()
                .map_err(|_| {
                    eros::error!(TcpTransportError::Io {
                        operation: "receive"
                    })
                })?
        };

        loop {
            let mut state = self.state.lock().map_err(|_| {
                eros::error!(TcpTransportError::Io {
                    operation: "receive"
                })
            })?;
            if state.read_buffers.get(channel.id()).unwrap().len() >= 4 {
                break;
            }
            let needed = 4 - state.read_buffers.get(channel.id()).unwrap().len();
            drop(state);
            let mut chunk = vec![0_u8; needed];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    let mut state = self.state.lock().map_err(|_| {
                        eros::error!(TcpTransportError::Io {
                            operation: "receive"
                        })
                    })?;
                    state.closed.insert(channel.id().to_owned());
                    return Ok(None);
                }
                Ok(read) => {
                    let mut state = self.state.lock().map_err(|_| {
                        eros::error!(TcpTransportError::Io {
                            operation: "receive"
                        })
                    })?;
                    state
                        .read_buffers
                        .get_mut(channel.id())
                        .unwrap()
                        .extend_from_slice(&chunk[..read]);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(None);
                }
                Err(_) => {
                    return Err(eros::error!(TcpTransportError::Io {
                        operation: "receive"
                    }));
                }
            }
        }

        let length = {
            let state = self.state.lock().map_err(|_| {
                eros::error!(TcpTransportError::Io {
                    operation: "receive"
                })
            })?;
            let buffer = state.read_buffers.get(channel.id()).unwrap();
            u32::from_be_bytes(buffer[..4].try_into().unwrap()) as usize
        };
        if length > self.config.max_message_size {
            let mut state = self.state.lock().map_err(|_| {
                eros::error!(TcpTransportError::Io {
                    operation: "receive"
                })
            })?;
            state.closed.insert(channel.id().to_owned());
            return Err(eros::error!(TcpTransportError::MessageTooLarge {
                length,
                max: self.config.max_message_size,
            }));
        }
        let total = 4 + length;

        loop {
            let mut state = self.state.lock().map_err(|_| {
                eros::error!(TcpTransportError::Io {
                    operation: "receive"
                })
            })?;
            if state.read_buffers.get(channel.id()).unwrap().len() >= total {
                break;
            }
            let needed = total - state.read_buffers.get(channel.id()).unwrap().len();
            drop(state);
            let mut chunk = vec![0_u8; needed];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    let mut state = self.state.lock().map_err(|_| {
                        eros::error!(TcpTransportError::Io {
                            operation: "receive"
                        })
                    })?;
                    state.closed.insert(channel.id().to_owned());
                    return Ok(None);
                }
                Ok(read) => {
                    let mut state = self.state.lock().map_err(|_| {
                        eros::error!(TcpTransportError::Io {
                            operation: "receive"
                        })
                    })?;
                    state
                        .read_buffers
                        .get_mut(channel.id())
                        .unwrap()
                        .extend_from_slice(&chunk[..read]);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut =>
                {
                    return Ok(None);
                }
                Err(_) => {
                    return Err(eros::error!(TcpTransportError::Io {
                        operation: "receive"
                    }));
                }
            }
        }

        let mut state = self.state.lock().map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "receive"
            })
        })?;
        let buffer = state.read_buffers.get_mut(channel.id()).unwrap();
        let payload = buffer[4..total].to_vec();
        buffer.drain(..total);
        Ok(Some(payload))
    }

    pub fn is_open(&self, channel: &TransportChannel) -> eros::Result<bool> {
        let state = self.state.lock().map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "is_open"
            })
        })?;
        Ok(state.connections.contains_key(channel.id()) && !state.closed.contains(channel.id()))
    }
}

impl Transport for TcpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Loopback
    }

    fn discover(&self) -> eros::Result<Vec<PeerEndpoint>> {
        Ok(Vec::new())
    }

    fn open(&self, peer: &PeerEndpoint, channel: ChannelKind) -> eros::Result<TransportChannel> {
        peer.validate()?;
        if peer.transport != TransportKind::Loopback {
            return Err(eros::error!(TcpTransportError::WrongTransportKind {
                expected: TransportKind::Loopback,
                received: peer.transport,
            }));
        }
        if !self.supports(channel) {
            return Err(eros::error!(TcpTransportError::UnsupportedChannel {
                channel
            }));
        }
        if peer.device_id == self.local.device_id {
            return Err(eros::error!(TcpTransportError::SelfConnection));
        }
        let stream = TcpStream::connect(&peer.address).map_err(|_| {
            eros::error!(TcpTransportError::ConnectFailed {
                address: peer.address.clone(),
            })
        })?;
        stream
            .set_read_timeout(Some(Duration::from_millis(1)))
            .map_err(|_| eros::error!(TcpTransportError::Io { operation: "open" }))?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| eros::error!(TcpTransportError::Io { operation: "open" }))?;
        let channel_id = format!("tcp-{}", state.next_id);
        state.next_id += 1;
        state.connections.insert(channel_id.clone(), stream);
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
            .map_err(|_| eros::error!(TcpTransportError::Io { operation: "close" }))?;
        if let Some(mut stream) = state.connections.remove(channel.id()) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        state.closed.insert(channel.id().to_owned());
        state.read_buffers.remove(channel.id());
        state.peer_endpoints.remove(channel.id());
        Ok(())
    }

    fn metrics(&self, channel: &TransportChannel) -> eros::Result<TransportMetrics> {
        let state = self.state.lock().map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "metrics"
            })
        })?;
        let closed = state.closed.contains(channel.id());
        Ok(TransportMetrics::new(Some(0), None, 0, closed))
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
                eros::error!(TcpTransportError::Io {
                    operation: "migrate"
                })
            })?;
            state
                .peer_endpoints
                .get(channel.id())
                .cloned()
                .ok_or_else(|| eros::error!(TcpTransportError::ChannelNotFound))?
        };
        if self.closed_contains(channel)? {
            return Err(eros::error!(TcpTransportError::ChannelClosed));
        }
        let kind = channel.kind();
        let mut stream = TcpStream::connect(&peer.address).map_err(|_| {
            eros::error!(TcpTransportError::ConnectFailed {
                address: peer.address.clone(),
            })
        })?;
        stream
            .set_read_timeout(Some(Duration::from_millis(1)))
            .map_err(|_| {
                eros::error!(TcpTransportError::Io {
                    operation: "migrate"
                })
            })?;
        let mut state = self.state.lock().map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "migrate"
            })
        })?;
        let channel_id = format!("tcp-{}", state.next_id);
        state.next_id += 1;
        state.connections.insert(channel_id.clone(), stream);
        state.read_buffers.insert(channel_id.clone(), Vec::new());
        state.peer_endpoints.insert(channel_id.clone(), peer);
        TransportChannel::new(channel_id, target, kind)
    }
}

impl TcpTransport {
    fn closed_contains(&self, channel: &TransportChannel) -> eros::Result<bool> {
        let state = self.state.lock().map_err(|_| {
            eros::error!(TcpTransportError::Io {
                operation: "migrate"
            })
        })?;
        Ok(state.closed.contains(channel.id()))
    }
}
