use std::net::{SocketAddr, TcpListener};
use std::sync::{Arc, Mutex};

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use super::config::TlsTransportConfig;
use super::errors::TlsTransportError;
use super::state::TlsTransportState;
use crate::identity::TransportCertificate;
use crate::transport::{PeerEndpoint, TransportKind};

pub struct TlsTransport {
    pub(crate) local: PeerEndpoint,
    pub(crate) config: TlsTransportConfig,
    pub(crate) certificate: TransportCertificate,
    pub(crate) peer_certificate_der: Option<Vec<u8>>,
    pub(crate) listener: Arc<TcpListener>,
    pub(crate) server_config: Arc<ServerConfig>,
    pub(crate) state: Arc<Mutex<TlsTransportState>>,
}

impl TlsTransport {
    pub fn new(local: PeerEndpoint) -> eros::Result<Self> {
        Self::with_config(local, TlsTransportConfig::default())
    }

    pub fn with_config(local: PeerEndpoint, config: TlsTransportConfig) -> eros::Result<Self> {
        local.validate()?;
        config.validate()?;
        if local.transport != TransportKind::Loopback {
            return Err(eros::error!(TlsTransportError::WrongTransportKind {
                expected: TransportKind::Loopback,
                received: local.transport,
            }));
        }
        let certificate = TransportCertificate::generate_for_device(local.device_id.clone())?;
        Self::with_certificate_and_config(local, certificate, None, config)
    }

    pub fn with_certificate(
        local: PeerEndpoint,
        certificate: TransportCertificate,
        peer_certificate_der: Option<Vec<u8>>,
    ) -> eros::Result<Self> {
        Self::with_certificate_and_config(
            local,
            certificate,
            peer_certificate_der,
            TlsTransportConfig::default(),
        )
    }

    pub fn with_certificate_and_config(
        local: PeerEndpoint,
        certificate: TransportCertificate,
        peer_certificate_der: Option<Vec<u8>>,
        config: TlsTransportConfig,
    ) -> eros::Result<Self> {
        local.validate()?;
        config.validate()?;
        if local.transport != TransportKind::Loopback {
            return Err(eros::error!(TlsTransportError::WrongTransportKind {
                expected: TransportKind::Loopback,
                received: local.transport,
            }));
        }
        let address: SocketAddr = local
            .address
            .parse()
            .map_err(|_| eros::error!(TlsTransportError::InvalidLocalAddress))?;
        if !address.ip().is_loopback() {
            return Err(eros::error!(TlsTransportError::InvalidLocalAddress));
        }
        let listener = TcpListener::bind(address).map_err(|_| {
            eros::error!(TlsTransportError::BindFailed {
                address: local.address.clone(),
            })
        })?;
        listener.set_nonblocking(true).map_err(|_| {
            eros::error!(TlsTransportError::Io {
                operation: "configure listener"
            })
        })?;

        let cert_der = CertificateDer::from(certificate.certificate_der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
            certificate.private_key_der().to_vec(),
        ));

        let server_config = if let Some(pinned) = peer_certificate_der.as_ref() {
            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(pinned.clone()))
                .map_err(|error| {
                    eros::error!(TlsTransportError::Tls {
                        detail: error.to_string()
                    })
                })?;
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|error| {
                    eros::error!(TlsTransportError::Tls {
                        detail: error.to_string()
                    })
                })?;
            ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![cert_der], key)
                .map_err(|error| {
                    eros::error!(TlsTransportError::Tls {
                        detail: error.to_string()
                    })
                })?
        } else {
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key)
                .map_err(|error| {
                    eros::error!(TlsTransportError::Tls {
                        detail: error.to_string()
                    })
                })?
        };

        Ok(Self {
            local,
            config,
            certificate,
            peer_certificate_der,
            listener: Arc::new(listener),
            server_config: Arc::new(server_config),
            state: Arc::new(Mutex::new(TlsTransportState::new())),
        })
    }

    pub fn pair(first: PeerEndpoint, second: PeerEndpoint) -> eros::Result<(Self, Self)> {
        Self::pair_with_config(first, second, TlsTransportConfig::default())
    }

    pub fn pair_with_config(
        first: PeerEndpoint,
        second: PeerEndpoint,
        config: TlsTransportConfig,
    ) -> eros::Result<(Self, Self)> {
        first.validate()?;
        second.validate()?;
        let first_certificate =
            crate::identity::TransportCertificate::generate_for_device(first.device_id.clone())?;
        let second_certificate =
            crate::identity::TransportCertificate::generate_for_device(second.device_id.clone())?;
        let first_cert_der = first_certificate.certificate_der().to_vec();
        let second_cert_der = second_certificate.certificate_der().to_vec();
        let first_transport = Self::with_certificate_and_config(
            first,
            first_certificate,
            Some(second_cert_der),
            config,
        )?;
        let second_transport = Self::with_certificate_and_config(
            second,
            second_certificate,
            Some(first_cert_der),
            config,
        )?;
        Ok((first_transport, second_transport))
    }

    pub fn local_endpoint(&self) -> &PeerEndpoint {
        &self.local
    }

    pub fn certificate(&self) -> &TransportCertificate {
        &self.certificate
    }

    pub fn config(&self) -> TlsTransportConfig {
        self.config
    }

    pub fn listener_address(&self) -> eros::Result<String> {
        self.listener
            .local_addr()
            .map(|address| address.to_string())
            .map_err(|_| {
                eros::error!(TlsTransportError::Io {
                    operation: "listener address"
                })
            })
    }
}
