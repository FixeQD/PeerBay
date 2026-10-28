use std::fmt::{Debug, Formatter, Write as FmtWrite};

use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, KeyPair,
    KeyUsagePurpose, PKCS_ED25519,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::errors::TransportCertificateError;
use super::validation::validate_device_id;

const FINGERPRINT_LENGTH: usize = 64;

/// A self-signed Ed25519 transport certificate bound to one PeerBay device ID.
pub struct TransportCertificate {
    device_id: String,
    certificate_der: Vec<u8>,
    private_key_der: Zeroizing<Vec<u8>>,
    public_key: [u8; 32],
    fingerprint: String,
}

impl TransportCertificate {
    pub fn generate_for_device(device_id: impl Into<String>) -> eros::Result<Self> {
        let device_id = device_id.into();
        validate_device_id(&device_id)?;

        let key_pair = Zeroizing::new(KeyPair::generate_for(&PKCS_ED25519).map_err(|error| {
            eros::error!(TransportCertificateError::GenerationFailed {
                detail: error.to_string(),
            })
        })?);
        let public_key_raw = key_pair.public_key_raw();
        let public_key = key_pair.public_key_raw().try_into().map_err(|_| {
            eros::error!(TransportCertificateError::InvalidPublicKeyLength {
                length: public_key_raw.len(),
            })
        })?;

        let subject_name = format!("peerbay-{device_id}");
        let mut params = CertificateParams::new(vec![subject_name]).map_err(|error| {
            eros::error!(TransportCertificateError::GenerationFailed {
                detail: error.to_string(),
            })
        })?;
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, format!("PeerBay {device_id}"));
        params.distinguished_name = distinguished_name;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];

        let certificate = params.self_signed(&*key_pair).map_err(|error| {
            eros::error!(TransportCertificateError::GenerationFailed {
                detail: error.to_string(),
            })
        })?;
        let certificate_der = certificate.der().to_vec();
        let private_key_der = Zeroizing::new(key_pair.serialize_der());
        let fingerprint = fingerprint_for(&certificate_der);

        let transport_certificate = Self {
            device_id,
            certificate_der,
            private_key_der,
            public_key,
            fingerprint,
        };
        transport_certificate.validate()?;
        Ok(transport_certificate)
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    pub fn certificate_der(&self) -> &[u8] {
        &self.certificate_der
    }

    pub fn private_key_der(&self) -> &[u8] {
        self.private_key_der.as_slice()
    }

    pub fn public_key_bytes(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn with_private_key_der<R>(&self, callback: impl FnOnce(&[u8]) -> R) -> R {
        callback(&self.private_key_der)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_device_id(&self.device_id)?;
        if self.certificate_der.is_empty() {
            return Err(eros::error!(TransportCertificateError::EmptyCertificate));
        }
        if self.private_key_der.is_empty() {
            return Err(eros::error!(TransportCertificateError::GenerationFailed {
                detail: "transport private key is empty".to_owned(),
            }));
        }
        if self.fingerprint != fingerprint_for(&self.certificate_der) {
            return Err(eros::error!(TransportCertificateError::FingerprintMismatch));
        }
        if self.fingerprint.len() != FINGERPRINT_LENGTH
            || !self
                .fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(eros::error!(TransportCertificateError::FingerprintMismatch));
        }

        Ok(())
    }
}

impl Debug for TransportCertificate {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TransportCertificate")
            .field("device_id", &self.device_id)
            .field("certificate_der", &"<public certificate redacted>")
            .field("private_key_der", &"<redacted>")
            .field("public_key", &"<redacted>")
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

fn fingerprint_for(certificate_der: &[u8]) -> String {
    let digest = Sha256::digest(certificate_der);
    let mut fingerprint = String::with_capacity(FINGERPRINT_LENGTH);
    for byte in digest {
        let _ = write!(fingerprint, "{byte:02x}");
    }
    fingerprint
}
