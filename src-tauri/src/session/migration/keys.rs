use std::fmt::{Debug, Formatter};

use rand::random;
use zeroize::Zeroize;

use crate::protocol::{ProtocolLimits, ResumeKey};

pub struct ResumeKeyStore {
    session_id: String,
    current: Option<ResumeKey>,
}

impl ResumeKeyStore {
    pub fn create_random(session_id: impl Into<String>) -> eros::Result<Self> {
        let session_id = session_id.into();
        ProtocolLimits::default().validate_string("sid", &session_id)?;

        let mut bytes: [u8; 32] = random();
        let key = ResumeKey::new(lower_case_hex(&bytes));
        bytes.zeroize();

        Ok(Self {
            session_id,
            current: Some(key?),
        })
    }

    pub fn inherit(session_id: impl Into<String>, key: ResumeKey) -> eros::Result<Self> {
        let session_id = session_id.into();
        ProtocolLimits::default().validate_string("sid", &session_id)?;

        Ok(Self {
            session_id,
            current: Some(key),
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn current(&self) -> Option<&ResumeKey> {
        self.current.as_ref()
    }

    pub fn clear(&mut self) {
        self.current = None;
    }
}

impl Debug for ResumeKeyStore {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ResumeKeyStore(<redacted>)")
    }
}

fn lower_case_hex(bytes: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut value = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        value.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        value.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    value
}
