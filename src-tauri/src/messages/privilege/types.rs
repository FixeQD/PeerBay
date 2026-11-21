use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use super::errors::PrivilegeError;
use super::validation::{
    validate_action_fields, validate_expiry, validate_identifier_list,
    validate_optional_safe_identifier, validate_safe_identifier, validate_timestamp,
};
use proto::ProtocolLimits;

#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeProvider {
    StandardApp,
    RuntimePermission,
    SpecialAppAccess,
    Accessibility,
    MediaProjection,
    CompanionDevice,
    UsbAdb,
    WirelessAdb,
    Shizuku,
    Sui,
    Root,
    DeviceOwner,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeAuthority {
    StandardApp,
    RuntimePermission,
    SpecialAppAccess,
    UserGrantedService,
    CompanionAssociation,
    AdbShell,
    ShizukuShell,
    RootShell,
    DeviceOwner,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeAdbTransport {
    Usb,
    Wireless,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeState {
    Unavailable,
    Detected,
    NeedsUserAction,
    Starting,
    Ready,
    Degraded,
    Revoked,
    Failed,
    Stopping,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeDecision {
    Allowed,
    Denied,
    NeedsUserAction,
    Unavailable,
    Degraded,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeCancellationReason {
    UserRequested,
    Timeout,
    PeerDisconnected,
    SessionClosed,
    BackendShutdown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivilegeProof {
    pub provider: PrivilegeProvider,
    pub authority: PrivilegeAuthority,
    pub package_name: String,
    pub uid: Option<u32>,
    pub process_identity: Option<String>,
    pub service_version: Option<String>,
    pub adb_transport: Option<PrivilegeAdbTransport>,
    pub selinux_context: Option<String>,
    pub started_at_ms: u64,
    pub checked_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    pub evidence: Vec<String>,
}

impl PrivilegeProof {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: PrivilegeProvider,
        authority: PrivilegeAuthority,
        package_name: impl Into<String>,
        uid: Option<u32>,
        process_identity: Option<String>,
        service_version: Option<String>,
        adb_transport: Option<PrivilegeAdbTransport>,
        selinux_context: Option<String>,
        started_at_ms: u64,
        checked_at_ms: u64,
        expires_at_ms: Option<u64>,
        evidence: Vec<String>,
    ) -> eros::Result<Self> {
        let proof = Self {
            provider,
            authority,
            package_name: package_name.into(),
            uid,
            process_identity,
            service_version,
            adb_transport,
            selinux_context,
            started_at_ms,
            checked_at_ms,
            expires_at_ms,
            evidence,
        };
        proof.validate()?;
        Ok(proof)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_safe_identifier("package_name", &self.package_name)?;
        validate_optional_safe_identifier("process_identity", self.process_identity.as_deref())?;
        validate_optional_safe_identifier("service_version", self.service_version.as_deref())?;
        validate_optional_safe_identifier("selinux_context", self.selinux_context.as_deref())?;
        validate_timestamp("started_at_ms", self.started_at_ms)?;
        validate_timestamp("checked_at_ms", self.checked_at_ms)?;

        if self.checked_at_ms < self.started_at_ms {
            return Err(eros::error!(PrivilegeError::TimestampOrder {
                earlier_field: "started_at_ms",
                later_field: "checked_at_ms",
            }));
        }
        validate_expiry("expires_at_ms", self.checked_at_ms, self.expires_at_ms)?;
        validate_identifier_list("evidence", &self.evidence)?;

        if self.adb_transport.is_some()
            && !matches!(
                self.provider,
                PrivilegeProvider::UsbAdb | PrivilegeProvider::WirelessAdb
            )
        {
            return Err(eros::error!(
                PrivilegeError::AdbTransportRequiresAdbProvider
            ));
        }

        Ok(())
    }
}

/// The result of a typed request for one concrete capability.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivilegeStateMessage {
    pub request_id: String,
    pub capability: String,
    pub state: PrivilegeState,
    pub decision: PrivilegeDecision,
    pub reason_code: String,
    pub provider: Option<PrivilegeProvider>,
    pub authority: Option<PrivilegeAuthority>,
    pub limitations: Vec<String>,
    pub requires_user_action: bool,
    pub next_action: Option<String>,
    pub proof: Option<PrivilegeProof>,
    pub checked_at_ms: u64,
    pub expires_at_ms: Option<u64>,
}

impl PrivilegeStateMessage {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: impl Into<String>,
        capability: impl Into<String>,
        state: PrivilegeState,
        decision: PrivilegeDecision,
        reason_code: impl Into<String>,
        provider: Option<PrivilegeProvider>,
        authority: Option<PrivilegeAuthority>,
        limitations: Vec<String>,
        requires_user_action: bool,
        next_action: Option<String>,
        proof: Option<PrivilegeProof>,
        checked_at_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> eros::Result<Self> {
        let message = Self {
            request_id: request_id.into(),
            capability: capability.into(),
            state,
            decision,
            reason_code: reason_code.into(),
            provider,
            authority,
            limitations,
            requires_user_action,
            next_action,
            proof,
            checked_at_ms,
            expires_at_ms,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_safe_identifier("request_id", &self.request_id)?;
        validate_safe_identifier("capability", &self.capability)?;
        validate_safe_identifier("reason_code", &self.reason_code)?;
        validate_identifier_list("limitations", &self.limitations)?;
        validate_timestamp("checked_at_ms", self.checked_at_ms)?;
        validate_expiry("expires_at_ms", self.checked_at_ms, self.expires_at_ms)?;
        validate_action_fields(self.requires_user_action, self.next_action.as_deref())?;

        if let Some(proof) = &self.proof {
            proof.validate()?;
            if Some(proof.provider) != self.provider {
                return Err(eros::error!(PrivilegeError::ProofProviderMismatch));
            }
            if Some(proof.authority) != self.authority {
                return Err(eros::error!(PrivilegeError::ProofAuthorityMismatch));
            }
        }

        if self.decision == PrivilegeDecision::NeedsUserAction && !self.requires_user_action {
            return Err(eros::error!(PrivilegeError::DecisionRequiresUserAction));
        }

        Ok(())
    }
}

/// A request from the peer to prepare one capability on the Android device.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivilegeRequest {
    pub request_id: String,
    pub capability: String,
    pub provider_hint: Option<PrivilegeProvider>,
    pub requested_at_ms: u64,
}

impl PrivilegeRequest {
    pub fn new(
        request_id: impl Into<String>,
        capability: impl Into<String>,
        provider_hint: Option<PrivilegeProvider>,
        requested_at_ms: u64,
    ) -> eros::Result<Self> {
        let request = Self {
            request_id: request_id.into(),
            capability: capability.into(),
            provider_hint,
            requested_at_ms,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_safe_identifier("request_id", &self.request_id)?;
        validate_safe_identifier("capability", &self.capability)?;
        validate_timestamp("requested_at_ms", self.requested_at_ms)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivilegeCancelRequest {
    pub request_id: String,
    pub reason: PrivilegeCancellationReason,
}

impl PrivilegeCancelRequest {
    pub fn new(
        request_id: impl Into<String>,
        reason: PrivilegeCancellationReason,
    ) -> eros::Result<Self> {
        let request = Self {
            request_id: request_id.into(),
            reason,
        };
        request.validate()?;
        Ok(request)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_safe_identifier("request_id", &self.request_id)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivilegeBackendSnapshot {
    pub id: PrivilegeProvider,
    pub state: PrivilegeState,
    pub authority: Option<PrivilegeAuthority>,
    pub features: Vec<String>,
    pub limitations: Vec<String>,
    pub requires_user_action: bool,
    pub next_action: Option<String>,
    pub proof: Option<PrivilegeProof>,
    pub checked_at_ms: u64,
    pub expires_at_ms: Option<u64>,
}

impl PrivilegeBackendSnapshot {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: PrivilegeProvider,
        state: PrivilegeState,
        authority: Option<PrivilegeAuthority>,
        features: Vec<String>,
        limitations: Vec<String>,
        requires_user_action: bool,
        next_action: Option<String>,
        proof: Option<PrivilegeProof>,
        checked_at_ms: u64,
        expires_at_ms: Option<u64>,
    ) -> eros::Result<Self> {
        let snapshot = Self {
            id,
            state,
            authority,
            features,
            limitations,
            requires_user_action,
            next_action,
            proof,
            checked_at_ms,
            expires_at_ms,
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn validate(&self) -> eros::Result<()> {
        validate_identifier_list("features", &self.features)?;
        validate_identifier_list("limitations", &self.limitations)?;
        validate_timestamp("checked_at_ms", self.checked_at_ms)?;
        validate_expiry("expires_at_ms", self.checked_at_ms, self.expires_at_ms)?;
        validate_action_fields(self.requires_user_action, self.next_action.as_deref())?;

        if let Some(proof) = &self.proof {
            proof.validate()?;
            if proof.provider != self.id {
                return Err(eros::error!(PrivilegeError::ProofProviderMismatch));
            }
            if Some(proof.authority) != self.authority {
                return Err(eros::error!(PrivilegeError::ProofAuthorityMismatch));
            }
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct PrivilegeCapabilities {
    pub backends: Vec<PrivilegeBackendSnapshot>,
}

impl PrivilegeCapabilities {
    pub fn new(backends: Vec<PrivilegeBackendSnapshot>) -> eros::Result<Self> {
        let capabilities = Self { backends };
        capabilities.validate()?;
        Ok(capabilities)
    }

    pub fn validate(&self) -> eros::Result<()> {
        let limits = ProtocolLimits::default();
        limits.validate_batch("backends", self.backends.len())?;

        let mut seen = HashSet::with_capacity(self.backends.len());
        for backend in &self.backends {
            backend.validate()?;
            if !seen.insert(backend.id) {
                return Err(eros::error!(PrivilegeError::DuplicateBackend {
                    provider: backend.id,
                }));
            }
        }

        Ok(())
    }
}
