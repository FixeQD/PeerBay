use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};

use crate::app::LifecycleState;
use crate::discovery::DiscoveredPeer;
use crate::identity::{DeviceIdentity, MAX_DEVICE_NAME_LENGTH, validate_display_name};
use crate::protocol::CapabilityDocument;
use crate::redaction::RedactionPolicy;
use crate::session::SessionState;
use crate::storage::PeerRecord;

pub const VIEWMODEL_SCHEMA_VERSION: u16 = 1;
pub const MAX_DEVICES: usize = 1024;
pub const MAX_SESSIONS: usize = 64;
pub const MAX_SNAPSHOT_BYTES: usize = 1_048_576;
const MIN_EMIT_MS: u64 = 1_577_836_800_000;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppViewModel {
    pub schema_version: u16,
    pub emitted_at_ms: u64,
    pub app: AppStatusView,
    pub identity: LocalIdentityView,
    pub devices: Vec<DeviceView>,
    pub sessions: Vec<SessionView>,
    pub diagnostics: DiagnosticsSummaryView,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppStatusView {
    pub lifecycle: String,
    pub ready: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LocalIdentityView {
    pub device_id: String,
    pub display_name: String,
    pub platform: String,
    pub platform_version: String,
    pub protocol_versions: Vec<u16>,
    pub transports: Vec<String>,
    pub features: Vec<String>,
    pub max_file_size: u64,
    pub max_message_size: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustStatus {
    Trusted,
    Discovered,
    Revoked,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceView {
    pub device_id: String,
    pub display_name: String,
    pub platform: String,
    pub trust: TrustStatus,
    pub fingerprint_preview: Option<String>,
    pub connection_state: String,
    pub transport_label: Option<String>,
    pub rtt_ms: Option<u32>,
    pub feature_rows: Vec<FeatureRowView>,
    pub available_actions: Vec<DeviceActionView>,
    pub blocked_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeatureRowState {
    AvailableAllowed,
    DisabledByPolicy,
    PermissionRequired,
    UnavailableOnPlatform,
    TemporarilyUnavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct FeatureRowView {
    pub feature_id: String,
    pub state: FeatureRowState,
    pub disabled_reason: Option<String>,
    pub next_step: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceAction {
    PairStart,
    SessionConnect,
    SessionDisconnect,
    SessionTakeover,
    SessionRelease,
    DevicesForget,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceActionView {
    pub action: DeviceAction,
    pub enabled: bool,
    pub disabled_reason: Option<String>,
    pub next_step: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SessionView {
    pub session_id: String,
    pub device_id: String,
    pub state: String,
    pub transport_label: String,
    pub rtt_ms: Option<u32>,
    pub open_channels: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DiagnosticsSummaryView {
    pub active_workers: usize,
    pub discovered_count: usize,
    pub trusted_count: usize,
    pub revoked_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionSummary {
    pub session_id: String,
    pub device_id: String,
    pub state: SessionState,
    pub transport_label: String,
    pub rtt_ms: Option<u32>,
    pub open_channels: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct SnapshotInputs<'a> {
    pub now_ms: u64,
    pub lifecycle: LifecycleState,
    pub identity: &'a DeviceIdentity,
    pub capabilities: &'a CapabilityDocument,
    pub discovered: &'a [DiscoveredPeer],
    pub trusted: &'a [PeerRecord],
    pub sessions: &'a [SessionSummary],
    pub active_workers: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ViewModelError {
    EmittedAtTooOld { value: u64 },
    TooManyDevices { count: usize },
    TooManySessions { count: usize },
    SnapshotTooLarge { size: usize },
    UnknownSessionPeer,
    InvalidPeerField { field: &'static str },
}

impl Display for ViewModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmittedAtTooOld { value } => write!(
                formatter,
                "snapshot timestamp {value} is before the minimum accepted value"
            ),
            Self::TooManyDevices { count } => write!(
                formatter,
                "snapshot would contain {count} devices, limit is {MAX_DEVICES}"
            ),
            Self::TooManySessions { count } => write!(
                formatter,
                "snapshot would contain {count} sessions, limit is {MAX_SESSIONS}"
            ),
            Self::SnapshotTooLarge { size } => write!(
                formatter,
                "serialized snapshot is {size} bytes, limit is {MAX_SNAPSHOT_BYTES}"
            ),
            Self::UnknownSessionPeer => write!(
                formatter,
                "snapshot session references a device outside the device union"
            ),
            Self::InvalidPeerField { field } => {
                write!(formatter, "peer field {field} failed validation")
            }
        }
    }
}

impl std::error::Error for ViewModelError {}

struct DeviceSource<'a> {
    status: TrustStatus,
    display_name: String,
    platform: String,
    fingerprint_preview: Option<String>,
    capabilities_snapshot: &'a str,
}

impl AppViewModel {
    pub fn build(inputs: SnapshotInputs<'_>) -> eros::Result<Self> {
        if inputs.now_ms < MIN_EMIT_MS {
            return Err(eros::error!(ViewModelError::EmittedAtTooOld {
                value: inputs.now_ms
            }));
        }

        let mut sources: BTreeMap<&str, DeviceSource<'_>> = BTreeMap::new();

        for record in inputs.trusted {
            let status = if record.is_revoked() {
                TrustStatus::Revoked
            } else {
                TrustStatus::Trusted
            };
            sources.insert(
                record.device_id.as_str(),
                DeviceSource {
                    status,
                    display_name: record.display_name.clone(),
                    platform: record.platform.clone(),
                    fingerprint_preview: match status {
                        TrustStatus::Trusted => Some(RedactionPolicy::redact_token_or_fingerprint(
                            &record.certificate_fingerprint,
                        )),
                        TrustStatus::Discovered | TrustStatus::Revoked => None,
                    },
                    capabilities_snapshot: record.capabilities_snapshot.as_str(),
                },
            );
        }

        for peer in inputs.discovered {
            sources
                .entry(peer.device_id.as_str())
                .or_insert_with(|| DeviceSource {
                    status: TrustStatus::Discovered,
                    display_name: peer.device_id.clone(),
                    platform: peer.platform.clone(),
                    fingerprint_preview: None,
                    capabilities_snapshot: "",
                });
        }

        if sources.len() > MAX_DEVICES {
            return Err(eros::error!(ViewModelError::TooManyDevices {
                count: sources.len()
            }));
        }
        if inputs.sessions.len() > MAX_SESSIONS {
            return Err(eros::error!(ViewModelError::TooManySessions {
                count: inputs.sessions.len()
            }));
        }
        for session in inputs.sessions {
            if !sources.contains_key(session.device_id.as_str()) {
                return Err(eros::error!(ViewModelError::UnknownSessionPeer));
            }
        }

        let mut devices = Vec::with_capacity(sources.len());
        for (device_id, source) in &sources {
            validate_peer_strings(source)?;
            devices.push(device_view(device_id, source, inputs.sessions));
        }

        let mut sessions: Vec<SessionView> = inputs
            .sessions
            .iter()
            .map(|session| SessionView {
                session_id: session.session_id.clone(),
                device_id: session.device_id.clone(),
                state: session.state.as_str().to_owned(),
                transport_label: session.transport_label.clone(),
                rtt_ms: session.rtt_ms,
                open_channels: session.open_channels,
            })
            .collect();
        sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));

        let trusted_count = inputs
            .trusted
            .iter()
            .filter(|record| !record.is_revoked())
            .count();

        let snapshot = Self {
            schema_version: VIEWMODEL_SCHEMA_VERSION,
            emitted_at_ms: inputs.now_ms,
            app: AppStatusView {
                lifecycle: lifecycle_str(inputs.lifecycle).to_owned(),
                ready: inputs.lifecycle == LifecycleState::Ready,
            },
            identity: LocalIdentityView {
                device_id: inputs.identity.device_id().to_owned(),
                display_name: inputs.identity.display_name().to_owned(),
                platform: inputs.capabilities.platform.clone(),
                platform_version: inputs.capabilities.platform_version.clone(),
                protocol_versions: inputs.capabilities.protocol_versions.clone(),
                transports: inputs.capabilities.transports.clone(),
                features: inputs.capabilities.features.clone(),
                max_file_size: inputs.capabilities.max_file_size,
                max_message_size: inputs.capabilities.max_message_size,
            },
            devices,
            sessions,
            diagnostics: DiagnosticsSummaryView {
                active_workers: inputs.active_workers,
                discovered_count: inputs.discovered.len(),
                trusted_count,
                revoked_count: inputs.trusted.len() - trusted_count,
            },
        };

        let size = serde_json::to_vec(&snapshot).map_or_else(
            |_| MAX_SNAPSHOT_BYTES.saturating_add(1),
            |bytes| bytes.len(),
        );
        if size > MAX_SNAPSHOT_BYTES {
            return Err(eros::error!(ViewModelError::SnapshotTooLarge { size }));
        }
        Ok(snapshot)
    }
}

fn device_view(
    device_id: &str,
    source: &DeviceSource<'_>,
    sessions: &[SessionSummary],
) -> DeviceView {
    let own_sessions: Vec<&SessionSummary> = sessions
        .iter()
        .filter(|session| session.device_id == device_id)
        .collect();
    let representative = own_sessions
        .iter()
        .copied()
        .find(|session| session_active(session.state))
        .or_else(|| {
            own_sessions
                .iter()
                .copied()
                .find(|session| !session.state.is_terminal())
        });
    let has_active_session = own_sessions
        .iter()
        .any(|session| session_active(session.state));

    let connection_state = representative
        .map(|session| session.state.as_str())
        .unwrap_or_else(|| match source.status {
            TrustStatus::Discovered => "discovered",
            TrustStatus::Trusted | TrustStatus::Revoked => "offline",
        });

    DeviceView {
        device_id: device_id.to_owned(),
        display_name: source.display_name.clone(),
        platform: source.platform.clone(),
        trust: source.status,
        fingerprint_preview: source.fingerprint_preview.clone(),
        connection_state: connection_state.to_owned(),
        transport_label: representative.map(|session| session.transport_label.clone()),
        rtt_ms: representative.and_then(|session| session.rtt_ms),
        feature_rows: match source.status {
            TrustStatus::Trusted => feature_rows_from_snapshot(source.capabilities_snapshot),
            TrustStatus::Discovered | TrustStatus::Revoked => Vec::new(),
        },
        available_actions: available_actions(source.status, has_active_session),
        blocked_reason: match source.status {
            TrustStatus::Revoked => Some("peer_revoked".to_owned()),
            TrustStatus::Discovered | TrustStatus::Trusted => None,
        },
    }
}

fn feature_rows_from_snapshot(snapshot: &str) -> Vec<FeatureRowView> {
    serde_json::from_str::<CapabilityDocument>(snapshot)
        .ok()
        .filter(|document| document.validate().is_ok())
        .map(|document| {
            document
                .features
                .iter()
                .map(|feature| FeatureRowView {
                    feature_id: feature.clone(),
                    state: FeatureRowState::AvailableAllowed,
                    disabled_reason: None,
                    next_step: None,
                })
                .collect()
        })
        .unwrap_or_default()
}

fn validate_peer_strings(source: &DeviceSource<'_>) -> eros::Result<()> {
    validate_display_name(&source.display_name).map_err(|_| {
        eros::error!(ViewModelError::InvalidPeerField {
            field: "display_name"
        })
    })?;
    validate_platform_string(&source.platform)
        .map_err(|_| eros::error!(ViewModelError::InvalidPeerField { field: "platform" }))?;
    Ok(())
}

fn validate_platform_string(value: &str) -> eros::Result<()> {
    if value.trim().is_empty()
        || value != value.trim()
        || value.chars().any(char::is_control)
        || value.chars().any(is_disallowed_format_character)
        || value
            .chars()
            .any(|character| matches!(character, '\u{2028}' | '\u{2029}'))
        || value.len() > MAX_DEVICE_NAME_LENGTH
    {
        return Err(eros::error!(ViewModelError::InvalidPeerField {
            field: "platform"
        }));
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

fn available_actions(status: TrustStatus, has_active_session: bool) -> Vec<DeviceActionView> {
    let entries: [(DeviceAction, bool, Option<&str>); 6] = match status {
        TrustStatus::Discovered => [
            (DeviceAction::PairStart, true, None),
            (DeviceAction::SessionConnect, false, Some("not_paired")),
            (DeviceAction::SessionDisconnect, false, Some("not_paired")),
            (DeviceAction::SessionTakeover, false, Some("not_paired")),
            (DeviceAction::SessionRelease, false, Some("not_paired")),
            (DeviceAction::DevicesForget, false, Some("not_paired")),
        ],
        TrustStatus::Trusted if has_active_session => [
            (DeviceAction::PairStart, false, Some("already_paired")),
            (DeviceAction::SessionConnect, false, Some("session_active")),
            (DeviceAction::SessionDisconnect, true, None),
            (DeviceAction::SessionTakeover, true, None),
            (DeviceAction::SessionRelease, true, None),
            (DeviceAction::DevicesForget, true, None),
        ],
        TrustStatus::Trusted => [
            (DeviceAction::PairStart, false, Some("already_paired")),
            (DeviceAction::SessionConnect, true, None),
            (DeviceAction::SessionDisconnect, false, Some("no_session")),
            (DeviceAction::SessionTakeover, false, Some("no_session")),
            (DeviceAction::SessionRelease, false, Some("no_session")),
            (DeviceAction::DevicesForget, true, None),
        ],
        TrustStatus::Revoked => [
            (DeviceAction::PairStart, false, Some("peer_revoked")),
            (DeviceAction::SessionConnect, false, Some("peer_revoked")),
            (DeviceAction::SessionDisconnect, false, Some("peer_revoked")),
            (DeviceAction::SessionTakeover, false, Some("peer_revoked")),
            (DeviceAction::SessionRelease, false, Some("peer_revoked")),
            (DeviceAction::DevicesForget, false, Some("peer_revoked")),
        ],
    };

    entries
        .into_iter()
        .map(|(action, enabled, reason)| DeviceActionView {
            action,
            enabled,
            disabled_reason: reason.map(str::to_owned),
            next_step: None,
        })
        .collect()
}

const fn lifecycle_str(state: LifecycleState) -> &'static str {
    match state {
        LifecycleState::Created => "created",
        LifecycleState::LoadingIdentity => "loading_identity",
        LifecycleState::LoadingStore => "loading_store",
        LifecycleState::StartingPlatform => "starting_platform",
        LifecycleState::StartingDiscovery => "starting_discovery",
        LifecycleState::Ready => "ready",
        LifecycleState::ShuttingDown => "shutting_down",
        LifecycleState::Stopped => "stopped",
    }
}

const fn session_active(state: SessionState) -> bool {
    !matches!(
        state,
        SessionState::Disconnected | SessionState::Released | SessionState::Closed
    )
}
