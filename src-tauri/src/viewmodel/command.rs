use std::collections::HashSet;
use std::fmt::{Display, Formatter};

use crate::messages::FeaturePolicy;
use crate::messages::PrivilegeProvider;
use identity::{validate_device_id, validate_display_name};
use proto::limits::ProtocolLimits;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneScreenMode {
    Viewer,
    Controller,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AppCommand {
    GetSnapshot,
    GetDiagnostics,
    Shutdown,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityCommand {
    Get,
    SetName { display_name: String },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DevicesCommand {
    List,
    StartDiscovery,
    StopDiscovery,
    Forget { device_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PairCommand {
    Start {
        device_id: String,
        transport_hint: Option<String>,
    },
    Confirm {
        pairing_id: String,
    },
    Cancel {
        pairing_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCommand {
    Connect { device_id: String },
    Disconnect { session_id: String },
    Takeover { session_id: String },
    Release { session_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyCommand {
    Get {
        peer_id: String,
    },
    Set {
        peer_id: String,
        base_revision: u64,
        changes: Vec<FeaturePolicy>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClipboardCommand {
    GetHistory {
        peer_id: Option<String>,
    },
    ClearHistory,
    SetPolicy {
        peer_id: String,
        policy: FeaturePolicy,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesCommand {
    ChooseSources,
    ChooseDestination,
    Send {
        peer_id: String,
        source_handles: Vec<String>,
    },
    Cancel {
        transfer_id: String,
    },
    Pause {
        transfer_id: String,
    },
    Resume {
        transfer_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderShareCommand {
    Start {
        peer_id: String,
        folder_handle: String,
    },
    Stop {
        share_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneCommand {
    RequestApps {
        session_id: String,
    },
    OpenScreen {
        session_id: String,
        mode: PhoneScreenMode,
    },
    CloseScreen {
        session_id: String,
    },
    RequestPrivilege {
        session_id: String,
        capability: String,
        provider_hint: Option<PrivilegeProvider>,
    },
    CancelPrivilegeRequest {
        request_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScreenCommand {
    Start { session_id: String, mode: String },
    Stop { session_id: String },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioCommand {
    Start {
        session_id: String,
        direction: String,
    },
    Stop {
        session_id: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputCommand {
    SetLayout { session_id: String, layout: String },
    Take { session_id: String },
    Release { session_id: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticsCommand {
    Export,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiCommand {
    App(AppCommand),
    Identity(IdentityCommand),
    Devices(DevicesCommand),
    Pair(PairCommand),
    Session(SessionCommand),
    Policy(PolicyCommand),
    Clipboard(ClipboardCommand),
    Files(FilesCommand),
    FolderShare(FolderShareCommand),
    Phone(PhoneCommand),
    Screen(ScreenCommand),
    Audio(AudioCommand),
    Input(InputCommand),
    Diagnostics(DiagnosticsCommand),
}

impl UiCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::App(command) => command.validate(),
            Self::Identity(command) => command.validate(),
            Self::Devices(command) => command.validate(),
            Self::Pair(command) => command.validate(),
            Self::Session(command) => command.validate(),
            Self::Policy(command) => command.validate(),
            Self::Clipboard(command) => command.validate(),
            Self::Files(command) => command.validate(),
            Self::FolderShare(command) => command.validate(),
            Self::Phone(command) => command.validate(),
            Self::Screen(command) => command.validate(),
            Self::Audio(command) => command.validate(),
            Self::Input(command) => command.validate(),
            Self::Diagnostics(command) => command.validate(),
        }
    }
}

impl AppCommand {
    pub fn validate(&self) -> eros::Result<()> {
        Ok(())
    }
}

impl IdentityCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::Get => Ok(()),
            Self::SetName { display_name } => validate_display_name(display_name),
        }
    }
}

impl DevicesCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::List | Self::StartDiscovery | Self::StopDiscovery => Ok(()),
            Self::Forget { device_id } => validate_device_id(device_id),
        }
    }
}

impl PairCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::Start {
                device_id,
                transport_hint,
            } => {
                validate_device_id(device_id)?;
                validate_optional_token("transport_hint", transport_hint.as_deref())
            }
            Self::Confirm { pairing_id } | Self::Cancel { pairing_id } => {
                validate_token("pairing_id", pairing_id)
            }
        }
    }
}

impl SessionCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::Connect { device_id } => validate_device_id(device_id),
            Self::Disconnect { session_id }
            | Self::Takeover { session_id }
            | Self::Release { session_id } => validate_token("session_id", session_id),
        }
    }
}

impl PolicyCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::Get { peer_id } => validate_device_id(peer_id),
            Self::Set {
                peer_id, changes, ..
            } => {
                validate_device_id(peer_id)?;
                validate_policy_changes(changes)
            }
        }
    }
}

impl ClipboardCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::GetHistory { peer_id } => {
                if let Some(peer_id) = peer_id {
                    validate_device_id(peer_id)?;
                }
                Ok(())
            }
            Self::ClearHistory => Ok(()),
            Self::SetPolicy { peer_id, policy } => {
                validate_device_id(peer_id)?;
                policy.validate()
            }
        }
    }
}

impl FilesCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::ChooseSources | Self::ChooseDestination => Ok(()),
            Self::Send {
                peer_id,
                source_handles,
            } => {
                validate_device_id(peer_id)?;
                validate_token_batch("source_handles", source_handles)
            }
            Self::Cancel { transfer_id }
            | Self::Pause { transfer_id }
            | Self::Resume { transfer_id } => validate_token("transfer_id", transfer_id),
        }
    }
}

impl FolderShareCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::Start {
                peer_id,
                folder_handle,
            } => {
                validate_device_id(peer_id)?;
                validate_token("folder_handle", folder_handle)
            }
            Self::Stop { share_id } => validate_token("share_id", share_id),
        }
    }
}

impl PhoneCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::RequestApps { session_id } | Self::CloseScreen { session_id } => {
                validate_token("session_id", session_id)
            }
            Self::OpenScreen { session_id, .. } => validate_token("session_id", session_id),
            Self::RequestPrivilege {
                session_id,
                capability,
                ..
            } => {
                validate_token("session_id", session_id)?;
                validate_identifier("capability", capability)
            }
            Self::CancelPrivilegeRequest { request_id } => validate_token("request_id", request_id),
        }
    }
}

impl ScreenCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::Start { session_id, mode } => {
                validate_token("session_id", session_id)?;
                validate_token("mode", mode)
            }
            Self::Stop { session_id } => validate_token("session_id", session_id),
        }
    }
}

impl AudioCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::Start {
                session_id,
                direction,
            } => {
                validate_token("session_id", session_id)?;
                validate_token("direction", direction)
            }
            Self::Stop { session_id } => validate_token("session_id", session_id),
        }
    }
}

impl InputCommand {
    pub fn validate(&self) -> eros::Result<()> {
        match self {
            Self::SetLayout { session_id, layout } => {
                validate_token("session_id", session_id)?;
                validate_token("layout", layout)
            }
            Self::Take { session_id } | Self::Release { session_id } => {
                validate_token("session_id", session_id)
            }
        }
    }
}

impl DiagnosticsCommand {
    pub fn validate(&self) -> eros::Result<()> {
        Ok(())
    }
}

fn validate_token(field: &'static str, value: &str) -> eros::Result<()> {
    ProtocolLimits::default().validate_string(field, value)?;

    if value != value.trim() {
        return Err(eros::error!(CommandError::UnexpectedWhitespace { field }));
    }
    if value.chars().any(char::is_control) {
        return Err(eros::error!(CommandError::ControlCharacter { field }));
    }

    Ok(())
}

fn validate_optional_token(field: &'static str, value: Option<&str>) -> eros::Result<()> {
    if let Some(value) = value {
        validate_token(field, value)?;
    }

    Ok(())
}

fn validate_identifier(field: &'static str, value: &str) -> eros::Result<()> {
    validate_token(field, value)?;

    if value.chars().any(|character| {
        !character.is_ascii_alphanumeric() && !matches!(character, '.' | '_' | '-' | ':')
    }) {
        return Err(eros::error!(CommandError::InvalidIdentifierCharacter {
            field
        }));
    }

    Ok(())
}

fn validate_token_batch(field: &'static str, values: &[String]) -> eros::Result<()> {
    if values.is_empty() {
        return Err(eros::error!(CommandError::EmptyBatch { field }));
    }

    ProtocolLimits::default().validate_batch(field, values.len())?;

    let mut seen = HashSet::with_capacity(values.len());
    for value in values {
        validate_token(field, value)?;
        if !seen.insert(value.as_str()) {
            return Err(eros::error!(CommandError::DuplicateEntry { field }));
        }
    }

    Ok(())
}

fn validate_policy_changes(changes: &[FeaturePolicy]) -> eros::Result<()> {
    if changes.is_empty() {
        return Err(eros::error!(CommandError::EmptyBatch { field: "changes" }));
    }

    ProtocolLimits::default().validate_batch("changes", changes.len())?;

    let mut seen = HashSet::with_capacity(changes.len());
    for policy in changes {
        policy.validate()?;
        if !seen.insert(policy.feature.as_str()) {
            return Err(eros::error!(CommandError::DuplicateEntry {
                field: "changes"
            }));
        }
    }

    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum CommandError {
    EmptyBatch { field: &'static str },
    DuplicateEntry { field: &'static str },
    UnexpectedWhitespace { field: &'static str },
    ControlCharacter { field: &'static str },
    InvalidIdentifierCharacter { field: &'static str },
}

impl Display for CommandError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyBatch { field } => {
                write!(
                    formatter,
                    "command field {field} must contain at least one item"
                )
            }
            Self::DuplicateEntry { field } => {
                write!(formatter, "command field {field} contains duplicate items")
            }
            Self::UnexpectedWhitespace { field } => write!(
                formatter,
                "command field {field} has unexpected surrounding whitespace"
            ),
            Self::ControlCharacter { field } => {
                write!(
                    formatter,
                    "command field {field} contains a control character"
                )
            }
            Self::InvalidIdentifierCharacter { field } => write!(
                formatter,
                "command field {field} contains an invalid identifier character"
            ),
        }
    }
}

impl std::error::Error for CommandError {}
