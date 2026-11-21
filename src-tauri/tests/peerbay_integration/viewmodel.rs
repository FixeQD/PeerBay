use std::collections::BTreeMap;
use std::time::Instant;

use identity::DeviceIdentity;
use peerbay_lib::app::LifecycleState;
use peerbay_lib::discovery::DiscoveredPeer;
use peerbay_lib::session::SessionState;
use peerbay_lib::storage::PeerRecord;
use peerbay_lib::viewmodel::{
    AppCommand, AppViewModel, AudioCommand, ClipboardCommand, CommandError, DeviceAction,
    DeviceView, DevicesCommand, DiagnosticsCommand, ErrorDetail, ErrorFeatureScope, ErrorView,
    FeatureRowState, FeatureRowView, FilesCommand, FolderShareCommand, IdentityCommand,
    InputCommand, MAX_DEVICES, MAX_SESSIONS, MAX_SNAPSHOT_BYTES, PairCommand, PhoneCommand,
    PhoneScreenMode, PolicyCommand, ScreenCommand, SessionCommand, SessionSummary, SnapshotInputs,
    TrustStatus, UiCommand, VIEWMODEL_SCHEMA_VERSION, ViewModelError, ViewModelErrorCode,
};
use proto::{CapabilityDocument, ProtocolLimitError};

use peerbay_lib::messages::{FeaturePolicy, PolicyError, PrivilegeProvider, UserPolicyState};

const LOCAL_DEVICE_ID: &str = "33333333-3333-4333-8333-333333333333";
const PEER_DEVICE_ID: &str = "11111111-1111-4111-8111-111111111111";
const OTHER_DEVICE_ID: &str = "22222222-2222-4222-8222-222222222222";
const SNAPSHOT_NOW_MS: u64 = 1_700_000_000_000;

fn local_identity() -> DeviceIdentity {
    DeviceIdentity::new(LOCAL_DEVICE_ID, "Local Device").unwrap()
}

fn local_capabilities() -> CapabilityDocument {
    CapabilityDocument::new(
        "linux",
        "6.1",
        vec![1],
        vec!["tcp".to_string()],
        vec!["clipboard".to_string()],
        Vec::new(),
        1_048_576,
        65_536,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap()
}

fn capabilities_snapshot() -> String {
    serde_json::to_string(&local_capabilities()).unwrap()
}

fn trusted_record(device_id: &str, display_name: &str) -> PeerRecord {
    PeerRecord::new(
        device_id,
        display_name,
        "android",
        "a".repeat(64),
        "b".repeat(64),
        "tcp",
    )
}

fn discovered_peer(device_id: &str) -> DiscoveredPeer {
    DiscoveredPeer {
        device_id: device_id.to_owned(),
        platform: "android".to_owned(),
        port: 47_000,
        addresses: BTreeMap::new(),
        last_seen: Instant::now(),
    }
}

fn session_summary(session_id: &str, device_id: &str, state: SessionState) -> SessionSummary {
    SessionSummary {
        session_id: session_id.to_owned(),
        device_id: device_id.to_owned(),
        state,
        transport_label: "tcp".to_owned(),
        rtt_ms: Some(12),
        open_channels: 1,
    }
}

fn snapshot_inputs<'a>(
    identity: &'a DeviceIdentity,
    capabilities: &'a CapabilityDocument,
    discovered: &'a [DiscoveredPeer],
    trusted: &'a [PeerRecord],
    sessions: &'a [SessionSummary],
) -> SnapshotInputs<'a> {
    SnapshotInputs {
        now_ms: SNAPSHOT_NOW_MS,
        lifecycle: LifecycleState::Ready,
        identity,
        capabilities,
        discovered,
        trusted,
        sessions,
        active_workers: 2,
    }
}

fn enabled_actions(device: &DeviceView) -> Vec<DeviceAction> {
    device
        .available_actions
        .iter()
        .filter(|entry| entry.enabled)
        .map(|entry| entry.action)
        .collect()
}

fn disabled_reason(device: &DeviceView, action: DeviceAction) -> Option<&str> {
    device
        .available_actions
        .iter()
        .find(|entry| entry.action == action)
        .and_then(|entry| entry.disabled_reason.as_deref())
}

fn viewmodel_error(result: eros::Result<AppViewModel>) -> ViewModelError {
    result
        .expect_err("snapshot build should fail")
        .downcast_inner::<ViewModelError>()
        .expect("viewmodel error should be preserved")
}

fn generated_device_id(index: usize) -> String {
    format!("{:08x}-0000-4000-8000-{:012x}", 0x1000 + index, index + 1)
}

fn bulky_capabilities_snapshot() -> String {
    let features: Vec<String> = (0..64).map(|index| format!("feature-{index:02}")).collect();
    let document = CapabilityDocument::new(
        "linux",
        "6.1",
        vec![1],
        vec!["tcp".to_string()],
        features,
        Vec::new(),
        1_048_576,
        65_536,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    serde_json::to_string(&document).unwrap()
}

#[test]
fn gateway_starts_with_privacy_safe_defaults() {
    assert!(peerbay_lib::viewmodel::ViewModelGateway::new().is_privacy_safe());
}

#[test]
fn empty_inputs_build_valid_snapshot_and_roundtrip() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let snapshot =
        AppViewModel::build(snapshot_inputs(&identity, &capabilities, &[], &[], &[])).unwrap();

    assert_eq!(snapshot.schema_version, VIEWMODEL_SCHEMA_VERSION);
    assert_eq!(snapshot.emitted_at_ms, SNAPSHOT_NOW_MS);
    assert_eq!(snapshot.app.lifecycle, "ready");
    assert!(snapshot.app.ready);
    assert_eq!(snapshot.identity.device_id, LOCAL_DEVICE_ID);
    assert_eq!(snapshot.diagnostics.active_workers, 2);
    assert_eq!(snapshot.diagnostics.discovered_count, 0);
    assert_eq!(snapshot.diagnostics.trusted_count, 0);
    assert_eq!(snapshot.diagnostics.revoked_count, 0);
    assert!(snapshot.devices.is_empty());
    assert!(snapshot.sessions.is_empty());

    let serialized = serde_json::to_string(&snapshot).unwrap();
    assert!(serialized.contains("\"schema_version\""));
    assert!(serialized.contains("\"emitted_at_ms\""));
    assert!(serialized.contains("\"active_workers\""));
    assert!(!serialized.contains("\"schemaVersion\""));
    let deserialized: AppViewModel = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, snapshot);
}

#[test]
fn trusted_and_discovered_dedup_by_device_id_with_trusted_wins() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let mut record = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    record.platform = "windows".to_owned();
    let discovered = vec![discovered_peer(PEER_DEVICE_ID)];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &discovered,
        std::slice::from_ref(&record),
        &[],
    ))
    .unwrap();

    assert_eq!(snapshot.devices.len(), 1);
    let device = &snapshot.devices[0];
    assert_eq!(device.device_id, PEER_DEVICE_ID);
    assert_eq!(device.trust, TrustStatus::Trusted);
    assert_eq!(device.display_name, "Phone Alpha");
    assert_eq!(device.platform, "windows");
    assert_eq!(snapshot.diagnostics.discovered_count, 1);
    assert_eq!(snapshot.diagnostics.trusted_count, 1);
    assert_eq!(snapshot.diagnostics.revoked_count, 0);
}

#[test]
fn serialized_snapshot_contains_no_full_fingerprint_or_token_hash() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let record = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        std::slice::from_ref(&record),
        &[],
    ))
    .unwrap();
    let serialized = serde_json::to_string(&snapshot).unwrap();

    assert!(!serialized.contains(&"a".repeat(64)));
    assert!(!serialized.contains(&"b".repeat(64)));
    let device = &snapshot.devices[0];
    assert_eq!(device.fingerprint_preview.as_deref(), Some("aaaa***"));
}

#[test]
fn revoked_peer_is_visible_with_disabled_actions() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let mut record = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    record.capabilities_snapshot = capabilities_snapshot();
    record.revoke(SNAPSHOT_NOW_MS - 1_000);
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        std::slice::from_ref(&record),
        &[],
    ))
    .unwrap();

    let device = &snapshot.devices[0];
    assert_eq!(device.trust, TrustStatus::Revoked);
    assert_eq!(device.fingerprint_preview, None);
    assert_eq!(device.blocked_reason.as_deref(), Some("peer_revoked"));
    assert_eq!(device.connection_state, "offline");
    assert!(device.feature_rows.is_empty());
    for entry in &device.available_actions {
        assert!(!entry.enabled);
        assert_eq!(entry.disabled_reason.as_deref(), Some("peer_revoked"));
    }
    assert_eq!(snapshot.diagnostics.trusted_count, 0);
    assert_eq!(snapshot.diagnostics.revoked_count, 1);
}

#[test]
fn actions_follow_trust_and_session_state() {
    let identity = local_identity();
    let capabilities = local_capabilities();

    let discovered = vec![discovered_peer(PEER_DEVICE_ID)];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &discovered,
        &[],
        &[],
    ))
    .unwrap();
    let device = &snapshot.devices[0];
    assert_eq!(enabled_actions(device), vec![DeviceAction::PairStart]);
    assert_eq!(
        disabled_reason(device, DeviceAction::SessionConnect),
        Some("not_paired")
    );
    assert_eq!(device.connection_state, "discovered");
    assert_eq!(device.fingerprint_preview, None);

    let trusted = vec![trusted_record(OTHER_DEVICE_ID, "Laptop Beta")];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &[],
    ))
    .unwrap();
    let device = &snapshot.devices[0];
    assert_eq!(
        enabled_actions(device),
        vec![DeviceAction::SessionConnect, DeviceAction::DevicesForget]
    );
    assert_eq!(
        disabled_reason(device, DeviceAction::PairStart),
        Some("already_paired")
    );
    assert_eq!(
        disabled_reason(device, DeviceAction::SessionDisconnect),
        Some("no_session")
    );
    assert_eq!(device.connection_state, "offline");

    let sessions = vec![session_summary(
        "session-1",
        OTHER_DEVICE_ID,
        SessionState::Connected,
    )];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &sessions,
    ))
    .unwrap();
    let device = &snapshot.devices[0];
    assert_eq!(
        enabled_actions(device),
        vec![
            DeviceAction::SessionDisconnect,
            DeviceAction::SessionTakeover,
            DeviceAction::SessionRelease,
            DeviceAction::DevicesForget,
        ]
    );
    assert_eq!(
        disabled_reason(device, DeviceAction::SessionConnect),
        Some("session_active")
    );
    assert_eq!(
        disabled_reason(device, DeviceAction::PairStart),
        Some("already_paired")
    );
    assert_eq!(device.connection_state, "connected");
    assert_eq!(device.transport_label.as_deref(), Some("tcp"));
    assert_eq!(device.rtt_ms, Some(12));

    let released = vec![session_summary(
        "session-1",
        OTHER_DEVICE_ID,
        SessionState::Released,
    )];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &released,
    ))
    .unwrap();
    let device = &snapshot.devices[0];
    assert_eq!(
        enabled_actions(device),
        vec![DeviceAction::SessionConnect, DeviceAction::DevicesForget]
    );
    assert_eq!(device.connection_state, "released");

    let closed = vec![session_summary(
        "session-1",
        OTHER_DEVICE_ID,
        SessionState::Closed,
    )];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &closed,
    ))
    .unwrap();
    let device = &snapshot.devices[0];
    assert_eq!(
        enabled_actions(device),
        vec![DeviceAction::SessionConnect, DeviceAction::DevicesForget]
    );
    assert_eq!(device.connection_state, "offline");
    assert_eq!(device.transport_label, None);
}

#[test]
fn session_referential_integrity_is_enforced() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let trusted = vec![trusted_record(PEER_DEVICE_ID, "Phone Alpha")];
    let sessions = vec![session_summary(
        "session-1",
        "99999999-9999-4999-8999-999999999999",
        SessionState::Connected,
    )];
    let error = viewmodel_error(AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &sessions,
    )));
    assert_eq!(error, ViewModelError::UnknownSessionPeer);

    let mut revoked = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    revoked.revoke(SNAPSHOT_NOW_MS - 1_000);
    let revoked_trusted = vec![revoked];
    let sessions = vec![session_summary(
        "session-1",
        PEER_DEVICE_ID,
        SessionState::Connected,
    )];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &revoked_trusted,
        &sessions,
    ))
    .unwrap();
    let device = &snapshot.devices[0];
    assert_eq!(device.trust, TrustStatus::Revoked);
    assert_eq!(device.connection_state, "connected");
    assert!(device.available_actions.iter().all(|entry| !entry.enabled));
}

#[test]
fn peer_strings_are_validated_at_emission() {
    let identity = local_identity();
    let capabilities = local_capabilities();

    let mut control_name = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    control_name.display_name = "Phone\u{0007}Alpha".to_owned();
    let error = viewmodel_error(AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        std::slice::from_ref(&control_name),
        &[],
    )));
    assert_eq!(
        error,
        ViewModelError::InvalidPeerField {
            field: "display_name"
        }
    );
    assert!(!error.to_string().contains("Phone"));

    let mut unicode_name = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    unicode_name.display_name = "Telefon Zażółć Gęślą Jaźń".to_owned();
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        std::slice::from_ref(&unicode_name),
        &[],
    ))
    .unwrap();
    assert_eq!(
        snapshot.devices[0].display_name,
        "Telefon Zażółć Gęślą Jaźń"
    );

    let mut control_platform = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    control_platform.platform = "android\u{0000}".to_owned();
    let error = viewmodel_error(AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        std::slice::from_ref(&control_platform),
        &[],
    )));
    assert_eq!(
        error,
        ViewModelError::InvalidPeerField { field: "platform" }
    );
}

#[test]
fn oversized_inputs_fail_closed() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let discovered: Vec<DiscoveredPeer> = (0..MAX_DEVICES + 1)
        .map(|index| discovered_peer(&generated_device_id(index)))
        .collect();
    let error = viewmodel_error(AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &discovered,
        &[],
        &[],
    )));
    assert_eq!(
        error,
        ViewModelError::TooManyDevices {
            count: MAX_DEVICES + 1
        }
    );

    let trusted = vec![trusted_record(PEER_DEVICE_ID, "Phone Alpha")];
    let sessions: Vec<SessionSummary> = (0..MAX_SESSIONS + 1)
        .map(|index| {
            session_summary(
                &format!("session-{index:04}"),
                PEER_DEVICE_ID,
                SessionState::Connected,
            )
        })
        .collect();
    let error = viewmodel_error(AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &sessions,
    )));
    assert_eq!(
        error,
        ViewModelError::TooManySessions {
            count: MAX_SESSIONS + 1
        }
    );
}

#[test]
fn giant_serialized_snapshot_is_rejected() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let snapshot_json = bulky_capabilities_snapshot();
    let trusted: Vec<PeerRecord> = (0..MAX_DEVICES)
        .map(|index| {
            let mut record = trusted_record(&generated_device_id(index), &"n".repeat(128));
            record.capabilities_snapshot = snapshot_json.clone();
            record
        })
        .collect();
    let error = viewmodel_error(AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &[],
    )));
    let ViewModelError::SnapshotTooLarge { size } = error else {
        panic!("expected SnapshotTooLarge error");
    };
    assert!(size > MAX_SNAPSHOT_BYTES);
}

#[test]
fn capabilities_snapshot_parses_to_feature_rows() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let mut record = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    record.capabilities_snapshot = capabilities_snapshot();
    let trusted = vec![record];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &[],
    ))
    .unwrap();

    let device = &snapshot.devices[0];
    assert_eq!(
        device.feature_rows,
        vec![FeatureRowView {
            feature_id: "clipboard".to_owned(),
            state: FeatureRowState::AvailableAllowed,
            disabled_reason: None,
            next_step: None,
        }]
    );
    let serialized = serde_json::to_string(&snapshot).unwrap();
    assert!(serialized.contains("\"feature_rows\""));
    assert!(serialized.contains("\"feature_id\""));
    assert!(serialized.contains("\"available_allowed\""));

    let mut empty_record = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    empty_record.capabilities_snapshot = String::new();
    let trusted = vec![empty_record];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &[],
    ))
    .unwrap();
    assert!(snapshot.devices[0].feature_rows.is_empty());

    let mut corrupt_record = trusted_record(PEER_DEVICE_ID, "Phone Alpha");
    corrupt_record.capabilities_snapshot = "{\"platform\":\"linux\"}".to_owned();
    let trusted = vec![corrupt_record];
    let snapshot = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &[],
    ))
    .unwrap();
    assert!(snapshot.devices[0].feature_rows.is_empty());
}

#[test]
fn snapshot_ordering_is_deterministic() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let discovered = vec![
        discovered_peer(OTHER_DEVICE_ID),
        discovered_peer(PEER_DEVICE_ID),
    ];
    let sessions = vec![
        session_summary("session-b", PEER_DEVICE_ID, SessionState::Connected),
        session_summary("session-a", OTHER_DEVICE_ID, SessionState::Degraded),
    ];
    let forward = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &discovered,
        &[],
        &sessions,
    ))
    .unwrap();

    let mut reversed_discovered = discovered.clone();
    reversed_discovered.reverse();
    let mut reversed_sessions = sessions.clone();
    reversed_sessions.reverse();
    let backward = AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &reversed_discovered,
        &[],
        &reversed_sessions,
    ))
    .unwrap();

    assert_eq!(forward, backward);
    assert_eq!(forward.devices[0].device_id, PEER_DEVICE_ID);
    assert_eq!(forward.devices[1].device_id, OTHER_DEVICE_ID);
    assert_eq!(forward.sessions[0].session_id, "session-a");
    assert_eq!(forward.sessions[1].session_id, "session-b");
    assert_eq!(forward.devices[0].connection_state, "connected");
    assert_eq!(forward.devices[1].connection_state, "degraded");
}

#[test]
fn local_identity_view_excludes_secret_material() {
    let identity = local_identity();
    let capabilities = local_capabilities();
    let snapshot =
        AppViewModel::build(snapshot_inputs(&identity, &capabilities, &[], &[], &[])).unwrap();

    assert_eq!(snapshot.identity.display_name, "Local Device");
    assert_eq!(snapshot.identity.platform, "linux");
    assert_eq!(snapshot.identity.platform_version, "6.1");
    assert_eq!(snapshot.identity.protocol_versions, vec![1]);
    assert_eq!(snapshot.identity.features, vec!["clipboard"]);
    assert_eq!(snapshot.identity.max_file_size, 1_048_576);
    assert_eq!(snapshot.identity.max_message_size, 65_536);

    let serialized = serde_json::to_string(&snapshot.identity).unwrap();
    assert!(!serialized.contains("fingerprint"));
    assert!(!serialized.contains("certificate"));
    assert!(!serialized.contains("token"));
}

#[test]
fn every_viewmodel_error_maps_to_a_redacted_error_view() {
    let cases = [
        (
            ViewModelError::EmittedAtTooOld {
                value: SNAPSHOT_NOW_MS,
            },
            ViewModelErrorCode::SnapshotEmittedAtStale,
            ErrorFeatureScope::Snapshot,
            "error.snapshot_emitted_at_stale",
            None,
        ),
        (
            ViewModelError::TooManyDevices {
                count: MAX_DEVICES + 1,
            },
            ViewModelErrorCode::SnapshotDeviceLimit,
            ErrorFeatureScope::Devices,
            "error.snapshot_device_limit",
            Some(ErrorDetail::Limit {
                value: MAX_DEVICES + 1,
                limit: MAX_DEVICES,
            }),
        ),
        (
            ViewModelError::TooManySessions {
                count: MAX_SESSIONS + 1,
            },
            ViewModelErrorCode::SnapshotSessionLimit,
            ErrorFeatureScope::Sessions,
            "error.snapshot_session_limit",
            Some(ErrorDetail::Limit {
                value: MAX_SESSIONS + 1,
                limit: MAX_SESSIONS,
            }),
        ),
        (
            ViewModelError::SnapshotTooLarge {
                size: MAX_SNAPSHOT_BYTES + 1,
            },
            ViewModelErrorCode::SnapshotTooLarge,
            ErrorFeatureScope::Snapshot,
            "error.snapshot_too_large",
            Some(ErrorDetail::Limit {
                value: MAX_SNAPSHOT_BYTES + 1,
                limit: MAX_SNAPSHOT_BYTES,
            }),
        ),
        (
            ViewModelError::UnknownSessionPeer,
            ViewModelErrorCode::SnapshotSessionIntegrity,
            ErrorFeatureScope::Sessions,
            "error.snapshot_session_integrity",
            None,
        ),
        (
            ViewModelError::InvalidPeerField {
                field: "display_name",
            },
            ViewModelErrorCode::PeerFieldInvalid,
            ErrorFeatureScope::Devices,
            "error.peer_field_invalid",
            Some(ErrorDetail::Field {
                field: "display_name".to_owned(),
            }),
        ),
    ];
    for (error, code, scope, message_key, detail) in &cases {
        let view = ErrorView::from(error);
        assert_eq!(view.code, *code);
        assert_eq!(view.user_message_key, *message_key);
        assert_eq!(view.feature_scope, *scope);
        assert_eq!(view.detail, *detail);
        assert!(!view.retryable);
    }
}

#[test]
fn error_view_wire_contract_is_snake_case_and_roundtrips() {
    let limit_view = ErrorView::from(&ViewModelError::TooManyDevices {
        count: MAX_DEVICES + 1,
    });
    let serialized = serde_json::to_string(&limit_view).unwrap();
    assert!(serialized.contains("\"code\":\"snapshot_device_limit\""));
    assert!(serialized.contains("\"user_message_key\":\"error.snapshot_device_limit\""));
    assert!(serialized.contains("\"retryable\":false"));
    assert!(serialized.contains("\"feature_scope\":\"devices\""));
    assert!(serialized.contains("\"detail\":{\"limit\":{\"value\":1025,\"limit\":1024}}"));
    assert!(!serialized.contains("\"schemaVersion\""));
    let deserialized: ErrorView = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, limit_view);

    let field_view = ErrorView::from(&ViewModelError::InvalidPeerField { field: "platform" });
    let serialized = serde_json::to_string(&field_view).unwrap();
    assert!(serialized.contains("\"code\":\"peer_field_invalid\""));
    assert!(serialized.contains("\"detail\":{\"field\":{\"field\":\"platform\"}}"));
    let deserialized: ErrorView = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, field_view);
}

#[test]
fn error_views_exclude_technical_and_private_data() {
    let errors = [
        ViewModelError::EmittedAtTooOld {
            value: SNAPSHOT_NOW_MS,
        },
        ViewModelError::TooManyDevices {
            count: MAX_DEVICES + 1,
        },
        ViewModelError::TooManySessions {
            count: MAX_SESSIONS + 1,
        },
        ViewModelError::SnapshotTooLarge {
            size: MAX_SNAPSHOT_BYTES + 1,
        },
        ViewModelError::UnknownSessionPeer,
        ViewModelError::InvalidPeerField { field: "platform" },
    ];
    for error in &errors {
        let view = ErrorView::from(error);
        let serialized = serde_json::to_string(&view).unwrap();
        assert!(!serialized.contains(&"a".repeat(64)));
        assert!(!serialized.contains('/'));
        assert!(!serialized.contains('\\'));
        assert!(!serialized.contains("technical_message"));
        assert!(!serialized.contains("correlation_id"));
        assert!(!serialized.contains("platform_code"));
        assert!(!serialized.contains("stack"));
    }
}

#[test]
fn real_snapshot_build_failures_map_to_error_views() {
    let identity = local_identity();
    let capabilities = local_capabilities();

    let stale = SnapshotInputs {
        now_ms: 1_000,
        lifecycle: LifecycleState::Ready,
        identity: &identity,
        capabilities: &capabilities,
        discovered: &[],
        trusted: &[],
        sessions: &[],
        active_workers: 0,
    };
    let view = ErrorView::from(&viewmodel_error(AppViewModel::build(stale)));
    assert_eq!(view.code, ViewModelErrorCode::SnapshotEmittedAtStale);
    assert_eq!(view.feature_scope, ErrorFeatureScope::Snapshot);
    assert_eq!(view.detail, None);

    let trusted = vec![trusted_record(PEER_DEVICE_ID, "Phone Alpha")];
    let sessions = vec![session_summary(
        "session-1",
        "99999999-9999-4999-8999-999999999999",
        SessionState::Connected,
    )];
    let view = ErrorView::from(&viewmodel_error(AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &sessions,
    ))));
    assert_eq!(view.code, ViewModelErrorCode::SnapshotSessionIntegrity);
    assert_eq!(view.feature_scope, ErrorFeatureScope::Sessions);

    let sessions: Vec<SessionSummary> = (0..MAX_SESSIONS + 1)
        .map(|index| {
            session_summary(
                &format!("session-{index:04}"),
                PEER_DEVICE_ID,
                SessionState::Connected,
            )
        })
        .collect();
    let view = ErrorView::from(&viewmodel_error(AppViewModel::build(snapshot_inputs(
        &identity,
        &capabilities,
        &[],
        &trusted,
        &sessions,
    ))));
    assert_eq!(view.code, ViewModelErrorCode::SnapshotSessionLimit);
    assert_eq!(
        view.detail,
        Some(ErrorDetail::Limit {
            value: MAX_SESSIONS + 1,
            limit: MAX_SESSIONS,
        })
    );
}

fn feature_policy() -> FeaturePolicy {
    FeaturePolicy::new(
        "clipboard.text",
        UserPolicyState::Allow,
        Vec::new(),
        None,
        None,
    )
    .unwrap()
}

fn all_commands() -> Vec<UiCommand> {
    vec![
        UiCommand::App(AppCommand::GetSnapshot),
        UiCommand::App(AppCommand::GetDiagnostics),
        UiCommand::App(AppCommand::Shutdown),
        UiCommand::Identity(IdentityCommand::Get),
        UiCommand::Identity(IdentityCommand::SetName {
            display_name: "Nowa Nazwa".to_owned(),
        }),
        UiCommand::Devices(DevicesCommand::List),
        UiCommand::Devices(DevicesCommand::StartDiscovery),
        UiCommand::Devices(DevicesCommand::StopDiscovery),
        UiCommand::Devices(DevicesCommand::Forget {
            device_id: PEER_DEVICE_ID.to_owned(),
        }),
        UiCommand::Pair(PairCommand::Start {
            device_id: PEER_DEVICE_ID.to_owned(),
            transport_hint: Some("tcp".to_owned()),
        }),
        UiCommand::Pair(PairCommand::Confirm {
            pairing_id: "pair-1".to_owned(),
        }),
        UiCommand::Pair(PairCommand::Cancel {
            pairing_id: "pair-1".to_owned(),
        }),
        UiCommand::Session(SessionCommand::Connect {
            device_id: PEER_DEVICE_ID.to_owned(),
        }),
        UiCommand::Session(SessionCommand::Disconnect {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Session(SessionCommand::Takeover {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Session(SessionCommand::Release {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Policy(PolicyCommand::Get {
            peer_id: PEER_DEVICE_ID.to_owned(),
        }),
        UiCommand::Policy(PolicyCommand::Set {
            peer_id: PEER_DEVICE_ID.to_owned(),
            base_revision: 3,
            changes: vec![feature_policy()],
        }),
        UiCommand::Clipboard(ClipboardCommand::GetHistory {
            peer_id: Some(PEER_DEVICE_ID.to_owned()),
        }),
        UiCommand::Clipboard(ClipboardCommand::ClearHistory),
        UiCommand::Clipboard(ClipboardCommand::SetPolicy {
            peer_id: PEER_DEVICE_ID.to_owned(),
            policy: feature_policy(),
        }),
        UiCommand::Files(FilesCommand::ChooseSources),
        UiCommand::Files(FilesCommand::ChooseDestination),
        UiCommand::Files(FilesCommand::Send {
            peer_id: PEER_DEVICE_ID.to_owned(),
            source_handles: vec!["handle-1".to_owned(), "handle-2".to_owned()],
        }),
        UiCommand::Files(FilesCommand::Cancel {
            transfer_id: "transfer-1".to_owned(),
        }),
        UiCommand::Files(FilesCommand::Pause {
            transfer_id: "transfer-1".to_owned(),
        }),
        UiCommand::Files(FilesCommand::Resume {
            transfer_id: "transfer-1".to_owned(),
        }),
        UiCommand::FolderShare(FolderShareCommand::Start {
            peer_id: PEER_DEVICE_ID.to_owned(),
            folder_handle: "folder-1".to_owned(),
        }),
        UiCommand::FolderShare(FolderShareCommand::Stop {
            share_id: "share-1".to_owned(),
        }),
        UiCommand::Phone(PhoneCommand::RequestApps {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Phone(PhoneCommand::OpenScreen {
            session_id: "session-1".to_owned(),
            mode: PhoneScreenMode::Viewer,
        }),
        UiCommand::Phone(PhoneCommand::CloseScreen {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Phone(PhoneCommand::RequestPrivilege {
            session_id: "session-1".to_owned(),
            capability: "phone.input.root".to_owned(),
            provider_hint: Some(PrivilegeProvider::Root),
        }),
        UiCommand::Phone(PhoneCommand::CancelPrivilegeRequest {
            request_id: "request-1".to_owned(),
        }),
        UiCommand::Screen(ScreenCommand::Start {
            session_id: "session-1".to_owned(),
            mode: "primary".to_owned(),
        }),
        UiCommand::Screen(ScreenCommand::Stop {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Audio(AudioCommand::Start {
            session_id: "session-1".to_owned(),
            direction: "to_peer".to_owned(),
        }),
        UiCommand::Audio(AudioCommand::Stop {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Input(InputCommand::SetLayout {
            session_id: "session-1".to_owned(),
            layout: "pl".to_owned(),
        }),
        UiCommand::Input(InputCommand::Take {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Input(InputCommand::Release {
            session_id: "session-1".to_owned(),
        }),
        UiCommand::Diagnostics(DiagnosticsCommand::Export),
    ]
}

#[test]
fn full_command_catalog_roundtrips_and_validates() {
    let commands = all_commands();
    assert_eq!(commands.len(), 42);
    for command in &commands {
        command
            .validate()
            .expect("catalog command must pass validation");
        let serialized = serde_json::to_string(command).unwrap();
        let deserialized: UiCommand = serde_json::from_str(&serialized).unwrap();
        assert_eq!(&deserialized, command);
    }
}

#[test]
fn command_wire_contract_is_snake_case() {
    let command = UiCommand::App(AppCommand::GetSnapshot);
    assert_eq!(
        serde_json::to_string(&command).unwrap(),
        "{\"app\":\"get_snapshot\"}"
    );

    let command = UiCommand::Session(SessionCommand::Connect {
        device_id: PEER_DEVICE_ID.to_owned(),
    });
    assert_eq!(
        serde_json::to_string(&command).unwrap(),
        "{\"session\":{\"connect\":{\"device_id\":\"11111111-1111-4111-8111-111111111111\"}}}"
    );

    let command = UiCommand::Phone(PhoneCommand::OpenScreen {
        session_id: "session-1".to_owned(),
        mode: PhoneScreenMode::Controller,
    });
    let serialized = serde_json::to_string(&command).unwrap();
    assert!(serialized.contains("\"open_screen\""));
    assert!(serialized.contains("\"mode\":\"controller\""));

    let command = UiCommand::FolderShare(FolderShareCommand::Stop {
        share_id: "share-1".to_owned(),
    });
    let serialized = serde_json::to_string(&command).unwrap();
    assert!(serialized.contains("\"folder_share\""));

    assert!(serde_json::from_str::<PhoneScreenMode>("\"mirror\"").is_err());
}

#[test]
fn command_validation_rejects_invalid_shapes() {
    let malformed = UiCommand::Devices(DevicesCommand::Forget {
        device_id: "not-a-uuid".to_owned(),
    });
    assert!(malformed.validate().is_err());

    let nil = UiCommand::Devices(DevicesCommand::Forget {
        device_id: "00000000-0000-0000-0000-000000000000".to_owned(),
    });
    assert!(nil.validate().is_err());

    let non_canonical = UiCommand::Devices(DevicesCommand::Forget {
        device_id: "abcdefab-1234-4abc-8def-abcdefabcdef".to_uppercase(),
    });
    assert!(non_canonical.validate().is_err());

    for display_name in ["", " x", "\u{0007}", "x\u{0000}"] {
        let command = UiCommand::Identity(IdentityCommand::SetName {
            display_name: display_name.to_owned(),
        });
        assert!(
            command.validate().is_err(),
            "name {display_name:?} must fail"
        );
    }
    let too_long_name = UiCommand::Identity(IdentityCommand::SetName {
        display_name: "n".repeat(129),
    });
    assert!(too_long_name.validate().is_err());

    let blank_session = UiCommand::Session(SessionCommand::Disconnect {
        session_id: "   ".to_owned(),
    });
    let error = blank_session.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<ProtocolLimitError>().ok(),
        Some(ProtocolLimitError::InvalidIdentifier {
            field: "session_id"
        })
    );

    let control_session = UiCommand::Session(SessionCommand::Disconnect {
        session_id: "sess\u{0007}ion".to_owned(),
    });
    let error = control_session.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<CommandError>().ok(),
        Some(CommandError::ControlCharacter {
            field: "session_id"
        })
    );

    let padded_session = UiCommand::Session(SessionCommand::Disconnect {
        session_id: " session-1".to_owned(),
    });
    let error = padded_session.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<CommandError>().ok(),
        Some(CommandError::UnexpectedWhitespace {
            field: "session_id"
        })
    );

    let oversized_session = UiCommand::Session(SessionCommand::Disconnect {
        session_id: "s".repeat(4097),
    });
    let error = oversized_session.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<ProtocolLimitError>().ok(),
        Some(ProtocolLimitError::StringTooLong {
            field: "session_id",
            length: 4097,
            max: 4096,
        })
    );

    let empty_send = UiCommand::Files(FilesCommand::Send {
        peer_id: PEER_DEVICE_ID.to_owned(),
        source_handles: Vec::new(),
    });
    let error = empty_send.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<CommandError>().ok(),
        Some(CommandError::EmptyBatch {
            field: "source_handles"
        })
    );

    let duplicate_send = UiCommand::Files(FilesCommand::Send {
        peer_id: PEER_DEVICE_ID.to_owned(),
        source_handles: vec!["handle-1".to_owned(), "handle-1".to_owned()],
    });
    let error = duplicate_send.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<CommandError>().ok(),
        Some(CommandError::DuplicateEntry {
            field: "source_handles"
        })
    );

    let oversized_send = UiCommand::Files(FilesCommand::Send {
        peer_id: PEER_DEVICE_ID.to_owned(),
        source_handles: (0..257).map(|index| format!("handle-{index:04}")).collect(),
    });
    let error = oversized_send.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<ProtocolLimitError>().ok(),
        Some(ProtocolLimitError::BatchTooLarge {
            field: "source_handles",
            count: 257,
            max: 256,
        })
    );

    let empty_changes = UiCommand::Policy(PolicyCommand::Set {
        peer_id: PEER_DEVICE_ID.to_owned(),
        base_revision: 1,
        changes: Vec::new(),
    });
    let error = empty_changes.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<CommandError>().ok(),
        Some(CommandError::EmptyBatch { field: "changes" })
    );

    let invalid_policy = FeaturePolicy {
        feature: "clipboard.text".to_owned(),
        state: UserPolicyState::Allow,
        limitations: vec!["max-10".to_owned()],
        max_bytes: None,
        expires_at_ms: None,
    };
    let restricted_change = UiCommand::Policy(PolicyCommand::Set {
        peer_id: PEER_DEVICE_ID.to_owned(),
        base_revision: 1,
        changes: vec![invalid_policy],
    });
    let error = restricted_change.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<PolicyError>().ok(),
        Some(PolicyError::RestrictionsRequireLimitedState {
            feature: "clipboard.text".to_owned(),
        })
    );

    let bad_capability = UiCommand::Phone(PhoneCommand::RequestPrivilege {
        session_id: "session-1".to_owned(),
        capability: "phone input root".to_owned(),
        provider_hint: None,
    });
    let error = bad_capability.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<CommandError>().ok(),
        Some(CommandError::InvalidIdentifierCharacter {
            field: "capability"
        })
    );

    let local_history = UiCommand::Clipboard(ClipboardCommand::GetHistory { peer_id: None });
    assert!(local_history.validate().is_ok());

    let unicode_name = UiCommand::Identity(IdentityCommand::SetName {
        display_name: "Telefon Zażółć Gęślą Jaźń".to_owned(),
    });
    assert!(unicode_name.validate().is_ok());
}

#[test]
fn command_payloads_exclude_domain_and_secret_material() {
    for command in all_commands() {
        let serialized = serde_json::to_string(&command).unwrap();
        assert!(!serialized.contains("fingerprint"));
        assert!(!serialized.contains("certificate"));
        assert!(!serialized.contains("private_key"));
        assert!(!serialized.contains("token_hash"));
        assert!(!serialized.contains(&"a".repeat(64)));
    }
}

#[test]
fn policy_commands_reuse_feature_policy_contract() {
    let allow_limited = FeaturePolicy::new(
        "clipboard.files",
        UserPolicyState::AllowLimited,
        Vec::new(),
        Some(1024),
        None,
    )
    .unwrap();
    let command = UiCommand::Policy(PolicyCommand::Set {
        peer_id: PEER_DEVICE_ID.to_owned(),
        base_revision: 7,
        changes: vec![allow_limited.clone()],
    });
    assert!(command.validate().is_ok());

    let serialized = serde_json::to_string(&command).unwrap();
    assert!(serialized.contains("\"base_revision\":7"));
    assert!(serialized.contains("\"allow_limited\""));
    assert!(serialized.contains("\"max_bytes\":1024"));

    let deserialized: UiCommand = serde_json::from_str(&serialized).unwrap();
    assert_eq!(deserialized, command);

    let duplicate_features = UiCommand::Policy(PolicyCommand::Set {
        peer_id: PEER_DEVICE_ID.to_owned(),
        base_revision: 7,
        changes: vec![allow_limited.clone(), allow_limited],
    });
    let error = duplicate_features.validate().unwrap_err();
    assert_eq!(
        error.downcast_inner::<CommandError>().ok(),
        Some(CommandError::DuplicateEntry { field: "changes" })
    );
}
