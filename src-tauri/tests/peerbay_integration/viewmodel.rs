use std::collections::BTreeMap;
use std::time::Instant;

use peerbay_lib::app::LifecycleState;
use peerbay_lib::discovery::DiscoveredPeer;
use peerbay_lib::identity::DeviceIdentity;
use peerbay_lib::protocol::CapabilityDocument;
use peerbay_lib::session::SessionState;
use peerbay_lib::storage::PeerRecord;
use peerbay_lib::viewmodel::{
    AppViewModel, DeviceAction, DeviceView, FeatureRowState, FeatureRowView, SessionSummary,
    SnapshotInputs, TrustStatus, VIEWMODEL_SCHEMA_VERSION,
};

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
