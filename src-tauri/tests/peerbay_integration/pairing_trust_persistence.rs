use peerbay_lib::pairing::{
    PairingExchange, PairingExchangeError, PairingExchangeState, PairingSession,
};
use peerbay_lib::protocol::pairing::PairingAccepted;
use peerbay_lib::storage::PeerTrustStore;
use std::time::Duration;

const INITIATOR_FINGERPRINT: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RESPONDER_FINGERPRINT: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const INITIATOR_DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174000";
const RESPONDER_DEVICE_ID: &str = "123e4567-e89b-12d3-a456-426614174001";

fn common_versions() -> Vec<u16> {
    vec![1]
}

fn confirmed_pair() -> (PairingSession, PairingSession) {
    let mut initiator = PairingExchange::as_initiator(
        "pair-trust-1".to_owned(),
        INITIATOR_DEVICE_ID.to_owned(),
        INITIATOR_FINGERPRINT.to_owned(),
        common_versions(),
        Duration::from_secs(60),
    )
    .unwrap();
    let start = initiator.start_message().unwrap();

    let (mut responder, commit) = PairingExchange::from_pairing_start(
        &start,
        RESPONDER_DEVICE_ID.to_owned(),
        RESPONDER_FINGERPRINT.to_owned(),
        common_versions(),
        Duration::from_secs(60),
    )
    .unwrap();

    initiator.apply_commit(&commit).unwrap();
    let initiator_reveal = initiator.reveal().unwrap();
    let responder_reveal = responder.reveal().unwrap();
    responder.apply_nonce(&initiator_reveal).unwrap();
    initiator.apply_nonce(&responder_reveal).unwrap();

    let code = initiator.emit_pairing_code(10_000).unwrap();
    let confirm =
        peerbay_lib::protocol::pairing::PairingConfirm::accepted("pair-trust-1", code.sas_code)
            .unwrap();
    responder.verify_pairing_confirm(&confirm).unwrap();

    (
        PairingSession::new(initiator),
        PairingSession::new(responder),
    )
}

fn trust_store() -> (PeerTrustStore, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let peers_dir = dir.path().join("peers");
    std::fs::create_dir(&peers_dir).unwrap();
    (PeerTrustStore::new(peers_dir), dir)
}

#[test]
fn confirmed_state_is_terminal_before_trust_persistence() {
    let (initiator, responder) = confirmed_pair();
    assert_eq!(responder.state(), PairingExchangeState::Confirmed);
    assert_eq!(initiator.state(), PairingExchangeState::Revealed);
    assert!(responder.state() != PairingExchangeState::SessionTokenIssued);
    assert!(initiator.state() != PairingExchangeState::SessionTokenIssued);
}

#[test]
fn responder_accept_persists_trust_and_issues_session_token() {
    let (mut _initiator, mut responder) = confirmed_pair();
    let (store, _dir) = trust_store();

    let accepted = responder
        .accept(&store, "Phone", "android")
        .expect("responder accept should persist trust");

    assert_eq!(responder.state(), PairingExchangeState::SessionTokenIssued);
    assert_eq!(accepted.pairing_id, "pair-trust-1");
    assert!(!accepted.session_token.is_empty());
    assert!(accepted.expires_at_ms > 0);

    let record = store
        .load(INITIATOR_DEVICE_ID)
        .expect("trust record loaded");
    assert_eq!(record.device_id, INITIATOR_DEVICE_ID);
    assert!(!record.is_revoked());
}

#[test]
fn persisted_trust_record_never_contains_the_raw_session_token() {
    let (mut _initiator, mut responder) = confirmed_pair();
    let (store, _dir) = trust_store();

    let accepted = responder
        .accept(&store, "Phone", "android")
        .expect("responder accept should persist trust");

    let record = store
        .load(INITIATOR_DEVICE_ID)
        .expect("trust record loaded");
    let serialized = serde_json::to_string(&record).expect("record serializes");

    assert!(
        !serialized.contains(&accepted.session_token),
        "raw session token must not appear in the persisted trust record"
    );
    assert!(
        !serialized.contains("session_token"),
        "trust record wire shape must not expose token fields"
    );
}

#[test]
fn initiator_apply_accepted_persists_trust_from_peer_token() {
    let (mut initiator, mut responder) = confirmed_pair();
    let (store, _dir) = trust_store();

    let accepted = responder
        .accept(&store, "Phone", "android")
        .expect("responder accept should persist trust");

    let code = initiator
        .emit_pairing_code(10_000)
        .expect("initiator should still be able to emit its pairing code");
    let confirm =
        peerbay_lib::protocol::pairing::PairingConfirm::accepted("pair-trust-1", code.sas_code)
            .expect("confirmation should be valid");
    initiator
        .verify_pairing_confirm(&confirm)
        .expect("initiator should record its own SAS confirmation before applying accepted trust");

    initiator
        .apply_accepted(&store, RESPONDER_DEVICE_ID, &accepted, "Phone", "android")
        .expect("initiator apply_accepted should persist trust");

    assert_eq!(initiator.state(), PairingExchangeState::SessionTokenIssued);

    let record = store
        .load(RESPONDER_DEVICE_ID)
        .expect("initiator trust record loaded");
    assert_eq!(record.device_id, RESPONDER_DEVICE_ID);
    assert!(!record.is_revoked());
    assert!(!record.pairing_token_hash.is_empty());
}

#[test]
fn apply_accepted_rejects_expired_session_token() {
    let (mut initiator, mut responder) = confirmed_pair();
    let (store, _dir) = trust_store();

    let mut accepted = responder
        .accept(&store, "Phone", "android")
        .expect("responder accept should persist trust");
    accepted.expires_at_ms = 1;

    let code = initiator
        .emit_pairing_code(10_000)
        .expect("initiator should still be able to emit its pairing code");
    let confirm =
        peerbay_lib::protocol::pairing::PairingConfirm::accepted("pair-trust-1", code.sas_code)
            .expect("confirmation should be valid");
    initiator
        .verify_pairing_confirm(&confirm)
        .expect("initiator should record its own SAS confirmation");

    let err = initiator
        .apply_accepted(&store, RESPONDER_DEVICE_ID, &accepted, "Phone", "android")
        .expect_err("expired token must be rejected");
    assert_eq!(err, PairingExchangeError::TokenExpired);
    assert_eq!(initiator.state(), PairingExchangeState::Confirmed);
    assert!(store.load(RESPONDER_DEVICE_ID).is_err());
}

#[test]
fn apply_accepted_rejects_wrong_pairing_id() {
    let (mut initiator, mut responder) = confirmed_pair();
    let (store, _dir) = trust_store();

    let mut accepted = responder
        .accept(&store, "Phone", "android")
        .expect("responder accept should persist trust");
    accepted.pairing_id = "wrong-pairing-id".to_owned();

    let code = initiator
        .emit_pairing_code(10_000)
        .expect("initiator should still be able to emit its pairing code");
    let confirm =
        peerbay_lib::protocol::pairing::PairingConfirm::accepted("pair-trust-1", code.sas_code)
            .expect("confirmation should be valid");
    initiator
        .verify_pairing_confirm(&confirm)
        .expect("initiator should record its own SAS confirmation");

    let err = initiator
        .apply_accepted(&store, RESPONDER_DEVICE_ID, &accepted, "Phone", "android")
        .expect_err("wrong pairing id must be rejected");
    assert_eq!(err, PairingExchangeError::InvalidPairingId);
    assert!(store.load(RESPONDER_DEVICE_ID).is_err());
}

#[test]
fn cancel_after_confirmed_leaves_no_trust_record() {
    let (mut _initiator, mut responder) = confirmed_pair();
    let (store, _dir) = trust_store();

    responder.cancel();
    assert_eq!(responder.state(), PairingExchangeState::Cancelled);
    assert!(store.load(INITIATOR_DEVICE_ID).is_err());
}
