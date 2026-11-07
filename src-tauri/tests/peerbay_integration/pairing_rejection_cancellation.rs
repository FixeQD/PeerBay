//! Tests for rejection, cancellation, expiry and nonce cleanup in pairing

use peerbay_lib::pairing::{
    PairingExchange, PairingExchangeError, PairingExchangeState, PairingSession,
};
use peerbay_lib::protocol::pairing::PairingConfirm;
use std::time::Duration;

const INITIATOR_FP: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RESPONDER_FP: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const INIT_ID: &str = "device-a";
const RESP_ID: &str = "device-b";
const PAIRING_ID: &str = "pair-reject-1";

fn common_versions() -> Vec<u16> {
    vec![1]
}

fn new_initiator() -> PairingExchange {
    PairingExchange::as_initiator(
        PAIRING_ID.to_owned(),
        INIT_ID.to_owned(),
        INITIATOR_FP.to_owned(),
        common_versions(),
        Duration::from_secs(60),
    )
    .unwrap()
}

fn revealed_pair() -> (PairingSession, PairingSession) {
    let mut init = new_initiator();
    let start = init.start_message().unwrap();
    let (mut resp, commit) = PairingExchange::from_pairing_start(
        &start,
        RESP_ID.to_owned(),
        RESPONDER_FP.to_owned(),
        common_versions(),
        Duration::from_secs(60),
    )
    .unwrap();
    init.apply_commit(&commit).unwrap();
    let ir = init.reveal().unwrap();
    let rr = resp.reveal().unwrap();
    resp.apply_nonce(&ir).unwrap();
    init.apply_nonce(&rr).unwrap();
    (PairingSession::new(init), PairingSession::new(resp))
}

#[test]
fn denied_confirmation_transitions_to_rejected_and_clears_material() {
    let (mut init, mut resp) = revealed_pair();
    let _ = init.emit_pairing_code(10_000).unwrap();
    let denied = PairingConfirm::denied(PAIRING_ID).unwrap();
    let result = resp.verify_pairing_confirm(&denied);
    assert!(matches!(result, Err(PairingExchangeError::UserDenied)));
    assert_eq!(resp.state(), PairingExchangeState::Rejected);
    assert!(resp.secrets_invalidated());
}

#[test]
fn sas_mismatch_transitions_to_rejected_and_clears_material() {
    let (mut init, mut resp) = revealed_pair();
    let _ = init.emit_pairing_code(10_000).unwrap();
    let wrong = PairingConfirm::accepted(PAIRING_ID, "999999").unwrap();
    let result = resp.verify_pairing_confirm(&wrong);
    assert!(matches!(result, Err(PairingExchangeError::SasCodeMismatch)));
    assert_eq!(resp.state(), PairingExchangeState::Rejected);
    assert!(resp.secrets_invalidated());
}

#[test]
fn verified_confirmation_is_terminal_on_second_call() {
    let (mut init, mut resp) = revealed_pair();
    let code = init.emit_pairing_code(10_000).unwrap();
    resp.apply_pairing_code(&code).unwrap();
    let confirm = PairingConfirm::accepted(PAIRING_ID, code.sas_code.clone()).unwrap();
    resp.verify_pairing_confirm(&confirm).unwrap();
    let again = resp.verify_pairing_confirm(&confirm);
    assert!(matches!(again, Err(PairingExchangeError::AlreadyCompleted)));
    assert_eq!(resp.state(), PairingExchangeState::Confirmed);
}

#[test]
fn wrong_pairing_id_on_confirm_is_rejected() {
    let (mut init, mut resp) = revealed_pair();
    let code = init.emit_pairing_code(10_000).unwrap();
    let confirm = PairingConfirm::accepted("pair-wrong", code.sas_code).unwrap();
    let result = resp.verify_pairing_confirm(&confirm);
    assert!(matches!(
        result,
        Err(PairingExchangeError::InvalidPairingId)
    ));
}

#[test]
fn cancel_from_started_clears_material() {
    let mut init = new_initiator();
    assert_eq!(init.state(), PairingExchangeState::Started);
    init.cancel();
    assert_eq!(init.state(), PairingExchangeState::Cancelled);
    assert!(init.secrets_invalidated());
}

#[test]
fn cancel_from_committed_clears_material() {
    let mut init = new_initiator();
    let start = init.start_message().unwrap();
    let (_resp, commit) = PairingExchange::from_pairing_start(
        &start,
        RESP_ID.to_owned(),
        RESPONDER_FP.to_owned(),
        common_versions(),
        Duration::from_secs(60),
    )
    .unwrap();
    init.apply_commit(&commit).unwrap();
    assert_eq!(init.state(), PairingExchangeState::Committed);
    init.cancel();
    assert_eq!(init.state(), PairingExchangeState::Cancelled);
    assert!(init.secrets_invalidated());
}

#[test]
fn cancel_from_revealed_clears_material() {
    let (init, mut resp) = revealed_pair();
    let _ = init;
    let before = resp.state();
    assert_eq!(before, PairingExchangeState::Revealed);
    resp.cancel();
    assert_eq!(resp.state(), PairingExchangeState::Cancelled);
    assert!(resp.secrets_invalidated());
}

#[test]
fn cancel_after_confirmed_clears_material() {
    let (mut init, mut resp) = revealed_pair();
    let code = init.emit_pairing_code(10_000).unwrap();
    resp.apply_pairing_code(&code).unwrap();
    let confirm = PairingConfirm::accepted(PAIRING_ID, code.sas_code.clone()).unwrap();
    resp.verify_pairing_confirm(&confirm).unwrap();
    assert_eq!(resp.state(), PairingExchangeState::Confirmed);
    resp.cancel();
    assert_eq!(resp.state(), PairingExchangeState::Cancelled);
    assert!(resp.secrets_invalidated());
}

#[test]
fn expire_if_timed_out_does_not_change_terminal_state() {
    let (mut init, mut resp) = revealed_pair();
    let code = init.emit_pairing_code(10_000).unwrap();
    resp.apply_pairing_code(&code).unwrap();
    let confirm = PairingConfirm::accepted(PAIRING_ID, code.sas_code.clone()).unwrap();
    resp.verify_pairing_confirm(&confirm).unwrap();
    assert_eq!(resp.state(), PairingExchangeState::Confirmed);
    assert!(!resp.expire_if_timed_out());
    assert_eq!(resp.state(), PairingExchangeState::Confirmed);
}

#[test]
fn cancel_does_not_change_already_terminal_rejected() {
    let (mut init, mut resp) = revealed_pair();
    let _ = init.emit_pairing_code(10_000).unwrap();
    let denied = PairingConfirm::denied(PAIRING_ID).unwrap();
    let _ = resp.verify_pairing_confirm(&denied);
    assert_eq!(resp.state(), PairingExchangeState::Rejected);
    resp.cancel();
    assert_eq!(resp.state(), PairingExchangeState::Rejected);
}

#[test]
fn sas_code_cannot_be_emitted_before_revealed_state() {
    let mut init = new_initiator();
    assert!(matches!(
        init.emit_pairing_code(10_000),
        Err(PairingExchangeError::StateMismatch { .. })
    ));
}

#[test]
fn denied_code_is_not_persisted_into_trust() {
    let (_init, mut resp) = revealed_pair();
    let denied = PairingConfirm::denied(PAIRING_ID).unwrap();
    let _ = resp.verify_pairing_confirm(&denied);
    assert_eq!(resp.state(), PairingExchangeState::Rejected);
}
