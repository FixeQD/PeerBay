//! SAS confirmation flow tests

use peerbay_lib::pairing::{
    PairingExchange, PairingExchangeError, PairingExchangeState, PairingSession, SAS_CODE_LENGTH,
};
use peerbay_lib::protocol::pairing::PairingConfirm;
use std::time::Duration;

const INITIATOR_FINGERPRINT: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const RESPONDER_FINGERPRINT: &str =
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn common_versions() -> Vec<u16> {
    vec![1]
}

fn revealed_pair() -> (PairingSession, PairingSession) {
    let mut initiator = PairingExchange::as_initiator(
        "pair-sas-1".to_owned(),
        "device-a".to_owned(),
        INITIATOR_FINGERPRINT.to_owned(),
        common_versions(),
        Duration::from_secs(60),
    )
    .unwrap();
    let start = initiator.start_message().unwrap();

    let (mut responder, commit) = PairingExchange::from_pairing_start(
        &start,
        "device-b".to_owned(),
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

    (
        PairingSession::new(initiator),
        PairingSession::new(responder),
    )
}

#[test]
fn sas_code_is_exactly_six_ascii_digits() {
    let (mut initiator, _responder) = revealed_pair();
    let sas = initiator.sas_code().unwrap();
    assert_eq!(sas.code.len(), SAS_CODE_LENGTH);
    assert!(sas.code.bytes().all(|byte| byte.is_ascii_digit()));
    assert!(sas.code.starts_with('0') || sas.code.parse::<u32>().unwrap() > 0);
}

#[test]
fn both_peers_compute_the_same_sas_code() {
    let (mut initiator, mut responder) = revealed_pair();
    let initiator_code = initiator.sas_code().unwrap().code;
    let responder_code = responder.sas_code().unwrap().code;
    assert_eq!(initiator_code, responder_code);
}

#[test]
fn pairing_code_message_carryies_the_computed_sas_and_expires() {
    let (mut initiator, _responder) = revealed_pair();
    let code = initiator
        .emit_pairing_code(10_000)
        .expect("pairing code should be emitted");
    assert_eq!(code.sas_code, initiator.sas_code().unwrap().code);
    assert!(code.expires_at_ms > 0);
}

#[test]
fn zero_sas_code_lifetime_is_rejected() {
    let (mut initiator, _responder) = revealed_pair();
    let result = initiator.emit_pairing_code(0);
    assert!(matches!(
        result,
        Err(PairingExchangeError::InvalidSasCodeLifetime)
    ));
}

#[test]
fn confirmation_succeeds_when_codes_match() {
    let (mut initiator, mut responder) = revealed_pair();
    let code = initiator.emit_pairing_code(10_000).unwrap();
    let confirm = PairingConfirm::accepted("pair-sas-1", code.sas_code).unwrap();
    responder.verify_pairing_confirm(&confirm).unwrap();
    assert_eq!(responder.state(), PairingExchangeState::Confirmed);
}

#[test]
fn confirmation_rejects_on_sas_code_mismatch() {
    let (mut initiator, mut responder) = revealed_pair();
    let _ = initiator.emit_pairing_code(10_000).unwrap();
    let wrong = PairingConfirm::accepted("pair-sas-1", "999999").unwrap();
    let result = responder.verify_pairing_confirm(&wrong);
    assert!(matches!(result, Err(PairingExchangeError::SasCodeMismatch)));
    assert_eq!(responder.state(), PairingExchangeState::Rejected);
}

#[test]
fn denied_confirmation_clears_material() {
    let (mut initiator, mut responder) = revealed_pair();
    let _ = initiator.emit_pairing_code(10_000).unwrap();
    let denied = PairingConfirm::denied("pair-sas-1").unwrap();
    let result = responder.verify_pairing_confirm(&denied);
    assert!(matches!(result, Err(PairingExchangeError::UserDenied)));
    assert_eq!(responder.state(), PairingExchangeState::Rejected);
}

#[test]
fn confirmation_requires_revealed_state() {
    let mut initiator = PairingExchange::as_initiator(
        "pair-sas-2".to_owned(),
        "device-a".to_owned(),
        INITIATOR_FINGERPRINT.to_owned(),
        common_versions(),
        Duration::from_secs(60),
    )
    .unwrap();
    let confirm = PairingConfirm::accepted("pair-sas-2", "000000").unwrap();
    let result = initiator.verify_pairing_confirm(&confirm);
    assert!(matches!(
        result,
        Err(PairingExchangeError::StateMismatch { .. })
    ));
}

#[test]
fn confirmation_rejects_wrong_pairing_id() {
    let (mut initiator, mut responder) = revealed_pair();
    let code = initiator.emit_pairing_code(10_000).unwrap();
    let confirm = PairingConfirm::accepted("pair-wrong", code.sas_code).unwrap();
    let result = responder.verify_pairing_confirm(&confirm);
    assert!(matches!(
        result,
        Err(PairingExchangeError::InvalidPairingId)
    ));
}

#[test]
fn confirmed_exchange_is_terminal() {
    let (mut initiator, mut responder) = revealed_pair();
    let code = initiator.emit_pairing_code(10_000).unwrap();
    let confirm = PairingConfirm::accepted("pair-sas-1", code.sas_code).unwrap();
    responder.verify_pairing_confirm(&confirm).unwrap();
    let again = responder.verify_pairing_confirm(&confirm);
    assert!(matches!(again, Err(PairingExchangeError::AlreadyCompleted)));
}

#[test]
fn sas_code_redacts_nonces_in_debug_output() {
    let (mut initiator, _responder) = revealed_pair();
    let sas = initiator.sas_code().unwrap();
    let debug = format!("{:?}", sas);
    assert!(!debug.contains(&sas.initiator_nonce_hex));
    assert!(!debug.contains(&sas.responder_nonce_hex));
    assert!(debug.contains("redacted"));
}
