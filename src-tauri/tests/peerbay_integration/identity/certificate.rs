use std::panic::{AssertUnwindSafe, catch_unwind};

use peerbay_lib::identity::{DeviceIdentityError, TransportCertificate};
use sha2::{Digest, Sha256};
use x509_parser::prelude::{GeneralName, parse_x509_certificate};

use super::{DEVICE_ID, identity_error};

#[test]
fn generated_certificate_is_parseable_self_signed_and_bound_to_device_id() {
    let certificate =
        TransportCertificate::generate_for_device(DEVICE_ID).expect("certificate should generate");
    let (_, parsed) = parse_x509_certificate(certificate.certificate_der())
        .expect("certificate DER should parse");

    parsed
        .verify_signature(None)
        .expect("self-signed certificate signature should verify");
    assert_eq!(
        parsed.tbs_certificate.subject(),
        parsed.tbs_certificate.issuer()
    );
    assert_eq!(
        parsed
            .tbs_certificate
            .subject()
            .iter_common_name()
            .next()
            .expect("certificate should have a common name")
            .as_str()
            .expect("common name should be text"),
        format!("PeerBay {DEVICE_ID}")
    );
    assert_eq!(
        parsed
            .tbs_certificate
            .public_key()
            .subject_public_key
            .data
            .as_ref(),
        certificate.public_key_bytes().as_slice()
    );

    let san = parsed
        .subject_alternative_name()
        .expect("SAN extension should parse")
        .expect("certificate should have a SAN");
    assert!(san.value.general_names.iter().any(|name| {
        matches!(name, GeneralName::DNSName(value) if *value == format!("peerbay-{DEVICE_ID}"))
    }));
    assert!(
        parsed
            .basic_constraints()
            .expect("basic constraints should parse")
            .is_none()
    );
}

#[test]
fn certificate_fingerprint_is_lowercase_sha256_of_der() {
    let certificate =
        TransportCertificate::generate_for_device(DEVICE_ID).expect("certificate should generate");
    let digest = Sha256::digest(certificate.certificate_der());
    let expected = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    assert_eq!(certificate.fingerprint(), expected);
    assert_eq!(certificate.fingerprint().len(), 64);
    assert!(
        certificate
            .fingerprint()
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
}

#[test]
fn separately_generated_certificates_have_distinct_transport_identity() {
    let first = TransportCertificate::generate_for_device(DEVICE_ID)
        .expect("first certificate should generate");
    let second = TransportCertificate::generate_for_device(DEVICE_ID)
        .expect("second certificate should generate");

    assert_ne!(first.certificate_der(), second.certificate_der());
    assert_ne!(first.public_key_bytes(), second.public_key_bytes());
    assert_ne!(first.fingerprint(), second.fingerprint());
}

#[test]
fn certificate_private_key_is_only_available_inside_callback_and_is_redacted() {
    let certificate =
        TransportCertificate::generate_for_device(DEVICE_ID).expect("certificate should generate");
    let private_key = certificate.with_private_key_der(|bytes| bytes.to_vec());
    let debug = format!("{certificate:?}");

    assert!(!private_key.is_empty());
    assert!(debug.contains("<redacted>"));
    assert!(!debug.contains(&format!("{private_key:?}")));
    assert!(!debug.contains("private_key_der: ["));
}

#[test]
fn private_key_callback_panic_does_not_corrupt_the_certificate() {
    let certificate =
        TransportCertificate::generate_for_device(DEVICE_ID).expect("certificate should generate");
    let result = catch_unwind(AssertUnwindSafe(|| {
        certificate.with_private_key_der(|bytes| {
            assert!(!bytes.is_empty());
            panic!("simulated transport adapter panic");
        });
    }));

    assert!(result.is_err());
    certificate
        .validate()
        .expect("panic must not corrupt certificate");
}

#[test]
fn certificate_generation_rejects_uuid_and_rce_injection_payloads() {
    for value in [
        "$(touch /tmp/peerbay-certificate-rce)",
        "123e4567-e89b-12d3-a456-426614174000; touch /tmp/pwned",
        "../../etc/passwd",
        "123e4567-e89b-12d3-a456-426614174000\nwhoami",
    ] {
        let error = identity_error(TransportCertificate::generate_for_device(value).map(|_| ()));
        assert_eq!(error, DeviceIdentityError::InvalidDeviceIdFormat);
    }

    assert!(!std::path::Path::new("/tmp/peerbay-certificate-rce").exists());
}

#[test]
fn certificate_error_paths_do_not_echo_untrusted_device_payloads() {
    let payload = "$(touch /tmp/peerbay-certificate-rce);\nprivate-device-name";
    let error = TransportCertificate::generate_for_device(payload)
        .expect_err("untrusted device payload should fail UUID validation")
        .to_string();

    assert!(!error.contains(payload));
    assert!(!error.contains("private-device-name"));
    assert!(!error.contains("/tmp/peerbay-certificate-rce"));
}

#[test]
fn certificate_der_is_immutable_from_public_api() {
    let certificate =
        TransportCertificate::generate_for_device(DEVICE_ID).expect("certificate should generate");
    let before = certificate.fingerprint().to_owned();
    let public_der = certificate.certificate_der();

    assert!(!public_der.is_empty());
    assert_eq!(certificate.fingerprint(), before);
    certificate
        .validate()
        .expect("certificate should remain valid");
}
