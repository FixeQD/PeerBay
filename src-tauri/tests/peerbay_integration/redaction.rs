use peerbay_lib::redaction::RedactionPolicy;

#[test]
fn default_policy_is_privacy_safe() {
    assert!(RedactionPolicy::default().is_privacy_safe());
}
