use peerbay_lib::viewmodel::ViewModelGateway;

#[test]
fn gateway_starts_with_privacy_safe_defaults() {
    assert!(ViewModelGateway::new().is_privacy_safe());
}
