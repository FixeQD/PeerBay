use peerbay_lib::redaction::RedactionPolicy;

fn assert_does_not_contain_sensitive_value(label: &str, rendered: &str, value: &str) {
    assert!(
        !rendered.contains(value),
        "{label} leaked sensitive value {value:?}: {rendered:?}"
    );
}

#[test]
fn diagnostic_fields_do_not_contain_full_private_values() {
    let pairing_token = "pairing-token-8f0e7d6c5b4a39281716151413121110";
    let private_path = "/home/alice/PeerBay/private/clipboard-secrets.txt";
    let clipboard = "clipboard value: account=alice@example.test password=not-for-logs";
    let notification = "Private notification body: invoice 8472 and one-time code 019283";
    let input_payload = "key_down:Ctrl+Alt+T; text=private command payload";

    let rendered = serde_json::json!({
        "pairing_token": RedactionPolicy::redact_token_or_fingerprint(pairing_token),
        "path": RedactionPolicy::redact_path(private_path),
        "clipboard": RedactionPolicy::redact_clipboard_preview(clipboard),
        "notification": RedactionPolicy::redact_notification(notification),
        "input": RedactionPolicy::redact_input_payload(input_payload),
    })
    .to_string();

    for (label, value) in [
        ("pairing token", pairing_token),
        ("private path", private_path),
        ("clipboard", clipboard),
        ("notification", notification),
        ("input payload", input_payload),
    ] {
        assert_does_not_contain_sensitive_value(label, &rendered, value);
    }
}

#[test]
fn privacy_mode_log_entry_does_not_emit_the_original_private_record() {
    let private_record = concat!(
        "path=/home/alice/PeerBay/private/clipboard-secrets.txt ",
        "token=pairing-token-8f0e7d6c5b4a39281716151413121110 ",
        "clipboard=account=alice@example.test password=not-for-logs"
    );

    let rendered = RedactionPolicy::redact_log_entry(private_record, true);

    assert_does_not_contain_sensitive_value("privacy-mode log entry", &rendered, private_record);
    assert_does_not_contain_sensitive_value(
        "privacy-mode log entry path",
        &rendered,
        "/home/alice/PeerBay/private/clipboard-secrets.txt",
    );
    assert_does_not_contain_sensitive_value(
        "privacy-mode log entry token",
        &rendered,
        "pairing-token-8f0e7d6c5b4a39281716151413121110",
    );
}

#[test]
fn hostile_shell_like_data_is_redacted_as_data_and_never_executed() {
    let rce_like_payload = "$(touch /tmp/peerbay-rce-canary); cat /etc/passwd";
    let rce_like_path = "/tmp/$(touch peerbay-rce-canary)/private.txt";

    let rendered = format!(
        "payload={} path={}",
        RedactionPolicy::redact_input_payload(rce_like_payload),
        RedactionPolicy::redact_path(rce_like_path),
    );

    assert_does_not_contain_sensitive_value("shell-like payload", &rendered, rce_like_payload);
    assert_does_not_contain_sensitive_value("shell-like path", &rendered, rce_like_path);
    assert!(!std::path::Path::new("/tmp/peerbay-rce-canary").exists());
}

#[test]
fn redaction_scan_covers_short_and_long_secret_fields() {
    let short_secret = "xy";
    let long_secret = "0123456789abcdef0123456789abcdef0123456789abcdef";

    for (label, secret) in [("short secret", short_secret), ("long secret", long_secret)] {
        let rendered = RedactionPolicy::redact_string(secret, Some("secret"));
        assert_does_not_contain_sensitive_value(label, &rendered, secret);
    }

    let short_input = "x";
    let rendered = RedactionPolicy::redact_input_payload(short_input);
    assert_does_not_contain_sensitive_value("short input payload", &rendered, short_input);
}
