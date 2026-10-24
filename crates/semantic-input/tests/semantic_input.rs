use semantic_input::{KeyCode, KeyEvent, KeyState, Modifiers};

#[test]
fn modifiers_are_composable_without_platform_keycodes() {
    let modifiers = Modifiers::empty()
        .with(Modifiers::SHIFT)
        .with(Modifiers::ALT);
    assert!(modifiers.contains(Modifiers::SHIFT));
    assert!(modifiers.contains(Modifiers::ALT));
    assert!(!modifiers.contains(Modifiers::CONTROL));
}

#[test]
fn semantic_key_keeps_physical_code_separate_from_state() {
    let event = KeyEvent {
        code: KeyCode::Physical(42),
        state: KeyState::Down,
        modifiers: Modifiers::CONTROL,
    };
    assert_eq!(event.code, KeyCode::Physical(42));
    assert_eq!(event.state, KeyState::Down);
    assert!(event.modifiers.contains(Modifiers::CONTROL));
}
