use peerbay_lib::protocol::{
    ClipboardMessageType, ControlMessageType, FileMessageType, InputMessageType, MediaMessageType,
    MessageChannel, MessageEnvelope, MessageType, PairingMessageType, ProtocolLimitError,
    ProtocolLimits, SequenceError, SequenceTracker,
};

fn control_message(session_id: &str, seq: u64, timestamp_ms: u64) -> MessageEnvelope<()> {
    MessageEnvelope::new(
        format!("message-{seq}"),
        MessageType::Control(ControlMessageType::Ping),
        session_id,
        seq,
        timestamp_ms,
        (),
    )
}

fn clipboard_message(session_id: &str, seq: u64) -> MessageEnvelope<()> {
    MessageEnvelope::new(
        format!("clipboard-{seq}"),
        MessageType::Clipboard(ClipboardMessageType::Text),
        session_id,
        seq,
        1,
        (),
    )
}

fn file_message(session_id: &str, seq: u64) -> MessageEnvelope<()> {
    MessageEnvelope::new(
        format!("file-{seq}"),
        MessageType::Files(FileMessageType::Offer),
        session_id,
        seq,
        1,
        (),
    )
}

#[test]
fn tracker_binds_itself_to_the_authenticated_session() {
    let tracker = SequenceTracker::new("session-a").expect("session ID should be valid");

    assert_eq!(tracker.session_id(), "session-a");
}

#[test]
fn tracker_rejects_an_empty_session_id() {
    let error = SequenceTracker::new("   ")
        .expect_err("empty session IDs must not create a replay tracker")
        .downcast_inner::<ProtocolLimitError>()
        .expect("session ID validation should preserve the protocol limit error");

    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier { field: "sid" }
    );
}

#[test]
fn first_sequence_is_accepted_for_a_channel() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 42, 100))
        .expect("the first sequence should be accepted");

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(42));
}

#[test]
fn zero_is_a_valid_first_sequence_number() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 0, 100))
        .expect("zero is valid when it is the first sequence");

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(0));
}

#[test]
fn strictly_increasing_sequences_are_accepted() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    for seq in [1, 2, 3, 10, 11] {
        tracker
            .accept(&control_message("session-a", seq, 100))
            .expect("strictly increasing sequences should be accepted");
    }

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(11));
}

#[test]
fn sequence_gaps_are_allowed_without_accepting_regressions() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 3, 100))
        .expect("first sequence should be accepted");
    tracker
        .accept(&control_message("session-a", 9, 99))
        .expect("a gap can represent a lost message or reconnect");

    let error = tracker
        .accept(&control_message("session-a", 8, 101))
        .expect_err("a sequence below the high-water mark is replayed")
        .downcast_inner::<SequenceError>()
        .expect("replay error should be preserved");

    assert_eq!(
        error,
        SequenceError::Replay {
            channel: MessageChannel::Control,
            seq: 8,
            last_accepted: 9,
        }
    );
}

#[test]
fn an_equal_sequence_is_rejected_as_a_duplicate() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let message = control_message("session-a", 7, 100);

    tracker
        .accept(&message)
        .expect("first delivery should pass");

    let error = tracker
        .accept(&message)
        .expect_err("the same sequence must not be accepted twice")
        .downcast_inner::<SequenceError>()
        .expect("duplicate error should be preserved");

    assert_eq!(
        error,
        SequenceError::Duplicate {
            channel: MessageChannel::Control,
            seq: 7,
        }
    );
}

#[test]
fn a_lower_sequence_is_rejected_as_a_replay() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 12, 100))
        .expect("high-water mark should be accepted");

    let error = tracker
        .accept(&control_message("session-a", 4, 100))
        .expect_err("older sequence must be rejected")
        .downcast_inner::<SequenceError>()
        .expect("replay error should be preserved");

    assert_eq!(
        error,
        SequenceError::Replay {
            channel: MessageChannel::Control,
            seq: 4,
            last_accepted: 12,
        }
    );
}

#[test]
fn sequence_state_is_independent_between_channels() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 9, 100))
        .expect("control sequence should be accepted");
    tracker
        .accept(&file_message("session-a", 1))
        .expect("file channel starts independently");

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(9));
    assert_eq!(tracker.last_accepted(MessageChannel::Files), Some(1));
}

#[test]
fn a_wrong_session_is_rejected_before_sequence_state_changes() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    let error = tracker
        .accept(&control_message("session-b", 99, 100))
        .expect_err("a message from an old or different session must be rejected")
        .downcast_inner::<SequenceError>()
        .expect("session mismatch error should be preserved");

    assert_eq!(
        error,
        SequenceError::SessionMismatch {
            expected: "session-a".to_owned(),
            received: "session-b".to_owned(),
        }
    );
    assert_eq!(tracker.last_accepted(MessageChannel::Control), None);
}

#[test]
fn duplicate_rejection_does_not_advance_the_high_water_mark() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let message = control_message("session-a", 5, 100);

    tracker
        .accept(&message)
        .expect("first delivery should pass");
    assert!(tracker.accept(&message).is_err());

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(5));
}

#[test]
fn replay_rejection_does_not_advance_the_high_water_mark() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 8, 100))
        .expect("high-water mark should be accepted");
    assert!(
        tracker
            .accept(&control_message("session-a", 3, 100))
            .is_err()
    );

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(8));
}

#[test]
fn a_higher_sequence_is_accepted_even_when_timestamp_moves_backwards() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 10, 500))
        .expect("first message should be accepted");
    tracker
        .accept(&control_message("session-a", 11, 499))
        .expect("timestamps are supplementary and do not order messages");

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(11));
}

#[test]
fn unknown_messages_have_their_own_sequence_channel() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let unknown = MessageEnvelope::new(
        "unknown-1",
        MessageType::Unknown("future.message".to_owned()),
        "session-a",
        4,
        1,
        (),
    );

    tracker
        .accept(&unknown)
        .expect("unknown optional messages still need replay protection");

    assert_eq!(tracker.last_accepted(MessageChannel::Unknown), Some(4));
}

#[test]
fn unknown_messages_do_not_share_sequence_state_with_control_messages() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let unknown = MessageEnvelope::new(
        "unknown-1",
        MessageType::Unknown("future.message".to_owned()),
        "session-a",
        1,
        1,
        (),
    );

    tracker
        .accept(&control_message("session-a", 1, 1))
        .expect("control sequence should be accepted");
    tracker
        .accept(&unknown)
        .expect("unknown channel should start independently");

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(1));
    assert_eq!(tracker.last_accepted(MessageChannel::Unknown), Some(1));
}

#[test]
fn maximum_sequence_can_be_accepted_but_not_repeated() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let message = control_message("session-a", u64::MAX, 1);

    tracker
        .accept(&message)
        .expect("u64::MAX is a valid sequence value");

    let error = tracker
        .accept(&message)
        .expect_err("maximum sequence must still be protected from replay")
        .downcast_inner::<SequenceError>()
        .expect("duplicate error should be preserved");

    assert_eq!(
        error,
        SequenceError::Duplicate {
            channel: MessageChannel::Control,
            seq: u64::MAX,
        }
    );
}

#[test]
fn duplicate_sequence_is_rejected_even_when_message_id_changes() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let first = control_message("session-a", 1, 1);
    let second = MessageEnvelope::new(
        "different-message-id",
        MessageType::Control(ControlMessageType::Pong),
        "session-a",
        1,
        2,
        (),
    );

    tracker
        .accept(&first)
        .expect("first sequence should be accepted");
    let error = tracker
        .accept(&second)
        .expect_err("a new message ID must not bypass duplicate sequence detection")
        .downcast_inner::<SequenceError>()
        .expect("duplicate error should be preserved");

    assert_eq!(
        error,
        SequenceError::Duplicate {
            channel: MessageChannel::Control,
            seq: 1,
        }
    );
}

#[test]
fn clipboard_channel_tracks_sequences_separately_from_control() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 20, 100))
        .expect("control sequence should be accepted");
    tracker
        .accept(&clipboard_message("session-a", 20))
        .expect("clipboard sequence should be independent");

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(20));
    assert_eq!(tracker.last_accepted(MessageChannel::Clipboard), Some(20));
}

#[test]
fn every_known_channel_accepts_its_first_sequence_independently() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let messages = [
        (
            MessageType::Control(ControlMessageType::Ping),
            MessageChannel::Control,
        ),
        (
            MessageType::Pairing(PairingMessageType::Start),
            MessageChannel::Pairing,
        ),
        (
            MessageType::Clipboard(ClipboardMessageType::Text),
            MessageChannel::Clipboard,
        ),
        (
            MessageType::Files(FileMessageType::Offer),
            MessageChannel::Files,
        ),
        (
            MessageType::Input(InputMessageType::Move),
            MessageChannel::Input,
        ),
        (
            MessageType::Media(MediaMessageType::ScreenState),
            MessageChannel::Media,
        ),
    ];

    for (index, (message_type, channel)) in messages.into_iter().enumerate() {
        let envelope = MessageEnvelope::new(
            format!("message-{index}"),
            message_type,
            "session-a",
            1,
            1,
            (),
        );

        tracker
            .accept(&envelope)
            .expect("each logical channel should have its own first sequence");
        assert_eq!(tracker.last_accepted(channel), Some(1));
    }
}

#[test]
fn all_sequences_below_the_high_water_mark_are_rejected() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 16, 1))
        .expect("high-water mark should be accepted");

    for seq in 0..16 {
        let error = tracker
            .accept(&control_message("session-a", seq, 1))
            .expect_err("every lower sequence is a replay");
        let error = error
            .downcast_inner::<SequenceError>()
            .expect("replay error should be preserved");

        assert_eq!(
            error,
            SequenceError::Replay {
                channel: MessageChannel::Control,
                seq,
                last_accepted: 16,
            }
        );
    }
}

#[test]
fn sequence_wraparound_from_maximum_to_zero_is_rejected() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", u64::MAX, 1))
        .expect("maximum sequence should be accepted once");

    let error = tracker
        .accept(&control_message("session-a", 0, 1))
        .expect_err("wrapping to zero would move the channel backwards")
        .downcast_inner::<SequenceError>()
        .expect("replay error should be preserved");

    assert_eq!(
        error,
        SequenceError::Replay {
            channel: MessageChannel::Control,
            seq: 0,
            last_accepted: u64::MAX,
        }
    );
}

#[test]
fn changing_the_control_message_type_does_not_bypass_channel_replay_protection() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let ping = control_message("session-a", 4, 1);
    let pong = MessageEnvelope::new(
        "pong-message",
        MessageType::Control(ControlMessageType::Pong),
        "session-a",
        4,
        2,
        (),
    );

    tracker.accept(&ping).expect("ping should be accepted");
    assert!(tracker.accept(&pong).is_err());
    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(4));
}

#[test]
fn unknown_channel_sequences_are_monotonic_too() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let first = MessageEnvelope::new(
        "future-1",
        MessageType::Unknown("future.message".to_owned()),
        "session-a",
        5,
        1,
        (),
    );
    let replay = MessageEnvelope::new(
        "future-2",
        MessageType::Unknown("another.future.message".to_owned()),
        "session-a",
        4,
        1,
        (),
    );

    tracker
        .accept(&first)
        .expect("unknown message should pass once");
    let error = tracker
        .accept(&replay)
        .expect_err("unknown messages must still be replay protected")
        .downcast_inner::<SequenceError>()
        .expect("replay error should be preserved");

    assert_eq!(
        error,
        SequenceError::Replay {
            channel: MessageChannel::Unknown,
            seq: 4,
            last_accepted: 5,
        }
    );
}

#[test]
fn foreign_session_messages_never_create_state_for_any_channel() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");
    let messages = [
        control_message("session-b", 1, 1),
        clipboard_message("session-b", 1),
        file_message("session-b", 1),
    ];

    for message in &messages {
        assert!(tracker.accept(message).is_err());
    }

    assert_eq!(tracker.last_accepted(MessageChannel::Control), None);
    assert_eq!(tracker.last_accepted(MessageChannel::Clipboard), None);
    assert_eq!(tracker.last_accepted(MessageChannel::Files), None);
}

#[test]
fn a_second_tracker_starts_with_no_sequence_history() {
    let mut first = SequenceTracker::new("session-a").expect("tracker should be created");
    let mut second = SequenceTracker::new("session-a").expect("tracker should be created");
    let message = control_message("session-a", 9, 1);

    first
        .accept(&message)
        .expect("first tracker should accept it");
    second
        .accept(&message)
        .expect("a new authenticated session tracker starts clean");

    assert_eq!(first.last_accepted(MessageChannel::Control), Some(9));
    assert_eq!(second.last_accepted(MessageChannel::Control), Some(9));
}

#[test]
fn unseen_channels_have_no_high_water_mark() {
    let tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    assert_eq!(tracker.last_accepted(MessageChannel::Control), None);
    assert_eq!(tracker.last_accepted(MessageChannel::Pairing), None);
    assert_eq!(tracker.last_accepted(MessageChannel::Clipboard), None);
    assert_eq!(tracker.last_accepted(MessageChannel::Files), None);
    assert_eq!(tracker.last_accepted(MessageChannel::Input), None);
    assert_eq!(tracker.last_accepted(MessageChannel::Media), None);
    assert_eq!(tracker.last_accepted(MessageChannel::Unknown), None);
}

#[test]
fn session_id_length_uses_the_same_byte_limit_as_the_envelope() {
    let session_id = "x".repeat(ProtocolLimits::default().max_string_length() + 1);

    let error = SequenceTracker::new(session_id)
        .expect_err("an oversized session ID must not create a tracker")
        .downcast_inner::<ProtocolLimitError>()
        .expect("session limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::StringTooLong {
            field: "sid",
            length: ProtocolLimits::default().max_string_length() + 1,
            max: ProtocolLimits::default().max_string_length(),
        }
    );
}

#[test]
fn unicode_whitespace_session_ids_are_rejected() {
    let error = SequenceTracker::new("\u{2003}\u{2003}")
        .expect_err("unicode whitespace must not be accepted as a session ID")
        .downcast_inner::<ProtocolLimitError>()
        .expect("session limit error should be preserved");

    assert_eq!(
        error,
        ProtocolLimitError::InvalidIdentifier { field: "sid" }
    );
}

#[test]
fn a_valid_sequence_does_not_clear_other_channels_after_a_rejection() {
    let mut tracker = SequenceTracker::new("session-a").expect("tracker should be created");

    tracker
        .accept(&control_message("session-a", 10, 1))
        .expect("control sequence should be accepted");
    tracker
        .accept(&clipboard_message("session-a", 20))
        .expect("clipboard sequence should be accepted");
    assert!(tracker.accept(&control_message("session-a", 9, 1)).is_err());

    assert_eq!(tracker.last_accepted(MessageChannel::Control), Some(10));
    assert_eq!(tracker.last_accepted(MessageChannel::Clipboard), Some(20));
}
