use framed_ipc::{FrameError, FrameLimits, encode_frame, read_frame};

#[test]
fn roundtrips_empty_and_non_empty_frames() {
    let limits = FrameLimits::new(16).expect("valid limit");
    for payload in [b"".as_slice(), b"hello".as_slice()] {
        let frame = encode_frame(payload, limits).expect("frame should encode");
        assert_eq!(
            read_frame(&mut frame.as_slice(), limits).expect("frame should decode"),
            payload
        );
    }
}

#[test]
fn rejects_frames_over_limit_before_writing() {
    let limits = FrameLimits::new(4).expect("valid limit");
    let error = encode_frame(b"12345", limits)
        .expect_err("frame must be rejected")
        .downcast_inner::<FrameError>()
        .expect("frame error should be preserved");
    assert!(matches!(
        error,
        FrameError::FrameTooLarge { length: 5, max: 4 }
    ));
}

#[test]
fn rejects_truncated_payload() {
    let limits = FrameLimits::new(16).expect("valid limit");
    let error = read_frame(&mut &[0, 0, 0, 5, b'a'][..], limits)
        .expect_err("truncated payload must fail")
        .downcast_inner::<FrameError>()
        .expect("frame error should be preserved");
    assert!(matches!(
        error,
        FrameError::TruncatedPayload {
            expected: 5,
            received: 1
        }
    ));
}
