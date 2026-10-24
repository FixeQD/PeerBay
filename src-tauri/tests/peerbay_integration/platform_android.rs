#![cfg(target_os = "android")]

use peerbay_lib::platform::{AndroidBridgeState, AndroidHostLifecycle};

#[test]
fn bridge_state_tracks_native_host_lifecycle() {
    let state = AndroidBridgeState::new();
    assert_eq!(
        state
            .snapshot()
            .expect("read Android bridge state")
            .lifecycle,
        AndroidHostLifecycle::Created
    );

    state
        .transition(AndroidHostLifecycle::Resumed)
        .expect("created host should resume");
    state
        .transition(AndroidHostLifecycle::Paused)
        .expect("resumed host should pause");
    state
        .transition(AndroidHostLifecycle::Destroyed)
        .expect("paused host should be destroyable");
    assert_eq!(
        state
            .snapshot()
            .expect("read Android bridge state")
            .lifecycle,
        AndroidHostLifecycle::Destroyed
    );
}
