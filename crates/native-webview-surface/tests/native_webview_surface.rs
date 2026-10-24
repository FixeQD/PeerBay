use native_webview_surface::{
    Bounds, SurfaceCommand, SurfaceDescriptor, SurfaceId, SurfaceLifecycle, SurfaceState,
};

#[test]
fn lifecycle_supports_backend_independent_surface_commands() {
    let descriptor = SurfaceDescriptor {
        id: SurfaceId::new(7),
        bounds: Bounds::new(0, 0, 800, 600),
    };
    let mut lifecycle = SurfaceLifecycle::new(descriptor);

    lifecycle
        .apply(SurfaceCommand::Show)
        .expect("surface should show");
    lifecycle
        .apply(SurfaceCommand::Resize(Bounds::new(10, 20, 640, 480)))
        .expect("surface should resize");
    lifecycle
        .apply(SurfaceCommand::Hide)
        .expect("surface should hide");
    lifecycle
        .apply(SurfaceCommand::Destroy)
        .expect("surface should destroy");

    assert_eq!(lifecycle.state(), SurfaceState::Destroyed);
    assert_eq!(lifecycle.descriptor().id.get(), 7);
}

#[test]
fn destroyed_surface_rejects_new_commands() {
    let descriptor = SurfaceDescriptor {
        id: SurfaceId::new(1),
        bounds: Bounds::new(0, 0, 1, 1),
    };
    let mut lifecycle = SurfaceLifecycle::new(descriptor);
    lifecycle
        .apply(SurfaceCommand::Destroy)
        .expect("destroy should work");

    assert!(lifecycle.apply(SurfaceCommand::Show).is_err());
}
