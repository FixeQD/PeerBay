use peerbay_lib::platform::{PlatformDescriptor, PlatformTarget};

#[test]
fn descriptor_matches_compilation_target() {
    let expected = if cfg!(target_os = "linux") {
        PlatformTarget::Linux
    } else if cfg!(target_os = "windows") {
        PlatformTarget::Windows
    } else if cfg!(target_os = "android") {
        PlatformTarget::Android
    } else {
        PlatformTarget::Unsupported
    };

    assert_eq!(PlatformDescriptor::current().target(), expected);
}
