//! Linux platform adapters.

#[cfg(feature = "linux-x11")]
pub(crate) const X11_BACKEND: &str = "x11";

#[cfg(feature = "linux-wayland")]
pub(crate) const WAYLAND_BACKEND: &str = "wayland";

#[cfg(feature = "linux-pipewire")]
pub(crate) const PIPEWIRE_BACKEND: &str = "pipewire";

#[cfg(feature = "linux-bluez")]
pub(crate) const BLUEZ_BACKEND: &str = "bluez";

#[cfg(feature = "linux-direct-network")]
pub(crate) const DIRECT_NETWORK_BACKEND: &str = "direct-network";
