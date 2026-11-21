use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    LocalNetwork,
    UsbAdb,
    BluetoothLe,
    WifiDirect,
    PhoneHotspot,
    Loopback,
}

#[derive(Clone, Copy, Debug, Deserialize, Hash, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChannelKind {
    Control,
    Bulk,
    Media,
    Input,
    Fallback,
}

impl TransportKind {
    /// Wire label for transport kind
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalNetwork => "local_network",
            Self::UsbAdb => "usb_adb",
            Self::BluetoothLe => "bluetooth_le",
            Self::WifiDirect => "wifi_direct",
            Self::PhoneHotspot => "phone_hotspot",
            Self::Loopback => "loopback",
        }
    }
}
