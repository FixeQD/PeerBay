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
