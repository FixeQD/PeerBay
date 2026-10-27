#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FlakyConfig {
    pub drop_rate: f64,
    pub delay_ms: u32,
    pub reorder_rate: f64,
    pub duplicate_rate: f64,
    pub bandwidth_bytes: Option<u64>,
}
