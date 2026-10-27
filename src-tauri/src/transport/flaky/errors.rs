use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum FlakyTransportError {
    SimulatedDrop,
    SimulatedReorder,
    SimulatedDuplication,
    BandwidthExceeded,
}

impl fmt::Display for FlakyTransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SimulatedDrop => write!(f, "simulated drop executed"),
            Self::SimulatedReorder => write!(f, "simulated reorder executed"),
            Self::SimulatedDuplication => write!(f, "simulated duplication executed"),
            Self::BandwidthExceeded => write!(f, "bandwidth limit exceeded"),
        }
    }
}
