//! Local pairing nonce exchange boundary.

pub mod exchange;
pub mod errors;

pub use errors::{PairingExchangeError, PairingStateMachineError};
pub use exchange::{
    PairingExchange, PairingExchangeState, PairingManager, PairingRole, PairingSas, PairingSession, SAS_CODE_LENGTH,
};
