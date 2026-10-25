//! UmbraC2 beacon library.
//!
//! Layers (bottom to top):
//!   upk      canonical binary encoding        (contracts/vectors.json)
//!   crypto   X25519 + HKDF-SHA256 + AEAD
//!   wire     frame format and message registry
//!   session  per-connection key/nonce state machine
//!   transport TCP and HTTP channels
//!   task     command execution
//!   beacon   the actual loop

pub mod beacon;
pub mod config;
pub mod crypto;
pub mod session;
pub mod sysinfo;
pub mod task;
pub mod transport;
pub mod upk;
pub mod wire;

pub use beacon::Beacon;
pub use config::Config;
