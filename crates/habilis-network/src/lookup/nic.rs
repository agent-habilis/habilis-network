// A browser has no network interface to list.
#![cfg(not(target_arch = "wasm32"))]

use std::net::Ipv4Addr;

/// One `IPv4` address of a network interface that is up.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Nic {
    pub(super) name: String,
    pub(super) index: u32,
    pub(super) address: Ipv4Addr,
    pub(super) prefix_len: u8,
    /// The interface that carries the default route of the host.
    pub(super) on_default_route: bool,
}
