//! AXI4 (full) verification components: an active master (`master`), a
//! burst-aware golden memory (`slave`) and a protocol checker (`monitor`).
//!
//! Covers INCR / FIXED / WRAP bursts, multi-beat transfers with
//! `WLAST`/`RLAST`, per-transaction IDs, byte strobes and narrow `AxSIZE`,
//! multiple outstanding transactions with interleaved out-of-order read data
//! and out-of-order write responses, and exclusive access (`AxLOCK`/`EXOKAY`).

mod checker;
mod master;
mod ram;

pub use checker::{Axi4Checker, Axi4MonitorPorts};
pub use master::{Axi4Master, Axi4MasterPorts};
pub use ram::{Axi4Ram, Axi4SlavePorts};

/// `AxBURST` encodings.
pub(crate) mod burst {
    pub const FIXED: u64 = 0b00;
    pub const INCR: u64 = 0b01;
    pub const WRAP: u64 = 0b10;
}

/// Byte address of beat `n` (0-based) of a burst of `len + 1` beats, each
/// `bytes` wide, starting at `start`.
pub(crate) fn beat_addr(start: u64, bytes: u64, kind: u64, len: u64, n: u64) -> u64 {
    match kind {
        burst::FIXED => start,
        burst::WRAP => {
            let block = (len + 1) * bytes;
            let base = (start / block) * block;
            base + (start - base + n * bytes) % block
        }
        _ => {
            let aligned = start & !(bytes - 1);
            aligned + n * bytes
        }
    }
}
