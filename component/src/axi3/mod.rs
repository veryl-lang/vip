//! AXI3 verification components: an active master (`master`), a burst-aware
//! golden memory (`slave`) and a protocol checker (`monitor`).
//!
//! AXI3 differs from AXI4 in the write channel: each W beat carries a `WID`,
//! so a master may **interleave the write data** of several outstanding
//! bursts. These parts exercise that path — the master drives `WID` and
//! round-robins beats, the slave routes them back to their transaction by
//! `WID`, and the checker counts `WLAST` per `WID`. `AxLEN` is 4 bits (≤ 16
//! beats) and `AxLOCK` is the 2-bit encoding (`0b01` = exclusive). Burst
//! addressing (`beat_addr`) is shared with the AXI4 components.

mod checker;
mod master;
mod ram;

pub use checker::{Axi3Checker, Axi3MonitorPorts};
pub use master::{Axi3Master, Axi3MasterPorts};
pub use ram::{Axi3Ram, Axi3SlavePorts};
