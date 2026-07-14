//! AXI4-Lite verification components: a protocol checker (`monitor`), a
//! golden memory model (`slave`) and an active master (`master`). The data
//! path is width-agnostic (word vectors); addresses are treated as `u64`.

mod checker;
mod master;
mod ram;

pub use checker::{Axi4LiteChecker, Axi4LiteMonitorPorts};
pub use master::{Axi4LiteMaster, Axi4LiteMasterPorts};
pub use ram::{Axi4LiteRam, Axi4LiteSlavePorts};
