//! AXI4-Stream verification components: an active source (`transmitter`), a
//! golden sink (`receiver`) and a passive protocol checker (`monitor`), which
//! observes every stream signal read-only through the monitor modport. The
//! data path is width-agnostic (word vectors).

mod checker;
mod sink;
mod source;

pub use checker::{Axi4StreamChecker, AxiStreamMonitorPorts};
pub use sink::{Axi4StreamSink, AxiStreamReceiverPorts};
pub use source::{Axi4StreamSource, AxiStreamTransmitterPorts};
