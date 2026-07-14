//! Reusable AXI verification components for the Veryl simulator.
//!
//! The Veryl standard library ships the AXI interface definitions (e.g.
//! `axi4_lite_if`) but no parts to exercise them. This crate fills that gap
//! with bus-functional models, memory models and protocol checkers that
//! connect to the interfaces' own modports. Protocol-agnostic building
//! blocks live in [`common`]; each protocol has its own module.
//!
//! Currently implemented: [`axi4_lite`] — a checker (`monitor`), a golden
//! memory model (`slave`) and an active master (`master`).
//!
//! Wire them into a Veryl testbench through `Veryl.toml`:
//!
//! ```toml
//! [[components]]
//! path = "path/to/this/crate"
//! ```
//!
//! then instantiate against an `axi4_lite_if` instance:
//!
//! ```veryl
//! inst mst: $comp::axi4_lite_master (clk, rst, axi: bus.master );
//! inst chk: $comp::axi4_lite_checker(clk, rst, axi: bus.monitor);
//! inst ram: $comp::axi4_lite_ram    (clk, rst, axi: bus.slave  );
//! ```

use veryl_component::*;

mod common;

pub mod axi3;
pub mod axi4;
pub mod axi4_lite;
pub mod axi4_stream;

pub use axi3::{Axi3Checker, Axi3Master, Axi3Ram};
pub use axi4::{Axi4Checker, Axi4Master, Axi4Ram};
pub use axi4_lite::{Axi4LiteChecker, Axi4LiteMaster, Axi4LiteRam};
pub use axi4_stream::{Axi4StreamChecker, Axi4StreamSink, Axi4StreamSource};

veryl_component_export!(
    "axi4_lite_checker" => Axi4LiteChecker,
    "axi4_lite_ram" => Axi4LiteRam,
    "axi4_lite_master" => Axi4LiteMaster,
    "axi4_stream_source" => Axi4StreamSource,
    "axi4_stream_sink" => Axi4StreamSink,
    "axi4_stream_checker" => Axi4StreamChecker,
    "axi4_master" => Axi4Master,
    "axi4_ram" => Axi4Ram,
    "axi4_checker" => Axi4Checker,
    "axi3_master" => Axi3Master,
    "axi3_ram" => Axi3Ram,
    "axi3_checker" => Axi3Checker,
);

#[cfg(test)]
mod port_set_tests {
    use veryl_component::VerylInterface;

    /// Member names declared in a port set's manifest fragment.
    fn members(json: &str) -> Vec<String> {
        json.split(r#""member":""#)
            .skip(1)
            .map(|s| s.split('"').next().unwrap().to_string())
            .collect()
    }

    /// A monitor must observe every signal either bus side touches; an
    /// omission is otherwise silent (undeclared members are tolerated).
    fn assert_monitor_covers(monitor: &str, sides: [&str; 2]) {
        let monitor = members(monitor);
        for side in sides {
            for m in members(side) {
                assert!(monitor.contains(&m), "monitor misses member `{m}`");
            }
        }
    }

    #[test]
    fn monitors_cover_both_bus_sides() {
        use crate::{axi3, axi4, axi4_lite, axi4_stream};
        assert_monitor_covers(
            axi4_lite::Axi4LiteMonitorPorts::MEMBERS_JSON,
            [
                axi4_lite::Axi4LiteMasterPorts::MEMBERS_JSON,
                axi4_lite::Axi4LiteSlavePorts::MEMBERS_JSON,
            ],
        );
        assert_monitor_covers(
            axi4::Axi4MonitorPorts::MEMBERS_JSON,
            [
                axi4::Axi4MasterPorts::MEMBERS_JSON,
                axi4::Axi4SlavePorts::MEMBERS_JSON,
            ],
        );
        assert_monitor_covers(
            axi3::Axi3MonitorPorts::MEMBERS_JSON,
            [
                axi3::Axi3MasterPorts::MEMBERS_JSON,
                axi3::Axi3SlavePorts::MEMBERS_JSON,
            ],
        );
        assert_monitor_covers(
            axi4_stream::AxiStreamMonitorPorts::MEMBERS_JSON,
            [
                axi4_stream::AxiStreamTransmitterPorts::MEMBERS_JSON,
                axi4_stream::AxiStreamReceiverPorts::MEMBERS_JSON,
            ],
        );
    }
}
