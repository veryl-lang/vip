//! Passive AXI4-Stream protocol checker.

use crate::common::{Channel, fail_at, fold_words, high};
use veryl_component::*;

#[derive(VerylInterface)]
#[interface(path = "$std::axi4_stream_if", modport = "monitor")]
pub struct AxiStreamMonitorPorts {
    tvalid: InputPort,
    tready: InputPort,
    tdata: InputPort,
    tstrb: InputPort,
    tkeep: InputPort,
    tlast: InputPort,
    tid: InputPort,
    tdest: InputPort,
    tuser: InputPort,
}

/// Passive AXI4-Stream protocol checker. Connect to the `monitor` modport;
/// it drives nothing and fails the test on any handshake violation. Works at
/// any bus width (payloads compare as values).
#[derive(Component)]
#[component(kind = clocked, requires(file))]
pub struct Axi4StreamChecker {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; while asserted TVALID must stay low.
    rst: ResetPort,

    /// The AXI4-Stream bus, observed passively through the monitor modport.
    #[interface]
    axi: AxiStreamMonitorPorts,

    /// Cycles TVALID may stay high without TREADY before a hang is reported.
    #[param(name = "TIMEOUT")]
    timeout: Option<u64>,
    /// If set, the end-of-test coverage summary is written to this path.
    #[param(name = "REPORT")]
    report: Option<String>,

    ch: Channel,
    beats: u64,
    packets: u64,
    keep_seen: u64,
    strb_seen: u64,
    tr_beats: Option<TraceVar>,
}

impl Axi4StreamChecker {
    fn summary(&self) -> String {
        format!(
            "AXI4-Stream checker: {} beat(s), {} packet(s); keep lanes={:#x}, strb lanes={:#x}; \
             max stall={} cyc",
            self.beats, self.packets, self.keep_seen, self.strb_seen, self.ch.max_stall,
        )
    }
}

#[component_impl]
impl Axi4StreamChecker {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        self.tr_beats = ctx.trace_var("beats", 32).ok();
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            if ctx.read(self.axi.tvalid).as_bool() {
                fail_at(ctx, "AXI4-Stream: TVALID must be low during reset");
            }
            self.ch.clear();
            return Ok(());
        }
        let four_state = ctx.is_4state();

        let tvalid = ctx.read(self.axi.tvalid);
        let tready = ctx.read(self.axi.tready);
        let tdata = ctx.read(self.axi.tdata);
        let tstrb = ctx.read(self.axi.tstrb);
        let tkeep = ctx.read(self.axi.tkeep);
        let tlast = ctx.read(self.axi.tlast);
        let tid = ctx.read(self.axi.tid);
        let tdest = ctx.read(self.axi.tdest);
        let tuser = ctx.read(self.axi.tuser);

        // Payload must be known while TVALID is asserted (four-state).
        if four_state
            && high(&tvalid)
            && [&tdata, &tstrb, &tkeep, &tlast, &tid, &tdest, &tuser]
                .iter()
                .any(|f| f.has_unknown())
        {
            fail_at(ctx, "AXI4-Stream: payload is X/Z while TVALID");
        }
        if four_state && (tvalid.has_unknown() || tready.has_unknown()) {
            fail_at(ctx, "AXI4-Stream: TVALID/TREADY is X/Z");
        }

        // TVALID must hold and the payload stay stable until TREADY.
        let payload = [
            tdata.clone(),
            tstrb.clone(),
            tkeep.clone(),
            tlast.clone(),
            tid,
            tdest,
            tuser,
        ];
        if let Some(reason) = self.ch.check(high(&tvalid), high(&tready), &payload) {
            fail_at(ctx, format!("AXI4-Stream: {reason}"));
        }

        if let Some(limit) = self.timeout
            && self.ch.stall_cycles == limit.saturating_add(1)
        {
            fail_at(
                ctx,
                format!("AXI4-Stream: no TREADY within {limit} cycles (timeout)"),
            );
        }

        // Coverage.
        if high(&tvalid) && high(&tready) {
            self.beats += 1;
            if high(&tlast) {
                self.packets += 1;
            }
            self.keep_seen |= fold_words(&tkeep);
            self.strb_seen |= fold_words(&tstrb);
        }
        if let Some(v) = self.tr_beats {
            ctx.trace(v, self.beats);
        }
        Ok(())
    }

    fn on_finish(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let summary = self.summary();
        ctx.log(&summary);
        if let Some(path) = self.report.clone() {
            use std::io::Write;
            let mut file = ctx.create(&path)?;
            writeln!(file, "{summary}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veryl_component::testing::MockSim;

    fn checker_sim() -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .input("axi.tvalid", 1)
            .input("axi.tready", 1)
            .input("axi.tdata", 32)
            .input("axi.tstrb", 4)
            .input("axi.tkeep", 4)
            .input("axi.tlast", 1)
            .input("axi.tid", 4)
            .input("axi.tdest", 2)
            .input("axi.tuser", 5)
    }

    #[test]
    fn legal_stream_passes() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4StreamChecker>().unwrap();
        sim.set("rst", 0u64);
        // A stalled-but-stable beat (payload, including TLAST, held), then
        // the handshake.
        sim.set("axi.tvalid", 1u64);
        sim.set("axi.tdata", 0xabcu64);
        sim.set("axi.tkeep", 0xfu64);
        sim.set("axi.tstrb", 0xfu64);
        sim.set("axi.tlast", 1u64);
        sim.clock(&mut c).unwrap();
        sim.clock(&mut c).unwrap();
        sim.set("axi.tready", 1u64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.tvalid", 0u64);
        sim.clock(&mut c).unwrap();
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn tvalid_dropped_before_tready_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4StreamChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.tvalid", 1u64);
        sim.set("axi.tdata", 0xabcu64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.tvalid", 0u64); // dropped without TREADY
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("VALID deasserted"))
        );
    }

    #[test]
    fn payload_change_while_stalled_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4StreamChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.tvalid", 1u64);
        sim.set("axi.tdata", 0x111u64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.tdata", 0x222u64); // changed while stalled
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("payload changed")));
    }

    #[test]
    fn coverage_is_reported() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4StreamChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.tvalid", 1u64);
        sim.set("axi.tready", 1u64);
        sim.set("axi.tdata", 0x1u64);
        sim.set("axi.tkeep", 0xfu64);
        sim.set("axi.tlast", 1u64);
        sim.clock(&mut c).unwrap();
        sim.finish(&mut c).unwrap();
        let summary = sim.logs().join("\n");
        assert!(summary.contains("1 beat(s)"), "{summary}");
        assert!(summary.contains("1 packet(s)"), "{summary}");
        assert!(summary.contains("keep lanes=0xf"), "{summary}");
    }

    // --- AMBA compliance: directed rule tests ---

    /// A `width`-bit value whose bit 0 is driven X (unknown).
    fn x_bit(width: u32) -> Value {
        Value::from_bits([0].into_iter().collect(), [1].into_iter().collect(), width)
    }

    #[test]
    fn directed_tvalid_high_during_reset_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4StreamChecker>().unwrap();
        sim.set("rst", 1u64);
        sim.set("axi.tvalid", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("TVALID must be low during reset"))
        );
    }

    #[test]
    fn directed_payload_x_while_tvalid_fails() {
        let mut sim = checker_sim().four_state(true);
        let mut c = sim.build::<Axi4StreamChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.tvalid", 1u64);
        sim.set("axi.tdata", x_bit(32));
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("X/Z while TVALID"))
        );
    }

    #[test]
    fn directed_control_line_x_fails() {
        let mut sim = checker_sim().four_state(true);
        let mut c = sim.build::<Axi4StreamChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.tvalid", x_bit(1));
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("TVALID/TREADY is X/Z"))
        );
    }

    #[test]
    fn directed_stall_beyond_timeout_fails() {
        let mut sim = checker_sim().param("TIMEOUT", 4u64);
        let mut c = sim.build::<Axi4StreamChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.tvalid", 1u64);
        sim.set("axi.tdata", 0xabcu64);
        sim.set("axi.tkeep", 0xfu64);
        for _ in 0..8 {
            sim.clock(&mut c).unwrap();
        }
        assert!(sim.failures().iter().any(|f| f.contains("timeout")));
    }
}
