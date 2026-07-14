//! Passive AXI4-Lite protocol checker.

use crate::common::{Channel, Latency, fail_at, fold_words, high, resp};
use std::collections::HashSet;
use veryl_component::*;

#[derive(VerylInterface)]
#[interface(path = "$std::axi4_lite_if", modport = "monitor")]
pub struct Axi4LiteMonitorPorts {
    awvalid: InputPort,
    awready: InputPort,
    awaddr: InputPort,
    awprot: InputPort,
    wvalid: InputPort,
    wready: InputPort,
    wdata: InputPort,
    wstrb: InputPort,
    bvalid: InputPort,
    bready: InputPort,
    bresp: InputPort,
    arvalid: InputPort,
    arready: InputPort,
    araddr: InputPort,
    arprot: InputPort,
    rvalid: InputPort,
    rready: InputPort,
    rdata: InputPort,
    rresp: InputPort,
}

/// Passive AXI4-Lite protocol checker. Connect to the `monitor` modport;
/// it drives nothing and fails the test on any handshake or response
/// violation it sees. Works at any bus width (payloads compare as values).
#[derive(Component)]
#[component(kind = clocked, requires(file))]
pub struct Axi4LiteChecker {
    /// Bus clock; every edge samples the monitored signals.
    clk: ClockPort,
    /// Bus reset; while asserted all VALIDs must stay low and handshake
    /// history is cleared.
    rst: ResetPort,

    /// The AXI4-Lite bus, observed passively through the monitor modport.
    #[interface]
    axi: Axi4LiteMonitorPorts,

    /// Cycles a channel may stay stalled (VALID without READY) before it is
    /// reported as a hang. Left unset the timeout is disabled.
    #[param(name = "TIMEOUT")]
    timeout: Option<u64>,
    /// Cycles the bus may show no handshake at all while a response is
    /// outstanding before it is reported as a deadlock. Unset disables it.
    #[param(name = "LIVENESS")]
    liveness: Option<u64>,
    /// If set, the end-of-test coverage summary is also written to this path.
    #[param(name = "REPORT")]
    report: Option<String>,

    aw: Channel,
    w: Channel,
    b: Channel,
    ar: Channel,
    r: Channel,

    aw_done: u64,
    w_done: u64,
    b_done: u64,
    ar_done: u64,
    r_done: u64,

    // Coverage.
    resp_okay: u64,
    resp_slverr: u64,
    resp_decerr: u64,
    addr_lo: u64,
    addr_hi: u64,
    seen_addr: bool,
    distinct: HashSet<u64>,
    strobe_seen: u64,
    noop_writes: u64,
    max_outstanding: u64,
    write_lat: Latency,
    read_lat: Latency,

    // Latency bookkeeping: the cycle each request handshook, popped in order.
    aw_cycles: std::collections::VecDeque<u64>,
    ar_cycles: std::collections::VecDeque<u64>,
    idle_cycles: u64,
    tr_outstanding: Option<TraceVar>,
}

impl Axi4LiteChecker {
    fn data_bytes(&self) -> u64 {
        (self.axi.wdata.width() as u64 / 8).max(1)
    }

    fn clear(&mut self) {
        self.aw.clear();
        self.w.clear();
        self.b.clear();
        self.ar.clear();
        self.r.clear();
        // Reset drops in-flight transactions, so the outstanding counters must
        // reset too, or phantom work trips a false liveness deadlock.
        self.aw_done = 0;
        self.w_done = 0;
        self.b_done = 0;
        self.ar_done = 0;
        self.r_done = 0;
        self.aw_cycles.clear();
        self.ar_cycles.clear();
        self.idle_cycles = 0;
    }

    fn note_addr(&mut self, addr: u64) {
        self.distinct.insert(addr);
        if self.seen_addr {
            self.addr_lo = self.addr_lo.min(addr);
            self.addr_hi = self.addr_hi.max(addr);
        } else {
            self.addr_lo = addr;
            self.addr_hi = addr;
            self.seen_addr = true;
        }
    }

    fn note_resp(&mut self, code: u64) {
        match code {
            resp::OKAY => self.resp_okay += 1,
            resp::SLVERR => self.resp_slverr += 1,
            resp::DECERR => self.resp_decerr += 1,
            _ => {} // EXOKAY is reported separately as a violation.
        }
    }

    fn summary(&self) -> String {
        format!(
            "AXI4-Lite checker: {} write(s), {} read(s); resp okay={} slverr={} decerr={}; \
             addr [{:#x}..={:#x}] ({} distinct); strobe lanes={:#x}, {} no-op write(s); \
             max outstanding={}; max stall={} cyc; write latency min/avg/max={}/{}/{}; \
             read latency min/avg/max={}/{}/{}",
            self.b_done,
            self.r_done,
            self.resp_okay,
            self.resp_slverr,
            self.resp_decerr,
            self.addr_lo,
            self.addr_hi,
            self.distinct.len(),
            self.strobe_seen,
            self.noop_writes,
            self.max_outstanding,
            self.aw
                .max_stall
                .max(self.w.max_stall)
                .max(self.b.max_stall)
                .max(self.ar.max_stall)
                .max(self.r.max_stall),
            self.write_lat.min,
            self.write_lat.avg(),
            self.write_lat.max,
            self.read_lat.min,
            self.read_lat.avg(),
            self.read_lat.max,
        )
    }
}

#[component_impl]
impl Axi4LiteChecker {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        // Addresses are treated as u64; a wider address bus would silently read
        // as zero.
        for (name, w) in [
            ("awaddr", self.axi.awaddr.width()),
            ("araddr", self.axi.araddr.width()),
        ] {
            if w > 64 {
                bail!("axi4_lite_checker: {name} width {w} exceeds the 64-bit address limit");
            }
        }
        self.tr_outstanding = ctx.trace_var("outstanding", 16).ok();
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            // A master must hold every VALID low throughout reset.
            for (name, port) in [
                ("AWVALID", self.axi.awvalid),
                ("WVALID", self.axi.wvalid),
                ("BVALID", self.axi.bvalid),
                ("ARVALID", self.axi.arvalid),
                ("RVALID", self.axi.rvalid),
            ] {
                if ctx.read(port).as_bool() {
                    fail_at(ctx, format!("AXI4-Lite: {name} must be low during reset"));
                }
            }
            self.clear();
            return Ok(());
        }
        let four_state = ctx.is_4state();
        let now = ctx.cycle();

        let awvalid = ctx.read(self.axi.awvalid);
        let awready = ctx.read(self.axi.awready);
        let awaddr = ctx.read(self.axi.awaddr);
        let awprot = ctx.read(self.axi.awprot);
        let wvalid = ctx.read(self.axi.wvalid);
        let wready = ctx.read(self.axi.wready);
        let wdata = ctx.read(self.axi.wdata);
        let wstrb = ctx.read(self.axi.wstrb);
        let bvalid = ctx.read(self.axi.bvalid);
        let bready = ctx.read(self.axi.bready);
        let bresp = ctx.read(self.axi.bresp);
        let arvalid = ctx.read(self.axi.arvalid);
        let arready = ctx.read(self.axi.arready);
        let araddr = ctx.read(self.axi.araddr);
        let arprot = ctx.read(self.axi.arprot);
        let rvalid = ctx.read(self.axi.rvalid);
        let rready = ctx.read(self.axi.rready);
        let rdata = ctx.read(self.axi.rdata);
        let rresp = ctx.read(self.axi.rresp);

        // Values needed after the payloads are moved into the stability check.
        let aw_addr = awaddr.as_u64().unwrap_or(0);
        let ar_addr = araddr.as_u64().unwrap_or(0);
        let b_resp = bresp.as_u64().unwrap_or(0);
        let r_resp = rresp.as_u64().unwrap_or(0);
        // Folded so the strobe-lane coverage stays valid past a 64-byte bus.
        let w_strb = fold_words(&wstrb);

        // Payload must be known while its VALID is asserted (four-state).
        if four_state {
            let payloads: [(&str, bool, &[&Value]); 5] = [
                ("AW", high(&awvalid), &[&awaddr, &awprot]),
                ("W", high(&wvalid), &[&wdata, &wstrb]),
                ("B", high(&bvalid), &[&bresp]),
                ("AR", high(&arvalid), &[&araddr, &arprot]),
                ("R", high(&rvalid), &[&rdata, &rresp]),
            ];
            for (name, valid, fields) in payloads {
                if valid && fields.iter().any(|f| f.has_unknown()) {
                    fail_at(ctx, format!("AXI4-Lite {name}: payload is X/Z while VALID"));
                }
            }
        }

        // Handshake stability, per channel.
        let checks = [
            (
                "AW",
                self.aw
                    .check(high(&awvalid), high(&awready), &[awaddr, awprot]),
            ),
            (
                "W",
                self.w.check(high(&wvalid), high(&wready), &[wdata, wstrb]),
            ),
            (
                "B",
                self.b
                    .check(high(&bvalid), high(&bready), std::slice::from_ref(&bresp)),
            ),
            (
                "AR",
                self.ar
                    .check(high(&arvalid), high(&arready), &[araddr, arprot]),
            ),
            (
                "R",
                self.r.check(high(&rvalid), high(&rready), &[rdata, rresp]),
            ),
        ];
        for (name, violation) in checks {
            if let Some(reason) = violation {
                fail_at(ctx, format!("AXI4-Lite {name}: {reason}"));
            }
        }

        // AXI4-Lite has no exclusive access, so EXOKAY is never legal.
        if high(&bvalid) && b_resp == resp::EXOKAY {
            fail_at(ctx, "AXI4-Lite B: EXOKAY is not a legal AXI4-Lite response");
        }
        if high(&rvalid) && r_resp == resp::EXOKAY {
            fail_at(ctx, "AXI4-Lite R: EXOKAY is not a legal AXI4-Lite response");
        }

        // Control lines must never be X/Z under a four-state run.
        if four_state {
            for (name, v) in [
                ("AWVALID", &awvalid),
                ("AWREADY", &awready),
                ("WVALID", &wvalid),
                ("WREADY", &wready),
                ("BVALID", &bvalid),
                ("BREADY", &bready),
                ("ARVALID", &arvalid),
                ("ARREADY", &arready),
                ("RVALID", &rvalid),
                ("RREADY", &rready),
            ] {
                if v.has_unknown() {
                    fail_at(ctx, format!("AXI4-Lite: {name} is X/Z"));
                }
            }
        }

        let aw_hs = high(&awvalid) && high(&awready);
        let w_hs = high(&wvalid) && high(&wready);
        let b_hs = high(&bvalid) && high(&bready);
        let ar_hs = high(&arvalid) && high(&arready);
        let r_hs = high(&rvalid) && high(&rready);

        // Addresses must be aligned to the data width.
        let mask = self.data_bytes() - 1;
        if aw_hs && aw_addr & mask != 0 {
            fail_at(ctx, format!("AXI4-Lite AW: unaligned address {aw_addr:#x}"));
        }
        if ar_hs && ar_addr & mask != 0 {
            fail_at(ctx, format!("AXI4-Lite AR: unaligned address {ar_addr:#x}"));
        }

        // Outstanding-transaction accounting: a response may not overtake its
        // request. Each AXI4-Lite write is one AW + one W + one B beat.
        self.aw_done += aw_hs as u64;
        self.w_done += w_hs as u64;
        self.b_done += b_hs as u64;
        self.ar_done += ar_hs as u64;
        self.r_done += r_hs as u64;
        if self.b_done > self.aw_done.min(self.w_done) {
            fail_at(ctx, "AXI4-Lite B: write response with no outstanding write");
        }
        if self.r_done > self.ar_done {
            fail_at(ctx, "AXI4-Lite R: read response with no outstanding read");
        }

        // Hang timeout: a channel stalled too long without READY.
        if let Some(limit) = self.timeout {
            for (name, ch) in [
                ("AW", &self.aw),
                ("W", &self.w),
                ("B", &self.b),
                ("AR", &self.ar),
                ("R", &self.r),
            ] {
                if ch.stall_cycles == limit.saturating_add(1) {
                    fail_at(
                        ctx,
                        format!("AXI4-Lite {name}: no READY within {limit} cycles (timeout)"),
                    );
                }
            }
        }

        // Latency of each transaction (request handshake to response).
        if aw_hs {
            self.aw_cycles.push_back(now);
        }
        if ar_hs {
            self.ar_cycles.push_back(now);
        }
        if b_hs && let Some(start) = self.aw_cycles.pop_front() {
            self.write_lat.record(now - start);
        }
        if r_hs && let Some(start) = self.ar_cycles.pop_front() {
            self.read_lat.record(now - start);
        }

        // Coverage.
        if aw_hs {
            self.note_addr(aw_addr);
        }
        if ar_hs {
            self.note_addr(ar_addr);
        }
        if w_hs {
            self.strobe_seen |= w_strb;
            self.noop_writes += (w_strb == 0) as u64;
        }
        if b_hs {
            self.note_resp(b_resp);
        }
        if r_hs {
            self.note_resp(r_resp);
        }
        let outstanding = self.aw_done.min(self.w_done).saturating_sub(self.b_done)
            + self.ar_done.saturating_sub(self.r_done);
        self.max_outstanding = self.max_outstanding.max(outstanding);
        if let Some(v) = self.tr_outstanding {
            ctx.trace(v, outstanding);
        }

        // Liveness: a pending response but no handshake anywhere is a deadlock.
        let any_hs = aw_hs || w_hs || b_hs || ar_hs || r_hs;
        if outstanding > 0 && !any_hs {
            self.idle_cycles += 1;
        } else {
            self.idle_cycles = 0;
        }
        if let Some(limit) = self.liveness
            && self.idle_cycles == limit.saturating_add(1)
        {
            fail_at(
                ctx,
                format!("AXI4-Lite: bus idle for {limit} cycles with work outstanding (deadlock)"),
            );
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
        checker_sim_addr(32)
    }

    fn checker_sim_addr(addr_w: u32) -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .input("axi.awvalid", 1)
            .input("axi.awready", 1)
            .input("axi.awaddr", addr_w)
            .input("axi.awprot", 3)
            .input("axi.wvalid", 1)
            .input("axi.wready", 1)
            .input("axi.wdata", 32)
            .input("axi.wstrb", 4)
            .input("axi.bvalid", 1)
            .input("axi.bready", 1)
            .input("axi.bresp", 2)
            .input("axi.arvalid", 1)
            .input("axi.arready", 1)
            .input("axi.araddr", addr_w)
            .input("axi.arprot", 3)
            .input("axi.rvalid", 1)
            .input("axi.rready", 1)
            .input("axi.rdata", 32)
            .input("axi.rresp", 2)
    }

    #[test]
    fn legal_write_handshake_passes() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);

        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x10u64);
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wdata", 0xdeadu64);
        sim.set("axi.wstrb", 0xfu64);
        sim.clock(&mut c).unwrap();
        sim.clock(&mut c).unwrap();
        sim.set("axi.awready", 1u64);
        sim.set("axi.wready", 1u64);
        sim.clock(&mut c).unwrap();

        sim.set("axi.awvalid", 0u64);
        sim.set("axi.wvalid", 0u64);
        sim.set("axi.awready", 0u64);
        sim.set("axi.wready", 0u64);
        sim.set("axi.bvalid", 1u64);
        sim.set("axi.bready", 1u64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.bvalid", 0u64);
        sim.clock(&mut c).unwrap();

        assert!(!sim.failed(), "unexpected failures: {:?}", sim.failures());
    }

    #[test]
    fn valid_dropped_before_ready_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x10u64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.awvalid", 0u64);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("AW") && f.contains("VALID deasserted"))
        );
    }

    #[test]
    fn payload_change_while_stalled_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x10u64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.awaddr", 0x20u64);
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("payload changed")));
    }

    #[test]
    fn exokay_response_is_rejected() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.bvalid", 1u64);
        sim.set("axi.bresp", resp::EXOKAY);
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("EXOKAY")));
    }

    #[test]
    fn response_without_request_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.bvalid", 1u64);
        sim.set("axi.bready", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("no outstanding write"))
        );
    }

    #[test]
    fn valid_high_during_reset_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 1u64);
        sim.set("axi.awvalid", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("AWVALID") && f.contains("during reset"))
        );
    }

    #[test]
    fn stall_beyond_timeout_fails() {
        let mut sim = checker_sim().param("TIMEOUT", 3u64);
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x10u64);
        for _ in 0..5 {
            sim.clock(&mut c).unwrap();
        }
        assert!(sim.failures().iter().any(|f| f.contains("timeout")));
    }

    #[test]
    fn unaligned_address_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        // 32-bit data => 4-byte alignment; 0x12 is unaligned.
        sim.set("axi.arvalid", 1u64);
        sim.set("axi.arready", 1u64);
        sim.set("axi.araddr", 0x12u64);
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("unaligned")));
    }

    #[test]
    fn deadlock_trips_liveness() {
        let mut sim = checker_sim().param("LIVENESS", 4u64);
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        // One read request accepted, then the bus goes silent (no R).
        sim.set("axi.arvalid", 1u64);
        sim.set("axi.arready", 1u64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.arvalid", 0u64);
        sim.set("axi.arready", 0u64);
        for _ in 0..6 {
            sim.clock(&mut c).unwrap();
        }
        assert!(sim.failures().iter().any(|f| f.contains("deadlock")));
    }

    #[test]
    fn failure_messages_carry_the_cycle() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.bvalid", 1u64);
        sim.set("axi.bready", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().all(|f| f.starts_with("cycle ")));
    }

    #[test]
    fn coverage_is_reported_at_finish() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x40u64);
        sim.set("axi.awready", 1u64);
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wready", 1u64);
        sim.set("axi.wstrb", 0xfu64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.awvalid", 0u64);
        sim.set("axi.wvalid", 0u64);
        sim.set("axi.bvalid", 1u64);
        sim.set("axi.bready", 1u64);
        sim.set("axi.bresp", resp::SLVERR);
        sim.clock(&mut c).unwrap();
        sim.finish(&mut c).unwrap();

        let summary = sim.logs().join("\n");
        assert!(summary.contains("1 write(s)"), "{summary}");
        assert!(summary.contains("slverr=1"), "{summary}");
        assert!(summary.contains("strobe lanes=0xf"), "{summary}");
        assert!(summary.contains("latency"), "{summary}");
    }

    #[test]
    fn report_is_written_to_file() {
        let path = std::env::temp_dir().join("axi4_lite_checker_report.txt");
        let mut sim = checker_sim().param("REPORT", path.to_str().unwrap());
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.clock(&mut c).unwrap();
        sim.finish(&mut c).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("AXI4-Lite checker:"), "{text}");
        std::fs::remove_file(&path).ok();
    }

    // --- AMBA compliance: directed rule tests ---

    /// A `width`-bit value whose bit 0 is driven X (unknown).
    fn x_bit(width: u32) -> Value {
        Value::from_bits([0].into_iter().collect(), [1].into_iter().collect(), width)
    }

    #[test]
    fn directed_read_exokay_rejected() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.rvalid", 1u64);
        sim.set("axi.rresp", resp::EXOKAY);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("R") && f.contains("EXOKAY"))
        );
    }

    #[test]
    fn directed_read_response_without_request_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.rvalid", 1u64);
        sim.set("axi.rready", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("no outstanding read"))
        );
    }

    #[test]
    fn directed_payload_x_while_valid_fails() {
        let mut sim = checker_sim().four_state(true);
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", x_bit(32));
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("X/Z while VALID")));
    }

    #[test]
    fn directed_control_line_x_fails() {
        let mut sim = checker_sim().four_state(true);
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", x_bit(1));
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("AWVALID is X/Z")));
    }

    #[test]
    fn reset_clears_outstanding_no_phantom_deadlock() {
        let mut sim = checker_sim().param("LIVENESS", 3u64);
        let mut c = sim.build::<Axi4LiteChecker>().unwrap();
        sim.set("rst", 0u64);
        // A write's AW and W handshake, but its B never arrives.
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awready", 1u64);
        sim.set("axi.awaddr", 0x10u64);
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wready", 1u64);
        sim.set("axi.wstrb", 0xfu64);
        sim.clock(&mut c).unwrap();
        // Reset drops the in-flight write (all VALIDs low during reset).
        sim.set("axi.awvalid", 0u64);
        sim.set("axi.wvalid", 0u64);
        sim.set("axi.awready", 0u64);
        sim.set("axi.wready", 0u64);
        sim.set("rst", 1u64);
        sim.clock(&mut c).unwrap();
        sim.set("rst", 0u64);
        // The bus idles well past the liveness limit; without clearing the
        // outstanding counters this would trip a false deadlock.
        for _ in 0..6 {
            sim.clock(&mut c).unwrap();
        }
        assert!(!sim.failed(), "unexpected failures: {:?}", sim.failures());
    }

    #[test]
    fn address_wider_than_64_bits_is_rejected() {
        let mut sim = checker_sim_addr(96);
        let err = sim.build::<Axi4LiteChecker>().err().unwrap();
        assert!(err.to_string().contains("64-bit address limit"), "{err}");
    }
}
