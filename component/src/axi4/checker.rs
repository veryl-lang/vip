//! Passive AXI4 (full) protocol checker.

use crate::common::{Channel, Latency, fail_at, high, resp};
use std::collections::{HashMap, VecDeque};
use veryl_component::*;

#[derive(VerylInterface)]
#[interface(path = "$std::axi4_if", modport = "monitor")]
pub struct Axi4MonitorPorts {
    awvalid: InputPort,
    awready: InputPort,
    awaddr: InputPort,
    awlen: InputPort,
    awsize: InputPort,
    awburst: InputPort,
    awid: InputPort,
    awlock: InputPort,
    wvalid: InputPort,
    wready: InputPort,
    wdata: InputPort,
    wstrb: InputPort,
    wlast: InputPort,
    bvalid: InputPort,
    bready: InputPort,
    bresp: InputPort,
    bid: InputPort,
    arvalid: InputPort,
    arready: InputPort,
    araddr: InputPort,
    arlen: InputPort,
    arsize: InputPort,
    arburst: InputPort,
    arid: InputPort,
    arlock: InputPort,
    rvalid: InputPort,
    rready: InputPort,
    rdata: InputPort,
    rresp: InputPort,
    rid: InputPort,
    rlast: InputPort,
}

/// Passive AXI4 protocol checker on the `monitor` modport. On top of the
/// per-channel handshake-stability rules it enforces burst legality:
/// `WLAST`/`RLAST` aligning with `AxLEN`, bursts staying inside a 4 KiB page,
/// legal `AxBURST`/`AxSIZE`. It tracks responses per ID, so it accepts
/// interleaved out-of-order reads and out-of-order write responses, and
/// flags a `BID`/`RID` with no outstanding request. Exclusive transactions
/// (`AxLOCK`) must be power-of-two, ≤ 16 beats, ≤ 128 bytes and size-aligned,
/// and `EXOKAY` may only answer an exclusive access.
#[derive(Component)]
#[component(kind = clocked, requires(file))]
pub struct Axi4Checker {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; while asserted all VALIDs must stay low.
    rst: ResetPort,

    /// The AXI4 bus, observed passively through the monitor modport.
    #[interface]
    axi: Axi4MonitorPorts,

    /// Cycles a channel may stall without READY before a hang is reported.
    #[param(name = "TIMEOUT")]
    timeout: Option<u64>,
    /// If set, the end-of-test coverage summary is written to this path.
    #[param(name = "REPORT")]
    report: Option<String>,

    aw: Channel,
    w: Channel,
    b: Channel,
    ar: Channel,
    r: Channel,

    // W data is in AW order, so WLAST beat counts are a global FIFO.
    w_expect: VecDeque<u64>,
    w_count: u64,
    // B and R responses may be out of order, so they are tracked per ID.
    w_cycles_by_id: HashMap<u64, VecDeque<u64>>,
    w_excl_by_id: HashMap<u64, VecDeque<bool>>,
    r_expect_by_id: HashMap<u64, VecDeque<u64>>,
    r_count_by_id: HashMap<u64, u64>,
    r_cycles_by_id: HashMap<u64, VecDeque<u64>>,
    r_excl_by_id: HashMap<u64, VecDeque<bool>>,

    // Coverage.
    writes: u64,
    reads: u64,
    beats: u64,
    max_len: u64,
    fixed: u64,
    incr: u64,
    wrap: u64,
    sizes_seen: u64,
    exclusive: u64,
    exclusive_ok: u64,
    resp_okay: u64,
    resp_slverr: u64,
    resp_decerr: u64,
    write_lat: Latency,
    read_lat: Latency,
    tr_beats: Option<TraceVar>,
}

impl Axi4Checker {
    fn data_bytes(&self) -> u64 {
        (self.axi.wdata.width() as u64 / 8).max(1)
    }

    /// Validates the address-phase attributes of a burst.
    #[allow(clippy::too_many_arguments)]
    fn check_burst(
        &mut self,
        ctx: &mut SimCtx,
        ch: &str,
        addr: u64,
        len: u64,
        size: u64,
        kind: u64,
        lock: u64,
    ) {
        let bytes = 1u64 << size;
        if bytes > self.data_bytes() {
            fail_at(ctx, format!("AXI4 {ch}: SIZE {bytes} exceeds bus width"));
        }
        // Exclusive access: power-of-two beat count, ≤ 16 beats, ≤ 128 bytes
        // total, and an address aligned to the total transfer size.
        if lock != 0 {
            if !matches!(len, 0 | 1 | 3 | 7 | 15) {
                fail_at(
                    ctx,
                    format!(
                        "AXI4 {ch}: exclusive length {} is not a power of two",
                        len + 1
                    ),
                );
            }
            let total = (len + 1) * bytes;
            if total > 128 {
                fail_at(
                    ctx,
                    format!("AXI4 {ch}: exclusive burst of {total} bytes exceeds 128"),
                );
            }
            if total.is_power_of_two() && addr & (total - 1) != 0 {
                fail_at(
                    ctx,
                    format!("AXI4 {ch}: exclusive address {addr:#x} not aligned to {total}"),
                );
            }
            self.exclusive += 1;
        }
        if kind > 2 {
            fail_at(ctx, format!("AXI4 {ch}: reserved BURST type {kind}"));
        }
        // FIXED and WRAP bursts are limited to 16 beats.
        if kind != 1 && len > 15 {
            fail_at(
                ctx,
                format!(
                    "AXI4 {ch}: {} beats exceeds 16 for this burst type",
                    len + 1
                ),
            );
        }
        // INCR bursts must not cross a 4 KiB boundary.
        if kind == 1 {
            let last = addr.saturating_add((len + 1) * bytes).saturating_sub(1);
            if addr & !0xfff != last & !0xfff {
                fail_at(
                    ctx,
                    format!("AXI4 {ch}: INCR burst crosses a 4 KiB boundary"),
                );
            }
        }
        // WRAP bursts need a power-of-two beat count and an aligned address.
        if kind == 2 {
            if !matches!(len, 1 | 3 | 7 | 15) {
                fail_at(
                    ctx,
                    format!("AXI4 {ch}: WRAP length {} is not 2/4/8/16", len + 1),
                );
            }
            if addr & (bytes - 1) != 0 {
                fail_at(
                    ctx,
                    format!("AXI4 {ch}: WRAP address {addr:#x} not size-aligned"),
                );
            }
        }
        // Count coverage only for legal burst types (a reserved type is a
        // failure above, not an INCR).
        match kind {
            0 => self.fixed += 1,
            1 => self.incr += 1,
            2 => self.wrap += 1,
            _ => {}
        }
        self.sizes_seen |= 1 << size;
        self.max_len = self.max_len.max(len);
    }

    fn note_resp(&mut self, code: u64) {
        match code {
            resp::OKAY => self.resp_okay += 1,
            resp::SLVERR => self.resp_slverr += 1,
            resp::DECERR => self.resp_decerr += 1,
            _ => {} // EXOKAY is tallied via the exclusive counters.
        }
    }

    fn summary(&self) -> String {
        format!(
            "AXI4 checker: {} write(s), {} read(s), {} beat(s); burst fixed={} incr={} wrap={}; \
             exclusive={} (EXOKAY={}); resp okay={} slverr={} decerr={}; \
             max len={}; sizes={:#x}; write latency min/avg/max={}/{}/{}; \
             read latency min/avg/max={}/{}/{}; max stall={} cyc",
            self.writes,
            self.reads,
            self.beats,
            self.fixed,
            self.incr,
            self.wrap,
            self.exclusive,
            self.exclusive_ok,
            self.resp_okay,
            self.resp_slverr,
            self.resp_decerr,
            self.max_len,
            self.sizes_seen,
            self.write_lat.min,
            self.write_lat.avg(),
            self.write_lat.max,
            self.read_lat.min,
            self.read_lat.avg(),
            self.read_lat.max,
            self.aw
                .max_stall
                .max(self.w.max_stall)
                .max(self.b.max_stall)
                .max(self.ar.max_stall)
                .max(self.r.max_stall),
        )
    }
}

#[component_impl]
impl Axi4Checker {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        // Addresses are treated as u64; a wider address bus would silently read
        // as zero.
        for (name, w) in [
            ("awaddr", self.axi.awaddr.width()),
            ("araddr", self.axi.araddr.width()),
        ] {
            if w > 64 {
                bail!("axi4_checker: {name} width {w} exceeds the 64-bit address limit");
            }
        }
        self.tr_beats = ctx.trace_var("beats", 32).ok();
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            for (name, port) in [
                ("AWVALID", self.axi.awvalid),
                ("WVALID", self.axi.wvalid),
                ("BVALID", self.axi.bvalid),
                ("ARVALID", self.axi.arvalid),
                ("RVALID", self.axi.rvalid),
            ] {
                if ctx.read(port).as_bool() {
                    fail_at(ctx, format!("AXI4: {name} must be low during reset"));
                }
            }
            self.aw.clear();
            self.w.clear();
            self.b.clear();
            self.ar.clear();
            self.r.clear();
            self.w_expect.clear();
            self.w_count = 0;
            self.w_cycles_by_id.clear();
            self.w_excl_by_id.clear();
            self.r_expect_by_id.clear();
            self.r_count_by_id.clear();
            self.r_cycles_by_id.clear();
            self.r_excl_by_id.clear();
            return Ok(());
        }

        let awvalid = ctx.read(self.axi.awvalid);
        let awready = ctx.read(self.axi.awready);
        let awaddr = ctx.read(self.axi.awaddr);
        let awlen = ctx.read(self.axi.awlen);
        let awsize = ctx.read(self.axi.awsize);
        let awburst = ctx.read(self.axi.awburst);
        let awid = ctx.read(self.axi.awid);
        let wvalid = ctx.read(self.axi.wvalid);
        let wready = ctx.read(self.axi.wready);
        let wdata = ctx.read(self.axi.wdata);
        let wstrb = ctx.read(self.axi.wstrb);
        let wlast = ctx.read(self.axi.wlast);
        let bvalid = ctx.read(self.axi.bvalid);
        let bready = ctx.read(self.axi.bready);
        let bresp = ctx.read(self.axi.bresp);
        let bid = ctx.read(self.axi.bid);
        let arvalid = ctx.read(self.axi.arvalid);
        let arready = ctx.read(self.axi.arready);
        let araddr = ctx.read(self.axi.araddr);
        let arlen = ctx.read(self.axi.arlen);
        let arsize = ctx.read(self.axi.arsize);
        let arburst = ctx.read(self.axi.arburst);
        let arid = ctx.read(self.axi.arid);
        let rvalid = ctx.read(self.axi.rvalid);
        let rready = ctx.read(self.axi.rready);
        let rdata = ctx.read(self.axi.rdata);
        let rresp = ctx.read(self.axi.rresp);
        let rid = ctx.read(self.axi.rid);
        let rlast = ctx.read(self.axi.rlast);
        let awlock = ctx.read(self.axi.awlock);
        let arlock = ctx.read(self.axi.arlock);
        let awlock_code = awlock.as_u64().unwrap_or(0);
        let arlock_code = arlock.as_u64().unwrap_or(0);
        let bresp_code = bresp.as_u64().unwrap_or(0);
        let rresp_code = rresp.as_u64().unwrap_or(0);

        // Nothing may be X/Z on a live line under a four-state run.
        if ctx.is_4state() {
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
                    fail_at(ctx, format!("AXI4: {name} is X/Z"));
                }
            }
            let payloads: [(&str, bool, &[&Value]); 5] = [
                (
                    "AW",
                    high(&awvalid),
                    &[&awaddr, &awlen, &awsize, &awburst, &awid, &awlock],
                ),
                ("W", high(&wvalid), &[&wdata, &wstrb, &wlast]),
                ("B", high(&bvalid), &[&bresp, &bid]),
                (
                    "AR",
                    high(&arvalid),
                    &[&araddr, &arlen, &arsize, &arburst, &arid, &arlock],
                ),
                ("R", high(&rvalid), &[&rdata, &rresp, &rid, &rlast]),
            ];
            for (name, valid, fields) in payloads {
                if valid && fields.iter().any(|f| f.has_unknown()) {
                    fail_at(ctx, format!("AXI4 {name}: payload is X/Z while VALID"));
                }
            }
        }

        // Handshake stability, per channel.
        let checks = [
            (
                "AW",
                self.aw.check(
                    high(&awvalid),
                    high(&awready),
                    &[
                        awaddr.clone(),
                        awlen.clone(),
                        awsize.clone(),
                        awburst.clone(),
                        awid.clone(),
                        awlock.clone(),
                    ],
                ),
            ),
            (
                "W",
                self.w
                    .check(high(&wvalid), high(&wready), &[wdata, wstrb, wlast.clone()]),
            ),
            (
                "B",
                self.b
                    .check(high(&bvalid), high(&bready), &[bresp, bid.clone()]),
            ),
            (
                "AR",
                self.ar.check(
                    high(&arvalid),
                    high(&arready),
                    &[
                        araddr.clone(),
                        arlen.clone(),
                        arsize.clone(),
                        arburst.clone(),
                        arid.clone(),
                        arlock.clone(),
                    ],
                ),
            ),
            (
                "R",
                self.r.check(
                    high(&rvalid),
                    high(&rready),
                    &[rdata, rresp, rid.clone(), rlast.clone()],
                ),
            ),
        ];
        for (name, violation) in checks {
            if let Some(reason) = violation {
                fail_at(ctx, format!("AXI4 {name}: {reason}"));
            }
        }

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
                        format!("AXI4 {name}: no READY within {limit} cycles (timeout)"),
                    );
                }
            }
        }

        let now = ctx.cycle();

        // Address-phase burst legality.
        if high(&awvalid) && high(&awready) {
            let len = awlen.as_u64().unwrap_or(0);
            self.check_burst(
                ctx,
                "AW",
                awaddr.as_u64().unwrap_or(0),
                len,
                awsize.as_u64().unwrap_or(0),
                awburst.as_u64().unwrap_or(0),
                awlock_code,
            );
            let id = awid.as_u64().unwrap_or(0);
            self.w_expect.push_back(len + 1);
            self.w_cycles_by_id.entry(id).or_default().push_back(now);
            self.w_excl_by_id
                .entry(id)
                .or_default()
                .push_back(awlock_code != 0);
        }
        if high(&arvalid) && high(&arready) {
            let len = arlen.as_u64().unwrap_or(0);
            self.check_burst(
                ctx,
                "AR",
                araddr.as_u64().unwrap_or(0),
                len,
                arsize.as_u64().unwrap_or(0),
                arburst.as_u64().unwrap_or(0),
                arlock_code,
            );
            let id = arid.as_u64().unwrap_or(0);
            self.r_expect_by_id
                .entry(id)
                .or_default()
                .push_back(len + 1);
            self.r_cycles_by_id.entry(id).or_default().push_back(now);
            self.r_excl_by_id
                .entry(id)
                .or_default()
                .push_back(arlock_code != 0);
        }

        // Data-phase beat counting: WLAST/RLAST must land on the last beat.
        if high(&wvalid) && high(&wready) {
            self.beats += 1;
            self.w_count += 1;
            if high(&wlast) {
                if let Some(exp) = self.w_expect.pop_front()
                    && self.w_count != exp
                {
                    fail_at(
                        ctx,
                        format!("AXI4 W: WLAST after {} beats, expected {exp}", self.w_count),
                    );
                }
                self.w_count = 0;
            }
        }
        if high(&rvalid) && high(&rready) {
            self.beats += 1;
            self.note_resp(rresp_code);
            let id = rid.as_u64().unwrap_or(0);
            // R may interleave across IDs; track each ID's read separately.
            if self.r_expect_by_id.get(&id).is_none_or(|q| q.is_empty()) {
                fail_at(ctx, format!("AXI4 R: RID {id} has no outstanding read"));
            }
            let count = self.r_count_by_id.entry(id).or_default();
            *count += 1;
            let count = *count;
            if high(&rlast) {
                if let Some(exp) = self.r_expect_by_id.get_mut(&id).and_then(|q| q.pop_front())
                    && count != exp
                {
                    fail_at(
                        ctx,
                        format!("AXI4 R id {id}: RLAST after {count} beats, expected {exp}"),
                    );
                }
                if let Some(start) = self.r_cycles_by_id.get_mut(&id).and_then(|q| q.pop_front()) {
                    self.read_lat.record(now - start);
                }
                let excl = self
                    .r_excl_by_id
                    .get_mut(&id)
                    .and_then(|q| q.pop_front())
                    .unwrap_or(false);
                if rresp_code == resp::EXOKAY {
                    if excl {
                        self.exclusive_ok += 1;
                    } else {
                        fail_at(
                            ctx,
                            format!("AXI4 R id {id}: EXOKAY on a non-exclusive read"),
                        );
                    }
                }
                self.reads += 1;
                self.r_count_by_id.insert(id, 0);
            }
        }
        if high(&bvalid) && high(&bready) {
            self.note_resp(bresp_code);
            let id = bid.as_u64().unwrap_or(0);
            match self.w_cycles_by_id.get_mut(&id).and_then(|q| q.pop_front()) {
                Some(start) => self.write_lat.record(now - start),
                None => fail_at(ctx, format!("AXI4 B: BID {id} has no outstanding write")),
            }
            let excl = self
                .w_excl_by_id
                .get_mut(&id)
                .and_then(|q| q.pop_front())
                .unwrap_or(false);
            if bresp_code == resp::EXOKAY {
                if excl {
                    self.exclusive_ok += 1;
                } else {
                    fail_at(
                        ctx,
                        format!("AXI4 B: EXOKAY on a non-exclusive write (id {id})"),
                    );
                }
            }
            self.writes += 1;
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
        checker_sim_addr(32)
    }

    fn checker_sim_addr(addr_w: u32) -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .input("axi.awvalid", 1)
            .input("axi.awready", 1)
            .input("axi.awaddr", addr_w)
            .input("axi.awlen", 8)
            .input("axi.awsize", 3)
            .input("axi.awburst", 2)
            .input("axi.awid", 4)
            .input("axi.awlock", 1)
            .input("axi.wvalid", 1)
            .input("axi.wready", 1)
            .input("axi.wdata", 32)
            .input("axi.wstrb", 4)
            .input("axi.wlast", 1)
            .input("axi.bvalid", 1)
            .input("axi.bready", 1)
            .input("axi.bresp", 2)
            .input("axi.bid", 4)
            .input("axi.arvalid", 1)
            .input("axi.arready", 1)
            .input("axi.araddr", addr_w)
            .input("axi.arlen", 8)
            .input("axi.arsize", 3)
            .input("axi.arburst", 2)
            .input("axi.arid", 4)
            .input("axi.arlock", 1)
            .input("axi.rvalid", 1)
            .input("axi.rready", 1)
            .input("axi.rdata", 32)
            .input("axi.rresp", 2)
            .input("axi.rid", 4)
            .input("axi.rlast", 1)
    }

    /// Accepts an AW address phase in one cycle (len beats, INCR, size 4B).
    fn aw(sim: &mut MockSim, c: &mut Axi4Checker, addr: u64, len: u64, kind: u64) {
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awready", 1u64);
        sim.set("axi.awaddr", addr);
        sim.set("axi.awlen", len);
        sim.set("axi.awsize", 2u64); // 4 bytes
        sim.set("axi.awburst", kind);
        sim.clock(c).unwrap();
        sim.set("axi.awvalid", 0u64);
        sim.set("axi.awready", 0u64);
    }

    fn w_beat(sim: &mut MockSim, c: &mut Axi4Checker, last: bool) {
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wready", 1u64);
        sim.set("axi.wlast", u64::from(last));
        sim.clock(c).unwrap();
        sim.set("axi.wvalid", 0u64);
        sim.set("axi.wready", 0u64);
    }

    #[test]
    fn legal_two_beat_write_passes() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 1, 1); // 2-beat INCR burst
        w_beat(&mut sim, &mut c, false);
        w_beat(&mut sim, &mut c, true);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn wlast_misaligned_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 1, 1); // expects 2 beats
        w_beat(&mut sim, &mut c, true); // WLAST on the first beat
        assert!(sim.failures().iter().any(|f| f.contains("WLAST")));
    }

    #[test]
    fn burst_crossing_4kb_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        // Start near the top of a page with a long INCR burst.
        aw(&mut sim, &mut c, 0xff0, 15, 1);
        assert!(sim.failures().iter().any(|f| f.contains("4 KiB")));
    }

    #[test]
    fn reserved_burst_type_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 0, 3); // 3 is reserved
        assert!(sim.failures().iter().any(|f| f.contains("reserved")));
    }

    #[test]
    fn wrap_non_power_of_two_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 2, 2); // WRAP, 3 beats
        assert!(sim.failures().iter().any(|f| f.contains("WRAP length")));
    }

    #[test]
    fn fixed_over_16_beats_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 16, 0); // FIXED, 17 beats
        assert!(sim.failures().iter().any(|f| f.contains("exceeds 16")));
    }

    #[test]
    fn bid_mismatch_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awid", 5u64);
        aw(&mut sim, &mut c, 0x40, 0, 1); // 1-beat INCR, ID 5
        w_beat(&mut sim, &mut c, true);
        sim.set("axi.bvalid", 1u64);
        sim.set("axi.bready", 1u64);
        sim.set("axi.bid", 7u64); // wrong ID
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("BID")));
    }

    /// Accepts an AW address phase with `AWLOCK` asserted (exclusive).
    fn aw_excl(sim: &mut MockSim, c: &mut Axi4Checker, addr: u64, len: u64) {
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awready", 1u64);
        sim.set("axi.awaddr", addr);
        sim.set("axi.awlen", len);
        sim.set("axi.awsize", 2u64);
        sim.set("axi.awburst", 1u64);
        sim.set("axi.awlock", 1u64);
        sim.clock(c).unwrap();
        sim.set("axi.awvalid", 0u64);
        sim.set("axi.awready", 0u64);
        sim.set("axi.awlock", 0u64);
    }

    /// Drives a single B response with the given ID and response code.
    fn b_resp(sim: &mut MockSim, c: &mut Axi4Checker, id: u64, code: u64) {
        sim.set("axi.bvalid", 1u64);
        sim.set("axi.bready", 1u64);
        sim.set("axi.bid", id);
        sim.set("axi.bresp", code);
        sim.clock(c).unwrap();
        sim.set("axi.bvalid", 0u64);
        sim.set("axi.bready", 0u64);
    }

    #[test]
    fn exclusive_write_with_exokay_passes() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw_excl(&mut sim, &mut c, 0x40, 0); // 1-beat exclusive, aligned
        w_beat(&mut sim, &mut c, true);
        b_resp(&mut sim, &mut c, 0, resp::EXOKAY);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn exokay_on_non_exclusive_write_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 0, 1); // normal 1-beat write
        w_beat(&mut sim, &mut c, true);
        b_resp(&mut sim, &mut c, 0, resp::EXOKAY); // illegal EXOKAY
        assert!(sim.failures().iter().any(|f| f.contains("non-exclusive")));
    }

    #[test]
    fn exclusive_unaligned_address_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw_excl(&mut sim, &mut c, 0x42, 0); // 4-byte access not 4-aligned
        assert!(sim.failures().iter().any(|f| f.contains("not aligned")));
    }

    #[test]
    fn coverage_is_reported() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 1, 1);
        w_beat(&mut sim, &mut c, false);
        w_beat(&mut sim, &mut c, true);
        sim.finish(&mut c).unwrap();
        let summary = sim.logs().join("\n");
        assert!(summary.contains("2 beat(s)"), "{summary}");
        assert!(summary.contains("incr=1"), "{summary}");
        assert!(summary.contains("max len=1"), "{summary}");
    }

    // --- AMBA compliance: directed rule tests ---

    #[test]
    fn directed_legal_wrap_passes() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 3, 2); // WRAP, 4 beats, size-aligned
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn directed_legal_fixed_passes() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 1, 0); // FIXED, 2 beats
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn directed_size_exceeds_bus_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awready", 1u64);
        sim.set("axi.awaddr", 0x40u64);
        sim.set("axi.awlen", 0u64);
        sim.set("axi.awsize", 3u64); // 8 bytes on a 4-byte bus
        sim.set("axi.awburst", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("exceeds bus width"))
        );
    }

    #[test]
    fn directed_valid_high_during_reset_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 1u64);
        sim.set("axi.awvalid", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("must be low during reset"))
        );
    }

    #[test]
    fn directed_read_id_without_outstanding_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.rvalid", 1u64);
        sim.set("axi.rready", 1u64);
        sim.set("axi.rid", 5u64);
        sim.set("axi.rlast", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("RID 5 has no outstanding read"))
        );
    }

    #[test]
    fn directed_exclusive_read_exokay_passes() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        // Exclusive read (ARLOCK) answered with EXOKAY is legal.
        sim.set("axi.arvalid", 1u64);
        sim.set("axi.arready", 1u64);
        sim.set("axi.araddr", 0x40u64);
        sim.set("axi.arlen", 0u64);
        sim.set("axi.arsize", 2u64);
        sim.set("axi.arburst", 1u64);
        sim.set("axi.arlock", 1u64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.arvalid", 0u64);
        sim.set("axi.arlock", 0u64);
        sim.set("axi.rvalid", 1u64);
        sim.set("axi.rready", 1u64);
        sim.set("axi.rid", 0u64);
        sim.set("axi.rresp", resp::EXOKAY);
        sim.set("axi.rlast", 1u64);
        sim.clock(&mut c).unwrap();
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
        sim.finish(&mut c).unwrap();
        // The legal exclusive read's EXOKAY is tallied in the coverage summary.
        assert!(
            sim.logs().join("\n").contains("exclusive=1 (EXOKAY=1)"),
            "{}",
            sim.logs().join("\n")
        );
    }

    #[test]
    fn directed_lock_x_while_valid_fails() {
        let mut sim = checker_sim().four_state(true);
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x40u64);
        sim.set("axi.awlock", x_bit(1));
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("X/Z while VALID")));
    }

    #[test]
    fn directed_lock_unstable_while_stalled_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        // AW stalls (VALID high, READY low) with LOCK asserted...
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x40u64);
        sim.set("axi.awlock", 1u64);
        sim.clock(&mut c).unwrap();
        // ...then LOCK changes while still stalled — a stability violation.
        sim.set("axi.awlock", 0u64);
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("payload changed")));
    }

    #[test]
    fn address_wider_than_64_bits_is_rejected() {
        let mut sim = checker_sim_addr(96);
        let err = sim.build::<Axi4Checker>().err().unwrap();
        assert!(err.to_string().contains("64-bit address limit"), "{err}");
    }

    #[test]
    fn directed_stall_beyond_timeout_fails() {
        let mut sim = checker_sim().param("TIMEOUT", 4u64);
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x40u64);
        sim.set("axi.awburst", 1u64);
        for _ in 0..8 {
            sim.clock(&mut c).unwrap();
        }
        assert!(sim.failures().iter().any(|f| f.contains("timeout")));
    }

    #[test]
    fn directed_valid_dropped_before_ready_fails() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x40u64);
        sim.clock(&mut c).unwrap();
        sim.set("axi.awvalid", 0u64); // dropped before AWREADY
        sim.clock(&mut c).unwrap();
        assert!(
            sim.failures()
                .iter()
                .any(|f| f.contains("AW") && f.contains("VALID deasserted"))
        );
    }

    /// A `width`-bit value whose bit 0 is driven X (unknown).
    fn x_bit(width: u32) -> Value {
        Value::from_bits([0].into_iter().collect(), [1].into_iter().collect(), width)
    }

    #[test]
    fn directed_payload_x_while_valid_fails() {
        let mut sim = checker_sim().four_state(true);
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", x_bit(32));
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("X/Z while VALID")));
    }

    #[test]
    fn directed_control_line_x_fails() {
        let mut sim = checker_sim().four_state(true);
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", x_bit(1));
        sim.clock(&mut c).unwrap();
        assert!(sim.failures().iter().any(|f| f.contains("AWVALID is X/Z")));
    }

    #[test]
    fn directed_slverr_is_accepted_and_tallied() {
        let mut sim = checker_sim();
        let mut c = sim.build::<Axi4Checker>().unwrap();
        sim.set("rst", 0u64);
        aw(&mut sim, &mut c, 0x40, 0, 1); // 1-beat write, ID 0
        w_beat(&mut sim, &mut c, true);
        b_resp(&mut sim, &mut c, 0, resp::SLVERR); // a legal error response
        assert!(!sim.failed(), "SLVERR is legal: {:?}", sim.failures());
        sim.finish(&mut c).unwrap();
        assert!(sim.logs().join("\n").contains("slverr=1"));
    }
}
