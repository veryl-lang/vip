//! Burst-aware AXI4 golden memory (slave) with multiple outstanding
//! transactions and interleaved (out-of-order) read responses.

use super::beat_addr;
use crate::common::{arg_words, data_value, mask_words, resp, stall_now, words_for};
use std::collections::{HashMap, HashSet};
use veryl_component::*;

/// An accepted burst awaiting or emitting data.
#[derive(Clone, Default)]
struct Burst {
    addr: u64,
    len: u64,
    size: u64,
    kind: u64,
    id: u64,
    lock: u64,
    beat: u64,
}

#[derive(VerylInterface)]
#[interface(path = "$std::axi4_if", modport = "slave")]
pub struct Axi4SlavePorts {
    awvalid: InputPort,
    awready: OutputPort,
    awaddr: InputPort,
    awlen: InputPort,
    awsize: InputPort,
    awburst: InputPort,
    awid: InputPort,
    awlock: InputPort,
    wvalid: InputPort,
    wready: OutputPort,
    wdata: InputPort,
    wstrb: InputPort,
    wlast: InputPort,
    bvalid: OutputPort,
    bready: InputPort,
    bresp: OutputPort,
    bid: OutputPort,
    arvalid: InputPort,
    arready: OutputPort,
    araddr: InputPort,
    arlen: InputPort,
    arsize: InputPort,
    arburst: InputPort,
    arid: InputPort,
    arlock: InputPort,
    rvalid: OutputPort,
    rready: InputPort,
    rdata: OutputPort,
    rresp: OutputPort,
    rid: OutputPort,
    rlast: OutputPort,
}

/// Burst-aware AXI4 slave memory. Connect to the `slave` modport. It accepts
/// INCR / FIXED / WRAP bursts, applies byte strobes per beat and echoes the
/// transaction `ID`. Up to `MAX_OUTSTANDING` reads run concurrently and their
/// beats are **interleaved** (out-of-order), so it stresses a master's
/// reorder handling. It implements an exclusive-access monitor: an exclusive
/// read (`ARLOCK`) reserves its address, an exclusive write (`AWLOCK`) to a
/// still-reserved address succeeds with `EXOKAY`, and any intervening normal
/// write clears the reservation so the exclusive write fails with `OKAY` and
/// leaves memory untouched. Accesses past `SIZE` answer `DECERR` and `set_resp`
/// injects a per-address `SLVERR`/`DECERR`; errored writes leave memory
/// untouched. `STALL` backpressures the ready lines.
#[derive(Component)]
#[component(kind = clocked)]
pub struct Axi4Ram {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; clears in-flight bursts but keeps memory.
    rst: ResetPort,

    /// The AXI4 bus, answered as a slave.
    #[interface]
    axi: Axi4SlavePorts,

    /// 0..=255 weight for randomly dropping the ready outputs.
    #[param(name = "STALL")]
    stall: Option<u64>,
    /// Concurrent reads (and buffered write responses); unset means 4.
    #[param(name = "MAX_OUTSTANDING")]
    max_outstanding: Option<u64>,
    /// Memory size in bytes; accesses at or above it answer DECERR. Unset
    /// means unbounded.
    #[param(name = "SIZE")]
    size_limit: Option<u64>,

    mem: HashMap<u64, Vec<u64>>,
    lfsr: u64,

    // Injected error responses, keyed by aligned address (SLVERR / DECERR).
    err: HashMap<u64, u64>,

    // Exclusive-access monitor: aligned addresses reserved by exclusive reads.
    reserved: HashSet<u64>,

    // Write side: one burst accepting W data, plus queued write responses
    // (each carries its own BRESP, since exclusive writes may report EXOKAY).
    w_cur: Option<Burst>,
    w_resp: u64,
    w_commit: bool,
    b_queue: std::collections::VecDeque<(u64, u64)>,
    aw_ready: bool,
    w_ready: bool,
    b_valid: bool,

    // Read side: concurrent reads, whose beats are round-robin interleaved.
    reads: std::collections::VecDeque<Burst>,
    ar_ready: bool,
    r_valid: bool,
    r_data: Vec<u64>,
    r_id: u64,
    r_resp: u64,
    r_last: bool,
}

impl Axi4Ram {
    fn data_bytes(&self) -> u64 {
        (self.axi.wdata.width() as u64 / 8).max(1)
    }

    fn data_words(&self) -> usize {
        words_for(self.axi.wdata.width())
    }

    fn max(&self) -> usize {
        self.max_outstanding.unwrap_or(4) as usize
    }

    fn align(&self, addr: u64) -> u64 {
        addr & !(self.data_bytes() - 1)
    }

    fn read_mem(&self, addr: u64) -> Vec<u64> {
        self.mem
            .get(&self.align(addr))
            .cloned()
            .unwrap_or_else(|| vec![0u64; self.data_words()])
    }

    /// Response for `addr`: DECERR past `SIZE`, else any injected error, else
    /// OKAY.
    fn resp_for(&self, addr: u64) -> u64 {
        let a = self.align(addr);
        if self.size_limit.is_some_and(|s| a >= s) {
            return resp::DECERR;
        }
        self.err.get(&a).copied().unwrap_or(resp::OKAY)
    }

    fn write_mem(&mut self, addr: u64, data: &[u64], strb: &[u64]) {
        let key = self.align(addr);
        let mut word = self
            .mem
            .get(&key)
            .cloned()
            .unwrap_or_else(|| vec![0u64; self.data_words()]);
        for byte in 0..self.data_bytes() as usize {
            if (strb[byte / 64] >> (byte % 64)) & 1 != 0 {
                let dword = byte / 8;
                let mask = 0xffu64 << ((byte % 8) * 8);
                word[dword] = (word[dword] & !mask) | (data[dword] & mask);
            }
        }
        self.mem.insert(key, word);
    }

    #[allow(clippy::too_many_arguments)]
    fn capture(
        &mut self,
        ctx: &mut SimCtx,
        addr: InputPort,
        len: InputPort,
        size: InputPort,
        burst: InputPort,
        id: InputPort,
        lock: InputPort,
    ) -> Burst {
        Burst {
            addr: ctx.read_u64(addr),
            len: ctx.read_u64(len),
            size: 1 << ctx.read_u64(size),
            kind: ctx.read_u64(burst),
            id: ctx.read_u64(id),
            lock: ctx.read_u64(lock),
            beat: 0,
        }
    }
}

#[component_impl]
impl Axi4Ram {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        // Addresses are read as u64; a wider address bus would be silently
        // truncated.
        for (name, w) in [
            ("awaddr", self.axi.awaddr.width()),
            ("araddr", self.axi.araddr.width()),
        ] {
            if w > 64 {
                bail!("axi4_ram: {name} width {w} exceeds the 64-bit address limit");
            }
        }
        self.lfsr = ctx.seed() | 1;
        self.r_data = vec![0; self.data_words()];
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            self.w_cur = None;
            self.reserved.clear();
            self.b_queue.clear();
            self.reads.clear();
            self.aw_ready = false;
            self.w_ready = false;
            self.b_valid = false;
            self.ar_ready = false;
            self.r_valid = false;
            for p in [
                self.axi.awready,
                self.axi.wready,
                self.axi.bvalid,
                self.axi.arready,
                self.axi.rvalid,
            ] {
                ctx.write(p, false);
            }
            return Ok(());
        }
        let stall = stall_now(&mut self.lfsr, self.stall);
        let max = self.max();
        let aw_r = self.aw_ready;
        let w_r = self.w_ready;
        let b_v = self.b_valid;
        let ar_r = self.ar_ready;
        let r_v = self.r_valid;

        // --- write engine ---
        if ctx.read(self.axi.awvalid).as_bool() && aw_r {
            let req = self.capture(
                ctx,
                self.axi.awaddr,
                self.axi.awlen,
                self.axi.awsize,
                self.axi.awburst,
                self.axi.awid,
                self.axi.awlock,
            );
            // Resolve exclusivity up front: exclusive writes commit only if the
            // address is still reserved; normal writes clear any reservation.
            let base = self.align(req.addr);
            if req.lock != 0 {
                self.w_commit = self.reserved.remove(&base);
                self.w_resp = if self.w_commit {
                    resp::EXOKAY
                } else {
                    resp::OKAY
                };
            } else {
                self.reserved.remove(&base);
                self.w_commit = true;
                self.w_resp = resp::OKAY;
            }
            self.w_cur = Some(req);
        }
        if ctx.read(self.axi.wvalid).as_bool()
            && w_r
            && let Some(mut req) = self.w_cur.take()
        {
            let addr = beat_addr(req.addr, req.size, req.kind, req.len, req.beat);
            let mut data = vec![0u64; self.data_words()];
            ctx.read_words(self.axi.wdata, &mut data);
            let mut strb = vec![0u64; words_for(self.data_bytes() as u32)];
            ctx.read_words(self.axi.wstrb, &mut strb);
            // An errored beat does not modify memory; the burst response is
            // the worst code across its beats (error dominates EXOKAY).
            let err = self.resp_for(addr);
            if self.w_commit && err == resp::OKAY {
                self.write_mem(addr, &data, &strb);
            }
            self.w_resp = self.w_resp.max(err);
            req.beat += 1;
            if ctx.read(self.axi.wlast).as_bool() {
                self.b_queue.push_back((req.id, self.w_resp));
            } else {
                self.w_cur = Some(req);
            }
        }
        if ctx.read(self.axi.bready).as_bool() && b_v {
            self.b_queue.pop_front();
        }
        self.aw_ready = self.w_cur.is_none() && self.b_queue.len() < max && !stall;
        self.w_ready = self.w_cur.is_some() && !stall;
        self.b_valid = !self.b_queue.is_empty();
        let (b_id, b_resp) = self.b_queue.front().copied().unwrap_or((0, resp::OKAY));

        // --- read engine (interleaved) ---
        if ctx.read(self.axi.arvalid).as_bool() && ar_r {
            let req = self.capture(
                ctx,
                self.axi.araddr,
                self.axi.arlen,
                self.axi.arsize,
                self.axi.arburst,
                self.axi.arid,
                self.axi.arlock,
            );
            if req.lock != 0 {
                self.reserved.insert(self.align(req.addr));
            }
            self.reads.push_back(req);
        }
        if r_v
            && ctx.read(self.axi.rready).as_bool()
            && let Some(req) = self.reads.front_mut()
        {
            req.beat += 1;
            if req.beat > req.len {
                self.reads.pop_front();
            } else {
                // Move to the back so the next cycle serves another read.
                self.reads.rotate_left(1);
            }
        }
        self.ar_ready = self.reads.len() < max && !stall;
        self.r_valid = !self.reads.is_empty();
        if let Some(req) = self.reads.front() {
            let addr = beat_addr(req.addr, req.size, req.kind, req.len, req.beat);
            let (id, lock, last) = (req.id, req.lock, req.beat == req.len);
            self.r_data = self.read_mem(addr);
            self.r_id = id;
            // An error dominates; otherwise an exclusive read reports EXOKAY.
            let err = self.resp_for(addr);
            self.r_resp = if err != resp::OKAY {
                err
            } else if lock != 0 {
                resp::EXOKAY
            } else {
                resp::OKAY
            };
            self.r_last = last;
        }

        // Drive outputs.
        ctx.write(self.axi.awready, self.aw_ready);
        ctx.write(self.axi.wready, self.w_ready);
        ctx.write(self.axi.bvalid, self.b_valid);
        ctx.write(self.axi.bresp, b_resp);
        ctx.write(self.axi.bid, b_id);
        ctx.write(self.axi.arready, self.ar_ready);
        ctx.write(self.axi.rvalid, self.r_valid);
        ctx.write_words(self.axi.rdata, &self.r_data);
        ctx.write(self.axi.rresp, self.r_resp);
        ctx.write(self.axi.rid, self.r_id);
        ctx.write(self.axi.rlast, self.r_valid && self.r_last);
        Ok(())
    }

    /// Backdoor write of one aligned word at full bus width.
    fn poke(&mut self, _ctx: &mut SimCtx, addr: u64, data: &Value) -> Result<()> {
        let key = self.align(addr);
        let words = arg_words(data, self.axi.wdata.width(), "poke data")?;
        self.mem.insert(key, words);
        Ok(())
    }

    /// Backdoor read of one aligned word at full bus width.
    #[ret_width(axi.DATA_WIDTH_BYTES * 8)]
    fn peek(&mut self, _ctx: &mut SimCtx, addr: u64) -> Result<Value> {
        let width = self.axi.wdata.width();
        Ok(data_value(self.read_mem(addr), width))
    }

    /// Makes accesses to `addr` answer `code` (0 OKAY, 2 SLVERR, 3 DECERR);
    /// OKAY clears any injected error. Errored writes do not modify memory.
    fn set_resp(&mut self, _ctx: &mut SimCtx, addr: u64, code: u64) -> Result<()> {
        let key = self.align(addr);
        if code == resp::OKAY {
            self.err.remove(&key);
        } else {
            self.err.insert(key, code);
        }
        Ok(())
    }

    /// Backdoor fill: sets `count` consecutive words starting at `base` to
    /// their own address, so a master can predict read data without writing.
    fn fill(&mut self, _ctx: &mut SimCtx, base: u64, count: u64) -> Result<()> {
        let bytes = self.data_bytes();
        for n in 0..count {
            let addr = self.align(base) + n * bytes;
            let mut words = vec![0u64; self.data_words()];
            words[0] = addr;
            mask_words(&mut words, self.axi.wdata.width());
            self.mem.insert(addr, words);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veryl_component::testing::MockSim;

    fn ram_sim() -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .input("axi.awvalid", 1)
            .output("axi.awready", 1)
            .input("axi.awaddr", 32)
            .input("axi.awlen", 8)
            .input("axi.awsize", 3)
            .input("axi.awburst", 2)
            .input("axi.awid", 4)
            .input("axi.awlock", 1)
            .input("axi.wvalid", 1)
            .output("axi.wready", 1)
            .input("axi.wdata", 32)
            .input("axi.wstrb", 4)
            .input("axi.wlast", 1)
            .output("axi.bvalid", 1)
            .input("axi.bready", 1)
            .output("axi.bresp", 2)
            .output("axi.bid", 4)
            .input("axi.arvalid", 1)
            .output("axi.arready", 1)
            .input("axi.araddr", 32)
            .input("axi.arlen", 8)
            .input("axi.arsize", 3)
            .input("axi.arburst", 2)
            .input("axi.arid", 4)
            .input("axi.arlock", 1)
            .output("axi.rvalid", 1)
            .input("axi.rready", 1)
            .output("axi.rdata", 32)
            .output("axi.rresp", 2)
            .output("axi.rid", 4)
            .output("axi.rlast", 1)
    }

    #[test]
    fn backdoor_poke_peek_fill() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4Ram>().unwrap();
        sim.call(&mut c, "poke", &[0x40u64.into(), 0x1234u64.into()])
            .unwrap();
        assert_eq!(
            sim.call(&mut c, "peek", &[0x40u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0x1234
        );
        sim.call(&mut c, "fill", &[0x0u64.into(), 4u64.into()])
            .unwrap();
        assert_eq!(
            sim.call(&mut c, "peek", &[0x8u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0x8
        );
    }

    /// Drives a single-beat exclusive read of `addr`, arming the monitor.
    fn excl_read(sim: &mut MockSim, c: &mut Axi4Ram, addr: u64) {
        sim.set("axi.araddr", addr);
        sim.set("axi.arvalid", 1u64);
        sim.set("axi.arlock", 1u64);
        sim.set("axi.rready", 1u64);
        let mut ar_done = false;
        for _ in 0..20 {
            let ar_hs = !ar_done && sim.get("axi.arready").as_u64().unwrap() == 1;
            let r_hs = sim.get("axi.rvalid").as_u64().unwrap() == 1;
            sim.clock(c).unwrap();
            if ar_hs {
                ar_done = true;
                sim.set("axi.arvalid", 0u64);
            }
            if r_hs {
                break;
            }
        }
    }

    /// Drives a single-beat exclusive write of `data` to `addr` and returns the
    /// captured `BRESP` (1 = EXOKAY on success, 0 = OKAY on failure).
    fn excl_write(sim: &mut MockSim, c: &mut Axi4Ram, addr: u64, data: u64) -> u64 {
        sim.set("axi.awaddr", addr);
        sim.set("axi.awlen", 0u64);
        sim.set("axi.awsize", 2u64);
        sim.set("axi.awburst", 1u64);
        sim.set("axi.awid", 3u64);
        sim.set("axi.awlock", 1u64);
        sim.set("axi.wstrb", 0xfu64);
        sim.set("axi.wlast", 1u64);
        sim.set("axi.wdata", data);
        sim.set("axi.bready", 1u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.wvalid", 1u64);
        let mut aw_done = false;
        let mut w_done = false;
        let mut bresp = 0;
        for _ in 0..20 {
            let aw_hs = !aw_done && sim.get("axi.awready").as_u64().unwrap() == 1;
            let w_hs = !w_done && sim.get("axi.wready").as_u64().unwrap() == 1;
            sim.clock(c).unwrap();
            if aw_hs {
                aw_done = true;
                sim.set("axi.awvalid", 0u64);
            }
            if w_hs {
                w_done = true;
                sim.set("axi.wvalid", 0u64);
            }
            if sim.get("axi.bvalid").as_u64().unwrap() == 1 {
                bresp = sim.get("axi.bresp").as_u64().unwrap();
                break;
            }
        }
        bresp
    }

    #[test]
    fn exclusive_write_succeeds_then_fails_after_intervening_write() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4Ram>().unwrap();
        sim.set("rst", 0u64);

        // Reserve 0x40, then an exclusive write to it succeeds with EXOKAY.
        excl_read(&mut sim, &mut c, 0x40);
        assert_eq!(excl_write(&mut sim, &mut c, 0x40, 0xcafe), resp::EXOKAY);
        assert_eq!(
            sim.call(&mut c, "peek", &[0x40u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0xcafe
        );

        // The successful write cleared the reservation, so a second exclusive
        // write with no fresh read fails with OKAY and leaves memory untouched.
        assert_eq!(excl_write(&mut sim, &mut c, 0x40, 0xdead), resp::OKAY);
        assert_eq!(
            sim.call(&mut c, "peek", &[0x40u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0xcafe
        );
    }

    #[test]
    fn incr_burst_write_lands_in_memory() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4Ram>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awaddr", 0x40u64);
        sim.set("axi.awlen", 1u64);
        sim.set("axi.awsize", 2u64);
        sim.set("axi.awburst", 1u64);
        sim.set("axi.awid", 7u64);
        sim.set("axi.wstrb", 0xfu64);
        sim.set("axi.bready", 1u64);
        let mut aw_done = false;
        let mut beat = 0u64;
        for _ in 0..40 {
            sim.set("axi.awvalid", u64::from(!aw_done));
            if beat < 2 {
                sim.set("axi.wvalid", 1u64);
                sim.set("axi.wdata", if beat == 0 { 0xaaaa } else { 0xbbbb });
                sim.set("axi.wlast", u64::from(beat == 1));
            } else {
                sim.set("axi.wvalid", 0u64);
            }
            let aw_hs = !aw_done && sim.get("axi.awready").as_u64().unwrap() == 1;
            let w_hs = beat < 2 && sim.get("axi.wready").as_u64().unwrap() == 1;
            sim.clock(&mut c).unwrap();
            if aw_hs {
                aw_done = true;
            }
            if w_hs {
                beat += 1;
            }
            if sim.get("axi.bvalid").as_u64().unwrap() == 1 {
                break;
            }
        }
        assert_eq!(
            sim.call(&mut c, "peek", &[0x40u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0xaaaa
        );
        assert_eq!(
            sim.call(&mut c, "peek", &[0x44u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0xbbbb
        );
    }

    /// Drives a single-beat normal write and returns the captured BRESP.
    fn write1(sim: &mut MockSim, c: &mut Axi4Ram, addr: u64, data: u64) -> u64 {
        sim.set("axi.awaddr", addr);
        sim.set("axi.awlen", 0u64);
        sim.set("axi.awsize", 2u64);
        sim.set("axi.awburst", 1u64);
        sim.set("axi.awid", 1u64);
        sim.set("axi.awlock", 0u64);
        sim.set("axi.wstrb", 0xfu64);
        sim.set("axi.wlast", 1u64);
        sim.set("axi.wdata", data);
        sim.set("axi.bready", 1u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.wvalid", 1u64);
        let mut aw_done = false;
        let mut w_done = false;
        let mut bresp = 0;
        for _ in 0..20 {
            let aw_hs = !aw_done && sim.get("axi.awready").as_u64().unwrap() == 1;
            let w_hs = !w_done && sim.get("axi.wready").as_u64().unwrap() == 1;
            sim.clock(c).unwrap();
            if aw_hs {
                aw_done = true;
                sim.set("axi.awvalid", 0u64);
            }
            if w_hs {
                w_done = true;
                sim.set("axi.wvalid", 0u64);
            }
            if sim.get("axi.bvalid").as_u64().unwrap() == 1 {
                bresp = sim.get("axi.bresp").as_u64().unwrap();
                break;
            }
        }
        bresp
    }

    /// Drives a single-beat read and returns the captured RRESP.
    fn read1(sim: &mut MockSim, c: &mut Axi4Ram, addr: u64) -> u64 {
        sim.set("axi.araddr", addr);
        sim.set("axi.arlen", 0u64);
        sim.set("axi.arsize", 2u64);
        sim.set("axi.arburst", 1u64);
        sim.set("axi.arid", 1u64);
        sim.set("axi.arlock", 0u64);
        sim.set("axi.rready", 1u64);
        sim.set("axi.arvalid", 1u64);
        let mut ar_done = false;
        let mut rresp = 0;
        for _ in 0..20 {
            let ar_hs = !ar_done && sim.get("axi.arready").as_u64().unwrap() == 1;
            let r_hs = sim.get("axi.rvalid").as_u64().unwrap() == 1;
            sim.clock(c).unwrap();
            if ar_hs {
                ar_done = true;
                sim.set("axi.arvalid", 0u64);
            }
            if r_hs {
                rresp = sim.get("axi.rresp").as_u64().unwrap();
                break;
            }
        }
        rresp
    }

    #[test]
    fn injected_slverr_write_does_not_land() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4Ram>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "set_resp", &[0x40u64.into(), resp::SLVERR.into()])
            .unwrap();
        assert_eq!(write1(&mut sim, &mut c, 0x40, 0xbad), resp::SLVERR);
        assert_eq!(
            sim.call(&mut c, "peek", &[0x40u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0 // an errored write leaves memory untouched
        );
    }

    #[test]
    fn decerr_past_size() {
        let mut sim = ram_sim().param("SIZE", 0x100u64);
        let mut c = sim.build::<Axi4Ram>().unwrap();
        sim.set("rst", 0u64);
        assert_eq!(read1(&mut sim, &mut c, 0x200), resp::DECERR);
        assert_eq!(write1(&mut sim, &mut c, 0x200, 0x1), resp::DECERR);
    }
}
