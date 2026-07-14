//! Active AXI4-Lite master bus-functional model.

use crate::common::{
    arg_words, data_value, fail_at, mask_words, next_rand, resp, stall_now, words_for,
};
use std::collections::{HashMap, HashSet, VecDeque};
use veryl_component::*;

/// A queued transaction, kept in a single program-ordered queue so that
/// same-address ordering can be enforced across the read and write channels.
/// Data and strobes are LSB-first word vectors so any bus width works.
enum Op {
    Write {
        addr: u64,
        data: Vec<u64>,
        strb: Vec<u64>,
        expect_ok: bool,
    },
    Read(ReadMeta),
}

impl Op {
    fn addr(&self) -> u64 {
        match self {
            Op::Write { addr, .. } => *addr,
            Op::Read(r) => r.addr,
        }
    }
}

/// A read in flight or queued: an optional expected value (self-check) and an
/// optional read-modify-write `(mask, value)` to apply on completion.
#[derive(Clone, Default)]
struct ReadMeta {
    addr: u64,
    expect: Option<Vec<u64>>,
    rmw: Option<(Vec<u64>, Vec<u64>)>,
}

/// Active AXI4-Lite master. Connect to the `master` modport. Testbench
/// methods enqueue transactions in zero time; the clocked FSM drives them
/// onto the bus, pipelining up to `MAX_OUTSTANDING` responses per
/// direction. Advance the clock (`clk.next(n)`) to let queued work run,
/// then drain read data with `pop_read`.
///
/// ```veryl
/// mst.write(0x10, 0xdead);
/// mst.read(0x10);
/// clk.next(20);
/// assert(mst.pop_read() == 0xdead);
/// ```
///
#[derive(VerylInterface)]
#[interface(path = "$std::axi4_lite_if", modport = "master")]
pub struct Axi4LiteMasterPorts {
    awvalid: OutputPort,
    awready: InputPort,
    awaddr: OutputPort,
    awprot: OutputPort,
    wvalid: OutputPort,
    wready: InputPort,
    wdata: OutputPort,
    wstrb: OutputPort,
    bvalid: InputPort,
    bready: OutputPort,
    bresp: InputPort,
    arvalid: OutputPort,
    arready: InputPort,
    araddr: OutputPort,
    arprot: OutputPort,
    rvalid: InputPort,
    rready: OutputPort,
    rdata: InputPort,
}

/// `expect_read`/`expect_write` turn the master into a self-checking
/// scoreboard: it compares the read data (or checks the write response)
/// itself and fails the test on a mismatch. The `STALL` parameter randomly
/// delays READY to stress the slave.
#[derive(Component)]
#[component(kind = clocked)]
pub struct Axi4LiteMaster {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; drops in-flight transactions and clears the queues.
    rst: ResetPort,

    /// The AXI4-Lite bus, driven as master.
    #[interface]
    axi: Axi4LiteMasterPorts,

    /// 0..=255 weight for randomly delaying BREADY/RREADY; unset never
    /// stalls.
    #[param(name = "STALL")]
    stall: Option<u64>,
    /// Maximum responses in flight per direction; unset means unbounded.
    #[param(name = "MAX_OUTSTANDING")]
    max_outstanding: Option<u64>,
    /// Cycles to hold WVALID back after AWVALID, to skew the write address
    /// and data channels and stress the slave. Unset asserts them together.
    #[param(name = "W_DELAY")]
    w_delay_param: Option<u64>,

    // Not-yet-issued transactions, in program order.
    ops: VecDeque<Op>,
    // Addresses with an in-flight transaction, to serialize same-address
    // accesses across the two channels (read-after-write / write-after-read).
    inflight: HashSet<u64>,
    // Issued transactions awaiting their response, in order.
    b_expect: VecDeque<(u64, bool)>,
    r_expect: VecDeque<ReadMeta>,
    reads: VecDeque<Vec<u64>>,
    last_bresp: u64,
    lfsr: u64,
    traffic_lfsr: u64,
    // Values written via `random_writes`, checked back by `verify_all`.
    shadow: HashMap<u64, Vec<u64>>,

    // Registered output shadows and the metadata of the write/read currently
    // being issued.
    aw_valid: bool,
    w_valid: bool,
    ar_valid: bool,
    b_ready: bool,
    r_ready: bool,
    aw_addr: u64,
    w_data: Vec<u64>,
    w_strb: Vec<u64>,
    ar_addr: u64,
    aw_acked: bool,
    w_acked: bool,
    cur_w: (u64, bool),
    cur_ar: ReadMeta,
    // Cycles left before WVALID follows AWVALID (the W_DELAY skew).
    w_delay: Option<u64>,
    // Waveform traces for the queue depth and outstanding count.
    tr_queued: Option<TraceVar>,
    tr_outstanding: Option<TraceVar>,
}

impl Axi4LiteMaster {
    fn data_words(&self) -> usize {
        words_for(self.axi.wdata.width())
    }

    fn data_bytes(&self) -> u32 {
        (self.axi.wdata.width() / 8).max(1)
    }

    fn strb_words(&self) -> usize {
        words_for(self.data_bytes())
    }

    /// An all-lanes-enabled strobe of the right width.
    fn full_strb(&self) -> Vec<u64> {
        let mut strb = vec![u64::MAX; self.strb_words()];
        mask_words(&mut strb, self.data_bytes());
        strb
    }

    /// A fresh full-width random data value.
    fn rand_data(&mut self) -> Vec<u64> {
        let mut data = vec![0u64; self.data_words()];
        for word in data.iter_mut() {
            *word = next_rand(&mut self.traffic_lfsr);
        }
        mask_words(&mut data, self.axi.wdata.width());
        data
    }

    fn max_outstanding(&self) -> u64 {
        self.max_outstanding.unwrap_or(u64::MAX)
    }

    /// Index of the next issuable op for the requested channel. Only the
    /// front-most queued op to each address is eligible, and only if that
    /// address has nothing in flight — so all accesses to one address keep
    /// program order across both channels (RAW / WAR hazards).
    fn next_op(&self, want_write: bool) -> Option<usize> {
        let mut blocked: HashSet<u64> = HashSet::new();
        for (idx, op) in self.ops.iter().enumerate() {
            let addr = op.addr();
            if self.inflight.contains(&addr) {
                blocked.insert(addr);
                continue;
            }
            if blocked.contains(&addr) {
                continue; // a program-earlier op to this address is still queued
            }
            if matches!(op, Op::Write { .. }) == want_write {
                return Some(idx);
            }
            // Front-most op to this address is on the other channel; it must
            // go first, so block later same-address ops here too.
            blocked.insert(addr);
        }
        None
    }

    fn reset_state(&mut self) {
        self.ops.clear();
        self.inflight.clear();
        self.b_expect.clear();
        self.r_expect.clear();
        self.reads.clear();
        self.shadow.clear();
        self.aw_valid = false;
        self.w_valid = false;
        self.ar_valid = false;
        self.b_ready = false;
        self.r_ready = false;
        self.aw_acked = false;
        self.w_acked = false;
        self.w_delay = None;
        self.w_data = vec![0; self.data_words()];
        self.w_strb = vec![0; self.strb_words()];
    }

    /// Merges a strobed value into the shadow copy, byte by byte, so it
    /// matches what a slave applies for partial-strobe writes.
    fn merge_shadow(&mut self, addr: u64, data: &[u64], strb: &[u64]) {
        let dbytes = self.data_bytes() as usize;
        let dwords = self.data_words();
        let word = self
            .shadow
            .entry(addr)
            .or_insert_with(|| vec![0u64; dwords]);
        for byte in 0..dbytes {
            if (strb[byte / 64] >> (byte % 64)) & 1 != 0 {
                let dword = byte / 8;
                let shift = (byte % 8) * 8;
                let mask = 0xffu64 << shift;
                word[dword] = (word[dword] & !mask) | (data[dword] & mask);
            }
        }
    }

    fn drive(&mut self, ctx: &mut SimCtx) {
        ctx.write(self.axi.awvalid, self.aw_valid);
        ctx.write(self.axi.awaddr, self.aw_addr);
        ctx.write(self.axi.awprot, 0u64);
        ctx.write(self.axi.wvalid, self.w_valid);
        ctx.write_words(self.axi.wdata, &self.w_data);
        ctx.write_words(self.axi.wstrb, &self.w_strb);
        ctx.write(self.axi.bready, self.b_ready);
        ctx.write(self.axi.arvalid, self.ar_valid);
        ctx.write(self.axi.araddr, self.ar_addr);
        ctx.write(self.axi.arprot, 0u64);
        ctx.write(self.axi.rready, self.r_ready);
    }
}

#[component_impl]
impl Axi4LiteMaster {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        // Addresses are driven from u64; a wider bus's high bits would be
        // silently dropped.
        for (name, w) in [
            ("awaddr", self.axi.awaddr.width()),
            ("araddr", self.axi.araddr.width()),
        ] {
            if w > 64 {
                bail!("axi4_lite_master: {name} width {w} exceeds the 64-bit address limit");
            }
        }
        let seed = ctx.seed();
        self.lfsr = seed | 1;
        self.traffic_lfsr = seed.rotate_left(32) | 1;
        self.w_data = vec![0; self.data_words()];
        self.w_strb = vec![0; self.strb_words()];
        self.tr_queued = ctx.trace_var("queued", 16).ok();
        self.tr_outstanding = ctx.trace_var("outstanding", 16).ok();
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            self.reset_state();
            self.drive(ctx);
            return Ok(());
        }
        let stall = stall_now(&mut self.lfsr, self.stall);
        let max = self.max_outstanding();

        // Outputs currently on the wire (committed last cycle).
        let aw_v = self.aw_valid;
        let w_v = self.w_valid;
        let ar_v = self.ar_valid;
        let b_r = self.b_ready;
        let r_r = self.r_ready;

        // Advance the W-after-AW skew from last cycle.
        if let Some(n) = self.w_delay {
            if n == 0 {
                self.w_valid = true;
                self.w_delay = None;
            } else {
                self.w_delay = Some(n - 1);
            }
        }

        // --- write engine ---
        if aw_v && ctx.read(self.axi.awready).as_bool() {
            self.aw_valid = false;
            self.aw_acked = true;
        }
        if w_v && ctx.read(self.axi.wready).as_bool() {
            self.w_valid = false;
            self.w_acked = true;
        }
        if self.aw_acked && self.w_acked {
            self.b_expect.push_back(self.cur_w);
            self.aw_acked = false;
            self.w_acked = false;
        }
        if b_r && ctx.read(self.axi.bvalid).as_bool() {
            if let Some((addr, expect_ok)) = self.b_expect.pop_front() {
                self.last_bresp = ctx.read_u64(self.axi.bresp);
                if expect_ok && self.last_bresp != resp::OKAY {
                    fail_at(
                        ctx,
                        format!(
                            "write @{:#x}: response {} (expected OKAY)",
                            addr, self.last_bresp
                        ),
                    );
                }
                self.inflight.remove(&addr);
            } else {
                fail_at(ctx, "AXI4-Lite B: response with no outstanding write");
            }
        }
        if !self.aw_valid
            && !self.w_valid
            && !self.aw_acked
            && !self.w_acked
            && self.w_delay.is_none()
            && (self.b_expect.len() as u64) < max
            && let Some(idx) = self.next_op(true)
            && let Op::Write {
                addr,
                data,
                strb,
                expect_ok,
            } = self.ops.remove(idx).unwrap()
        {
            self.aw_valid = true;
            self.aw_addr = addr;
            self.w_data = data;
            self.w_strb = strb;
            match self.w_delay_param {
                Some(d) if d > 0 => {
                    self.w_valid = false;
                    self.w_delay = Some(d - 1);
                }
                _ => self.w_valid = true,
            }
            self.cur_w = (addr, expect_ok);
            self.inflight.insert(addr);
        }
        self.b_ready = !self.b_expect.is_empty() && !stall;

        // --- read engine ---
        if ar_v && ctx.read(self.axi.arready).as_bool() {
            self.ar_valid = false;
            self.r_expect.push_back(self.cur_ar.clone());
        }
        if r_r && ctx.read(self.axi.rvalid).as_bool() {
            if let Some(meta) = self.r_expect.pop_front() {
                let mut data = vec![0u64; self.data_words()];
                ctx.read_words(self.axi.rdata, &mut data);
                match meta.expect {
                    Some(want) if want != data => fail_at(
                        ctx,
                        format!("read @{:#x}: expected {want:x?}, got {data:x?}", meta.addr),
                    ),
                    Some(_) => {}
                    None => {
                        if let Some((mask, value)) = meta.rmw {
                            let mut new = data.clone();
                            for (n, (m, v)) in new.iter_mut().zip(mask.iter().zip(&value)) {
                                *n = (*n & !m) | (v & m);
                            }
                            self.shadow.insert(meta.addr, new.clone());
                            let strb = self.full_strb();
                            self.ops.push_front(Op::Write {
                                addr: meta.addr,
                                data: new,
                                strb,
                                expect_ok: true,
                            });
                        } else {
                            self.reads.push_back(data);
                        }
                    }
                }
                self.inflight.remove(&meta.addr);
            } else {
                fail_at(ctx, "AXI4-Lite R: response with no outstanding read");
            }
        }
        if !self.ar_valid
            && (self.r_expect.len() as u64) < max
            && let Some(idx) = self.next_op(false)
            && let Op::Read(meta) = self.ops.remove(idx).unwrap()
        {
            self.ar_valid = true;
            self.ar_addr = meta.addr;
            self.inflight.insert(meta.addr);
            self.cur_ar = meta;
        }
        self.r_ready = !self.r_expect.is_empty() && !stall;

        if let Some(v) = self.tr_queued {
            ctx.trace(v, self.ops.len() as u64);
        }
        if let Some(v) = self.tr_outstanding {
            ctx.trace(v, (self.b_expect.len() + self.r_expect.len()) as u64);
        }
        self.drive(ctx);
        Ok(())
    }

    /// Queues a full-width write.
    fn write(&mut self, _ctx: &mut SimCtx, addr: u64, data: &Value) -> Result<()> {
        let data = arg_words(data, self.axi.wdata.width(), "write data")?;
        let strb = self.full_strb();
        self.ops.push_back(Op::Write {
            addr,
            data,
            strb,
            expect_ok: false,
        });
        Ok(())
    }

    /// Queues a write with an explicit byte-strobe.
    fn write_strb(
        &mut self,
        _ctx: &mut SimCtx,
        addr: u64,
        data: &Value,
        strb: &Value,
    ) -> Result<()> {
        let data = arg_words(data, self.axi.wdata.width(), "write data")?;
        let strb = arg_words(strb, self.data_bytes(), "write strobe")?;
        self.ops.push_back(Op::Write {
            addr,
            data,
            strb,
            expect_ok: false,
        });
        Ok(())
    }

    /// Queues a self-checking write: the response must be OKAY or the test
    /// fails.
    fn expect_write(&mut self, _ctx: &mut SimCtx, addr: u64, data: &Value) -> Result<()> {
        let data = arg_words(data, self.axi.wdata.width(), "write data")?;
        let strb = self.full_strb();
        self.ops.push_back(Op::Write {
            addr,
            data,
            strb,
            expect_ok: true,
        });
        Ok(())
    }

    /// Queues a read; retrieve its data later with `pop_read`.
    fn read(&mut self, _ctx: &mut SimCtx, addr: u64) -> Result<()> {
        self.ops.push_back(Op::Read(ReadMeta {
            addr,
            ..Default::default()
        }));
        Ok(())
    }

    /// Queues a self-checking read: the returned data is compared against
    /// `data` and a mismatch fails the test. No result is queued for
    /// `pop_read`.
    fn expect_read(&mut self, _ctx: &mut SimCtx, addr: u64, data: &Value) -> Result<()> {
        let expect = arg_words(data, self.axi.rdata.width(), "expected read data")?;
        self.ops.push_back(Op::Read(ReadMeta {
            addr,
            expect: Some(expect),
            ..Default::default()
        }));
        Ok(())
    }

    /// Queues an atomic read-modify-write: reads `addr`, replaces the bits
    /// selected by `mask` with those from `value`, and writes it back. The
    /// two accesses stay ordered on the bus by the hazard control.
    fn rmw(&mut self, _ctx: &mut SimCtx, addr: u64, mask: &Value, value: &Value) -> Result<()> {
        let mask = arg_words(mask, self.axi.wdata.width(), "rmw mask")?;
        let value = arg_words(value, self.axi.wdata.width(), "rmw value")?;
        self.ops.push_back(Op::Read(ReadMeta {
            addr,
            rmw: Some((mask, value)),
            ..Default::default()
        }));
        Ok(())
    }

    /// Queues `count` self-checking writes of random data to random
    /// word-aligned addresses within a `2^addr_bits`-byte window, recording
    /// each value. Drain them, then call `verify_all` to read them back and
    /// check every location. Works at any bus width. Deterministic per seed.
    fn random_writes(&mut self, _ctx: &mut SimCtx, count: u64, addr_bits: u64) -> Result<()> {
        let span = 1u64.checked_shl(addr_bits as u32).unwrap_or(u64::MAX);
        let align = self.data_bytes() as u64;
        let strb = self.full_strb();
        for _ in 0..count {
            let addr = (next_rand(&mut self.traffic_lfsr) % span) & !(align - 1);
            let data = self.rand_data();
            self.shadow.insert(addr, data.clone());
            self.ops.push_back(Op::Write {
                addr,
                data,
                strb: strb.clone(),
                expect_ok: true,
            });
        }
        Ok(())
    }

    /// Like `random_writes` but with a random partial byte-strobe on each
    /// write, so partial-lane writes are exercised. The shadow copy is
    /// merged byte-wise to match, then checked back by `verify_all`.
    fn random_strobed_writes(
        &mut self,
        _ctx: &mut SimCtx,
        count: u64,
        addr_bits: u64,
    ) -> Result<()> {
        let span = 1u64.checked_shl(addr_bits as u32).unwrap_or(u64::MAX);
        let align = self.data_bytes() as u64;
        let dbytes = self.data_bytes() as usize;
        let swords = self.strb_words();
        for _ in 0..count {
            let addr = (next_rand(&mut self.traffic_lfsr) % span) & !(align - 1);
            let data = self.rand_data();
            let mut strb = vec![0u64; swords];
            for byte in 0..dbytes {
                if next_rand(&mut self.traffic_lfsr) & 1 == 1 {
                    strb[byte / 64] |= 1 << (byte % 64);
                }
            }
            self.merge_shadow(addr, &data, &strb);
            self.ops.push_back(Op::Write {
                addr,
                data,
                strb,
                expect_ok: true,
            });
        }
        Ok(())
    }

    /// Queues `count` random self-checking transactions to a
    /// `2^addr_bits`-byte window, each a read with probability
    /// `read_percent/100` (checked against the value last written) or else a
    /// write of random data. Same-address accesses are serialized on the bus
    /// so reads always observe the intended value. Works at any bus width.
    fn random_traffic(
        &mut self,
        _ctx: &mut SimCtx,
        count: u64,
        addr_bits: u64,
        read_percent: u64,
    ) -> Result<()> {
        let span = 1u64.checked_shl(addr_bits as u32).unwrap_or(u64::MAX);
        let align = self.data_bytes() as u64;
        let strb = self.full_strb();
        let dwords = self.data_words();
        for _ in 0..count {
            let addr = (next_rand(&mut self.traffic_lfsr) % span) & !(align - 1);
            if next_rand(&mut self.traffic_lfsr) % 100 < read_percent {
                let expect = self
                    .shadow
                    .get(&addr)
                    .cloned()
                    .unwrap_or_else(|| vec![0u64; dwords]);
                self.ops.push_back(Op::Read(ReadMeta {
                    addr,
                    expect: Some(expect),
                    ..Default::default()
                }));
            } else {
                let data = self.rand_data();
                self.shadow.insert(addr, data.clone());
                self.ops.push_back(Op::Write {
                    addr,
                    data,
                    strb: strb.clone(),
                    expect_ok: true,
                });
            }
        }
        Ok(())
    }

    /// Queues a self-checking read of every address written by
    /// `random_writes`, returning how many. Call after the writes have
    /// drained; a read-back mismatch fails the test.
    fn verify_all(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        let mut entries: Vec<(u64, Vec<u64>)> =
            self.shadow.iter().map(|(&a, d)| (a, d.clone())).collect();
        entries.sort_by_key(|(addr, _)| *addr);
        let n = entries.len() as u64;
        for (addr, data) in entries {
            self.ops.push_back(Op::Read(ReadMeta {
                addr,
                expect: Some(data),
                ..Default::default()
            }));
        }
        Ok(n)
    }

    /// Pops the oldest completed read at full bus width, erroring if none
    /// is ready.
    #[ret_width(axi.DATA_WIDTH_BYTES * 8)]
    fn pop_read(&mut self, _ctx: &mut SimCtx) -> Result<Value> {
        let words = self
            .reads
            .pop_front()
            .ok_or_else(|| anyhow!("no read result available"))?;
        let width = self.axi.rdata.width();
        Ok(data_value(words, width))
    }

    /// Number of completed reads waiting in the result queue.
    fn num_reads(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(self.reads.len() as u64)
    }

    /// 1 when every queued transaction has completed, else 0.
    fn idle(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        let busy = !self.ops.is_empty()
            || !self.b_expect.is_empty()
            || !self.r_expect.is_empty()
            || self.aw_valid
            || self.w_valid
            || self.ar_valid
            || self.aw_acked
            || self.w_acked;
        Ok(u64::from(!busy))
    }

    /// Response code of the most recent write (`0` = OKAY, `2` = SLVERR).
    fn last_bresp(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(self.last_bresp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use veryl_component::testing::MockSim;

    fn master_sim() -> MockSim {
        master_sim_addr(32)
    }

    fn master_sim_addr(addr_w: u32) -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .output("axi.awvalid", 1)
            .input("axi.awready", 1)
            .output("axi.awaddr", addr_w)
            .output("axi.awprot", 3)
            .output("axi.wvalid", 1)
            .input("axi.wready", 1)
            .output("axi.wdata", 32)
            .output("axi.wstrb", 4)
            .input("axi.bvalid", 1)
            .output("axi.bready", 1)
            .input("axi.bresp", 2)
            .output("axi.arvalid", 1)
            .input("axi.arready", 1)
            .output("axi.araddr", addr_w)
            .output("axi.arprot", 3)
            .input("axi.rvalid", 1)
            .output("axi.rready", 1)
            .input("axi.rdata", 32)
    }

    fn u(sim: &mut MockSim, name: &str) -> u64 {
        sim.get(name).as_u64().unwrap()
    }

    fn idle(sim: &mut MockSim, c: &mut Axi4LiteMaster) -> bool {
        sim.call(c, "idle", &[]).unwrap().as_u64().unwrap() == 1
    }

    /// Plays a cooperative always-ready slave that returns `rdata` for the
    /// pending read, tolerating a stalling master, until the master is idle.
    fn serve_read(sim: &mut MockSim, c: &mut Axi4LiteMaster, rdata: u64) {
        let mut ar_done = false;
        for _ in 0..80 {
            let arvalid = u(sim, "axi.arvalid") == 1;
            sim.set("axi.arready", u64::from(arvalid && !ar_done));
            sim.set("axi.rvalid", u64::from(ar_done));
            sim.set("axi.rdata", rdata);
            if arvalid && !ar_done {
                ar_done = true;
            }
            sim.clock(c).unwrap();
            if ar_done && idle(sim, c) {
                return;
            }
        }
        panic!("read did not complete");
    }

    /// Plays a cooperative slave that accepts a write and responds `bresp`.
    fn serve_write(sim: &mut MockSim, c: &mut Axi4LiteMaster, bresp: u64) {
        let mut accepted = false;
        for _ in 0..80 {
            let awvalid = u(sim, "axi.awvalid") == 1;
            let wvalid = u(sim, "axi.wvalid") == 1;
            sim.set("axi.awready", u64::from(awvalid && !accepted));
            sim.set("axi.wready", u64::from(wvalid && !accepted));
            sim.set("axi.bvalid", u64::from(accepted));
            sim.set("axi.bresp", bresp);
            if awvalid && wvalid && !accepted {
                accepted = true;
            }
            sim.clock(c).unwrap();
            if accepted && idle(sim, c) {
                return;
            }
        }
        panic!("write did not complete");
    }

    #[test]
    fn write_drives_bus_and_completes() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "write", &[0x10u64.into(), 0xdeadu64.into()])
            .unwrap();

        sim.clock(&mut c).unwrap(); // launch: AW/W asserted
        assert_eq!(u(&mut sim, "axi.awvalid"), 1);
        assert_eq!(u(&mut sim, "axi.awaddr"), 0x10);
        assert_eq!(u(&mut sim, "axi.wdata"), 0xdead);
        assert_eq!(u(&mut sim, "axi.wstrb"), 0xf);

        sim.set("axi.awready", 1u64);
        sim.set("axi.wready", 1u64);
        sim.clock(&mut c).unwrap(); // AW/W handshake, BREADY asserts
        assert_eq!(u(&mut sim, "axi.awvalid"), 0);
        assert_eq!(u(&mut sim, "axi.bready"), 1);

        sim.set("axi.bvalid", 1u64);
        sim.set("axi.bresp", 0u64);
        sim.clock(&mut c).unwrap(); // B handshake, done

        assert!(idle(&mut sim, &mut c));
        assert_eq!(
            sim.call(&mut c, "last_bresp", &[])
                .unwrap()
                .as_u64()
                .unwrap(),
            0
        );
    }

    #[test]
    fn read_drives_bus_and_returns_data() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "read", &[0x20u64.into()]).unwrap();
        serve_read(&mut sim, &mut c, 0xcafe);
        assert_eq!(
            sim.call(&mut c, "pop_read", &[]).unwrap().as_u64().unwrap(),
            0xcafe
        );
    }

    #[test]
    fn expect_read_passes_on_match() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "expect_read", &[0x20u64.into(), 0xcafeu64.into()])
            .unwrap();
        serve_read(&mut sim, &mut c, 0xcafe);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
        assert_eq!(
            sim.call(&mut c, "num_reads", &[])
                .unwrap()
                .as_u64()
                .unwrap(),
            0
        );
    }

    #[test]
    fn expect_read_fails_on_mismatch() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "expect_read", &[0x20u64.into(), 0xcafeu64.into()])
            .unwrap();
        serve_read(&mut sim, &mut c, 0xdead);
        assert!(sim.failures().iter().any(|f| f.contains("expected")));
    }

    #[test]
    fn expect_write_passes_on_okay() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "expect_write", &[0x10u64.into(), 0x5u64.into()])
            .unwrap();
        serve_write(&mut sim, &mut c, resp::OKAY);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn expect_write_fails_on_error_response() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "expect_write", &[0x10u64.into(), 0x5u64.into()])
            .unwrap();
        serve_write(&mut sim, &mut c, resp::SLVERR);
        assert!(sim.failures().iter().any(|f| f.contains("response")));
    }

    #[test]
    fn reads_pipeline_multiple_outstanding() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "read", &[0x10u64.into()]).unwrap();
        sim.call(&mut c, "read", &[0x20u64.into()]).unwrap();

        sim.clock(&mut c).unwrap(); // launch AR1
        assert_eq!(u(&mut sim, "axi.arvalid"), 1);
        assert_eq!(u(&mut sim, "axi.araddr"), 0x10);

        sim.set("axi.arready", 1u64);
        sim.clock(&mut c).unwrap(); // AR1 accepted, AR2 launched before any R
        assert_eq!(u(&mut sim, "axi.arvalid"), 1);
        assert_eq!(u(&mut sim, "axi.araddr"), 0x20);

        // Accept AR2 and return R1 in the same cycle.
        sim.set("axi.arready", 1u64);
        sim.set("axi.rvalid", 1u64);
        sim.set("axi.rdata", 0xaaau64);
        sim.clock(&mut c).unwrap();
        assert_eq!(u(&mut sim, "axi.arvalid"), 0);

        // Return R2.
        sim.set("axi.arready", 0u64);
        sim.set("axi.rdata", 0xbbbu64);
        sim.clock(&mut c).unwrap();

        assert!(idle(&mut sim, &mut c));
        assert_eq!(
            sim.call(&mut c, "pop_read", &[]).unwrap().as_u64().unwrap(),
            0xaaa
        );
        assert_eq!(
            sim.call(&mut c, "pop_read", &[]).unwrap().as_u64().unwrap(),
            0xbbb
        );
    }

    #[test]
    fn transactions_complete_while_stalling() {
        let mut sim = master_sim().param("STALL", 200u64);
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "write", &[0x8u64.into(), 0x99u64.into()])
            .unwrap();
        serve_write(&mut sim, &mut c, resp::OKAY);
        sim.call(&mut c, "expect_read", &[0x8u64.into(), 0x1234u64.into()])
            .unwrap();
        serve_read(&mut sim, &mut c, 0x1234);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    /// Plays a single-outstanding memory slave (accept AW+W together,
    /// respond OKAY, serve reads from what was written) until the master is
    /// idle. `mem` persists across calls so writes are visible to later reads.
    fn serve_memory(sim: &mut MockSim, c: &mut Axi4LiteMaster, mem: &mut HashMap<u64, u64>) {
        let mut b_pending = false;
        let mut r_data: Option<u64> = None;
        for _ in 0..8000 {
            let awvalid = u(sim, "axi.awvalid") == 1;
            let wvalid = u(sim, "axi.wvalid") == 1;
            let accept_w = awvalid && wvalid && !b_pending;
            let arvalid = u(sim, "axi.arvalid") == 1;
            let accept_r = arvalid && r_data.is_none();
            let awaddr = u(sim, "axi.awaddr");
            let wdata = u(sim, "axi.wdata");
            let wstrb = u(sim, "axi.wstrb");
            let araddr = u(sim, "axi.araddr");
            let bready = u(sim, "axi.bready") == 1;
            let rready = u(sim, "axi.rready") == 1;

            sim.set("axi.awready", u64::from(accept_w));
            sim.set("axi.wready", u64::from(accept_w));
            sim.set("axi.bvalid", u64::from(b_pending));
            sim.set("axi.bresp", 0u64);
            sim.set("axi.arready", u64::from(accept_r));
            sim.set("axi.rvalid", u64::from(r_data.is_some()));
            sim.set("axi.rdata", r_data.unwrap_or(0));
            sim.clock(c).unwrap();

            if accept_w {
                let mut word = *mem.get(&awaddr).unwrap_or(&0);
                for byte in 0..4 {
                    if (wstrb >> byte) & 1 != 0 {
                        let mask = 0xffu64 << (byte * 8);
                        word = (word & !mask) | (wdata & mask);
                    }
                }
                mem.insert(awaddr, word);
                b_pending = true;
            }
            if b_pending && bready {
                b_pending = false;
            }
            if accept_r {
                r_data = Some(*mem.get(&araddr).unwrap_or(&0));
            }
            if r_data.is_some() && rready {
                r_data = None;
            }
            if !b_pending && r_data.is_none() && idle(sim, c) {
                return;
            }
        }
        panic!("memory service did not drain");
    }

    #[test]
    fn random_regression_roundtrips() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        let mut mem: HashMap<u64, u64> = HashMap::new();
        sim.call(&mut c, "random_writes", &[16u64.into(), 6u64.into()])
            .unwrap();
        serve_memory(&mut sim, &mut c, &mut mem); // drain the writes
        let n = sim
            .call(&mut c, "verify_all", &[])
            .unwrap()
            .as_u64()
            .unwrap();
        assert!(n > 0);
        serve_memory(&mut sim, &mut c, &mut mem); // read back, self-checking
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn mixed_random_traffic_self_checks() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        let mut mem: HashMap<u64, u64> = HashMap::new();
        // 100 ops over an 8-word window forces heavy read-after-write and
        // write-after-read collisions, stressing the per-address hazard
        // control; a broken one would read a stale value and fail.
        sim.call(
            &mut c,
            "random_traffic",
            &[100u64.into(), 5u64.into(), 40u64.into()],
        )
        .unwrap();
        serve_memory(&mut sim, &mut c, &mut mem);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn partial_strobe_regression_roundtrips() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        let mut mem: HashMap<u64, u64> = HashMap::new();
        sim.call(
            &mut c,
            "random_strobed_writes",
            &[32u64.into(), 6u64.into()],
        )
        .unwrap();
        serve_memory(&mut sim, &mut c, &mut mem);
        sim.call(&mut c, "verify_all", &[]).unwrap();
        serve_memory(&mut sim, &mut c, &mut mem);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }

    #[test]
    fn rmw_updates_masked_bits() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        let mut mem: HashMap<u64, u64> = HashMap::new();
        sim.call(&mut c, "write", &[0x10u64.into(), 0x0000_00ffu64.into()])
            .unwrap();
        // Replace byte 1 (mask 0xff00) with 0xab.
        sim.call(
            &mut c,
            "rmw",
            &[0x10u64.into(), 0xff00u64.into(), 0xab00u64.into()],
        )
        .unwrap();
        sim.call(
            &mut c,
            "expect_read",
            &[0x10u64.into(), 0x0000_abffu64.into()],
        )
        .unwrap();
        serve_memory(&mut sim, &mut c, &mut mem);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
        assert_eq!(*mem.get(&0x10).unwrap(), 0x0000_abff);
    }

    #[test]
    fn w_delay_skews_the_channels() {
        let mut sim = master_sim().param("W_DELAY", 2u64);
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "write", &[0x10u64.into(), 0x5u64.into()])
            .unwrap();
        sim.clock(&mut c).unwrap(); // AWVALID asserts, WVALID held back
        assert_eq!(u(&mut sim, "axi.awvalid"), 1);
        assert_eq!(u(&mut sim, "axi.wvalid"), 0);
        sim.clock(&mut c).unwrap();
        assert_eq!(u(&mut sim, "axi.wvalid"), 0);
        sim.clock(&mut c).unwrap(); // WVALID follows after two cycles
        assert_eq!(u(&mut sim, "axi.awvalid"), 1);
        assert_eq!(u(&mut sim, "axi.wvalid"), 1);
    }

    #[test]
    fn traces_queue_depth() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "read", &[0x10u64.into()]).unwrap();
        sim.call(&mut c, "read", &[0x20u64.into()]).unwrap();
        sim.clock(&mut c).unwrap(); // one launched, one still queued
        assert_eq!(sim.trace_value("queued").as_u64().unwrap(), 1);
    }

    #[test]
    fn pop_read_errors_when_empty() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4LiteMaster>().unwrap();
        let err = sim.call(&mut c, "pop_read", &[]).unwrap_err();
        assert!(err.to_string().contains("no read result"));
    }

    #[test]
    fn address_wider_than_64_bits_is_rejected() {
        let mut sim = master_sim_addr(96);
        let err = sim.build::<Axi4LiteMaster>().err().unwrap();
        assert!(err.to_string().contains("64-bit address limit"), "{err}");
    }
}
