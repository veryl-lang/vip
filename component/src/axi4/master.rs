//! Active AXI4 (full) master: multiple outstanding bursts with per-ID
//! response routing (out-of-order reads and write responses).

use super::{beat_addr, burst};
use crate::common::{
    arg_words, data_value, fail_at, mask_words, next_rand, resp, stall_now, words_for,
};
use std::collections::{HashMap, VecDeque};
use veryl_component::*;

/// A queued write burst.
#[derive(Clone, Default)]
struct WriteOp {
    addr: u64,
    len: u64,
    size_log: u64,
    kind: u64,
    lock: u64,
    data: Vec<Vec<u64>>,
    strb: Vec<Vec<u64>>,
    expect_ok: bool,
}

/// A queued (or in-flight) read burst.
#[derive(Clone, Default)]
struct ReadOp {
    addr: u64,
    len: u64,
    size_log: u64,
    kind: u64,
    lock: u64,
    beat: u64,
    expect: Option<Vec<Vec<u64>>>,
}

#[derive(VerylInterface)]
#[interface(path = "$std::axi4_if", modport = "master")]
pub struct Axi4MasterPorts {
    awvalid: OutputPort,
    awready: InputPort,
    awaddr: OutputPort,
    awlen: OutputPort,
    awsize: OutputPort,
    awburst: OutputPort,
    awid: OutputPort,
    awlock: OutputPort,
    wvalid: OutputPort,
    wready: InputPort,
    wdata: OutputPort,
    wstrb: OutputPort,
    wlast: OutputPort,
    bvalid: InputPort,
    bready: OutputPort,
    bresp: InputPort,
    bid: InputPort,
    arvalid: OutputPort,
    arready: InputPort,
    araddr: OutputPort,
    arlen: OutputPort,
    arsize: OutputPort,
    arburst: OutputPort,
    arid: OutputPort,
    arlock: OutputPort,
    rvalid: InputPort,
    rready: OutputPort,
    rdata: InputPort,
    rid: InputPort,
    rlast: InputPort,
}

/// Active AXI4 master. Connect to the `master` modport. Pipelines up to
/// `MAX_OUTSTANDING` reads and writes with distinct IDs and matches each
/// response to its transaction by ID, so it handles a slave's interleaved
/// out-of-order read data. Read data is self-checked. `random_burst_writes` /
/// `random_bursts` + `verify_all` give a randomized burst regression.
/// `exclusive_read` / `exclusive_write` exercise the locked read-modify-write
/// path; `exclusive_ok` reports whether the last exclusive write got EXOKAY.
#[derive(Component)]
#[component(kind = clocked)]
pub struct Axi4Master {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; drops in-flight bursts and clears the queues.
    rst: ResetPort,

    /// The AXI4 bus, driven as master.
    #[interface]
    axi: Axi4MasterPorts,

    /// 0..=255 weight for randomly delaying BREADY/RREADY.
    #[param(name = "STALL")]
    stall: Option<u64>,
    /// Maximum outstanding transactions per direction; unset means 4.
    #[param(name = "MAX_OUTSTANDING")]
    max_outstanding: Option<u64>,

    w_queue: VecDeque<WriteOp>,
    r_queue: VecDeque<ReadOp>,
    // Per outstanding write ID: (expect OKAY, is exclusive).
    b_out: HashMap<u64, (bool, u64)>,
    r_out: HashMap<u64, ReadOp>,
    reads: VecDeque<Vec<u64>>,
    shadow: HashMap<u64, Vec<u64>>,
    last_bresp: u64,
    last_excl_ok: bool,
    lfsr: u64,
    traffic_lfsr: u64,

    // Write being issued (phase 0 addr, 1 data) and read being issued.
    w_active: bool,
    w_phase: u8,
    w_beat: u64,
    w_id: u64,
    cur_w: WriteOp,
    ar_active: bool,
    ar_id: u64,
    cur_ar: ReadOp,

    // Registered output shadows.
    aw_valid: bool,
    w_valid: bool,
    b_ready: bool,
    ar_valid: bool,
    r_ready: bool,
}

impl Axi4Master {
    fn data_bytes(&self) -> u64 {
        (self.axi.wdata.width() as u64 / 8).max(1)
    }

    fn data_words(&self) -> usize {
        words_for(self.axi.wdata.width())
    }

    fn size_log(&self) -> u64 {
        self.data_bytes().trailing_zeros() as u64
    }

    fn max(&self) -> usize {
        self.max_outstanding.unwrap_or(4) as usize
    }

    fn id_mask(&self) -> u64 {
        let w = self.axi.awid.width();
        if w >= 64 { u64::MAX } else { (1u64 << w) - 1 }
    }

    fn full_strb(&self) -> Vec<u64> {
        let bytes = self.data_bytes() as u32;
        let mut strb = vec![u64::MAX; words_for(bytes)];
        mask_words(&mut strb, bytes);
        strb
    }

    /// A data word-vector holding `v` in its low 64 bits (internal expected
    /// values whose data is an address).
    fn scalar_words(&self, v: u64) -> Vec<u64> {
        let mut words = vec![0u64; self.data_words()];
        words[0] = v;
        mask_words(&mut words, self.axi.wdata.width());
        words
    }

    fn rand_data(&mut self) -> Vec<u64> {
        let mut data = vec![0u64; self.data_words()];
        for word in data.iter_mut() {
            *word = next_rand(&mut self.traffic_lfsr);
        }
        mask_words(&mut data, self.axi.wdata.width());
        data
    }

    fn narrow_strb(&self, addr: u64, size_bytes: u64) -> Vec<u64> {
        let offset = (addr & (self.data_bytes() - 1)) as usize;
        let mut strb = vec![0u64; words_for(self.data_bytes() as u32)];
        for byte in offset..offset + size_bytes as usize {
            strb[byte / 64] |= 1 << (byte % 64);
        }
        strb
    }

    fn merge_shadow(&mut self, addr: u64, data: &[u64], strb: &[u64]) {
        let dbytes = self.data_bytes() as usize;
        let dwords = self.data_words();
        let key = addr & !(self.data_bytes() - 1);
        let word = self.shadow.entry(key).or_insert_with(|| vec![0u64; dwords]);
        for byte in 0..dbytes {
            if (strb[byte / 64] >> (byte % 64)) & 1 != 0 {
                let dword = byte / 8;
                let mask = 0xffu64 << ((byte % 8) * 8);
                word[dword] = (word[dword] & !mask) | (data[dword] & mask);
            }
        }
    }

    /// Allocating a free ID (not a running counter) keeps two live writes off
    /// the same `BID`; the build check guarantees a free ID exists.
    fn next_write_id(&self) -> u64 {
        (0..=self.id_mask())
            .find(|id| !self.b_out.contains_key(id))
            .unwrap_or(0)
    }

    /// Read IDs are pooled apart from writes, so a read never takes a live
    /// write's ID.
    fn next_read_id(&self) -> u64 {
        (0..=self.id_mask())
            .find(|id| !self.r_out.contains_key(id))
            .unwrap_or(0)
    }

    fn w_beat_data(&self) -> Vec<u64> {
        self.cur_w
            .data
            .get(self.w_beat as usize)
            .cloned()
            .unwrap_or_else(|| vec![0u64; self.data_words()])
    }

    fn w_beat_strb(&self) -> Vec<u64> {
        self.cur_w
            .strb
            .get(self.w_beat as usize)
            .cloned()
            .unwrap_or_else(|| self.full_strb())
    }

    fn reset_state(&mut self) {
        self.w_queue.clear();
        self.r_queue.clear();
        self.b_out.clear();
        self.r_out.clear();
        self.reads.clear();
        self.shadow.clear();
        self.w_active = false;
        self.ar_active = false;
        self.aw_valid = false;
        self.w_valid = false;
        self.b_ready = false;
        self.ar_valid = false;
        self.r_ready = false;
    }

    fn drive(&mut self, ctx: &mut SimCtx) {
        let wbeat = self.w_beat_data();
        let wstrb = self.w_beat_strb();
        ctx.write(self.axi.awvalid, self.aw_valid);
        ctx.write(self.axi.awaddr, self.cur_w.addr);
        ctx.write(self.axi.awlen, self.cur_w.len);
        ctx.write(self.axi.awsize, self.cur_w.size_log);
        ctx.write(self.axi.awburst, self.cur_w.kind);
        ctx.write(self.axi.awid, self.w_id);
        ctx.write(self.axi.awlock, self.cur_w.lock);
        ctx.write(self.axi.wvalid, self.w_valid);
        ctx.write_words(self.axi.wdata, &wbeat);
        ctx.write_words(self.axi.wstrb, &wstrb);
        ctx.write(self.axi.wlast, self.w_beat == self.cur_w.len);
        ctx.write(self.axi.bready, self.b_ready);
        ctx.write(self.axi.arvalid, self.ar_valid);
        ctx.write(self.axi.araddr, self.cur_ar.addr);
        ctx.write(self.axi.arlen, self.cur_ar.len);
        ctx.write(self.axi.arsize, self.cur_ar.size_log);
        ctx.write(self.axi.arburst, self.cur_ar.kind);
        ctx.write(self.axi.arid, self.ar_id);
        ctx.write(self.axi.arlock, self.cur_ar.lock);
        ctx.write(self.axi.rready, self.r_ready);
    }
}

#[component_impl]
impl Axi4Master {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        // Addresses are driven from u64; a wider bus's high bits would be
        // silently dropped.
        for (name, w) in [
            ("awaddr", self.axi.awaddr.width()),
            ("araddr", self.axi.araddr.width()),
        ] {
            if w > 64 {
                bail!("axi4_master: {name} width {w} exceeds the 64-bit address limit");
            }
        }
        let seed = ctx.seed();
        self.lfsr = seed | 1;
        self.traffic_lfsr = seed.rotate_left(32) | 1;
        self.cur_w = WriteOp {
            data: vec![vec![0; self.data_words()]],
            strb: vec![self.full_strb()],
            ..Default::default()
        };
        // More outstanding per direction than the ID space holds would leave
        // no free ID for next_write_id/next_read_id to pick.
        let id_space = 1u64.checked_shl(self.axi.awid.width()).unwrap_or(u64::MAX);
        if self.max() as u64 > id_space {
            return Err(anyhow!(
                "axi4_master: MAX_OUTSTANDING ({}) exceeds the {}-bit ID space ({id_space})",
                self.max(),
                self.axi.awid.width(),
            ));
        }
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
        let max = self.max();
        let aw_v = self.aw_valid;
        let w_v = self.w_valid;
        let b_r = self.b_ready;
        let ar_v = self.ar_valid;
        let r_r = self.r_ready;

        // --- write engine (in-order AW/W, out-of-order B by ID) ---
        if self.w_active && self.w_phase == 0 && aw_v && ctx.read(self.axi.awready).as_bool() {
            self.w_phase = 1;
            self.w_beat = 0;
        } else if self.w_active && self.w_phase == 1 && w_v && ctx.read(self.axi.wready).as_bool() {
            self.w_beat += 1;
            if self.w_beat > self.cur_w.len {
                self.b_out
                    .insert(self.w_id, (self.cur_w.expect_ok, self.cur_w.lock));
                self.w_active = false;
            }
        }
        if b_r && ctx.read(self.axi.bvalid).as_bool() {
            let bid = ctx.read_u64(self.axi.bid);
            match self.b_out.remove(&bid) {
                Some((expect_ok, lock)) => {
                    self.last_bresp = ctx.read_u64(self.axi.bresp);
                    if lock != 0 {
                        // An exclusive write reports EXOKAY on success, OKAY on
                        // a lost reservation; both are legal here.
                        self.last_excl_ok = self.last_bresp == resp::EXOKAY;
                    } else if expect_ok && self.last_bresp != 0 {
                        fail_at(
                            ctx,
                            format!("AXI4 write id {bid}: response {}", self.last_bresp),
                        );
                    }
                }
                None => fail_at(ctx, format!("AXI4 B: unexpected BID {bid}")),
            }
        }
        if !self.w_active
            && self.b_out.len() < max
            && let Some(op) = self.w_queue.pop_front()
        {
            self.w_active = true;
            self.w_phase = 0;
            self.w_id = self.next_write_id();
            self.cur_w = op;
        }
        self.aw_valid = self.w_active && self.w_phase == 0;
        self.w_valid = self.w_active && self.w_phase == 1;
        self.b_ready = !self.b_out.is_empty() && !stall;

        // --- read engine (out-of-order R by ID) ---
        if self.ar_active && ar_v && ctx.read(self.axi.arready).as_bool() {
            let mut op = std::mem::take(&mut self.cur_ar);
            op.beat = 0;
            self.r_out.insert(self.ar_id, op);
            self.ar_active = false;
        }
        if r_r && ctx.read(self.axi.rvalid).as_bool() {
            let rid = ctx.read_u64(self.axi.rid);
            let mut beat = vec![0u64; self.data_words()];
            ctx.read_words(self.axi.rdata, &mut beat);
            let last = ctx.read(self.axi.rlast).as_bool();
            let mut last_bad = false;
            let mut data_bad = false;
            let mut store = None;
            let mut done = false;
            let mut known = false;
            if let Some(st) = self.r_out.get_mut(&rid) {
                known = true;
                last_bad = last != (st.beat == st.len);
                match &st.expect {
                    Some(exp) => data_bad = exp.get(st.beat as usize) != Some(&beat),
                    None => store = Some(beat.clone()),
                }
                st.beat += 1;
                done = st.beat > st.len;
            }
            if done {
                self.r_out.remove(&rid);
            }
            if !known {
                fail_at(ctx, format!("AXI4 R: unexpected RID {rid}"));
            }
            if last_bad {
                fail_at(ctx, format!("AXI4 read id {rid}: RLAST misaligned"));
            }
            if data_bad {
                fail_at(ctx, format!("AXI4 read id {rid}: data mismatch"));
            }
            if let Some(d) = store {
                self.reads.push_back(d);
            }
        }
        if !self.ar_active
            && self.r_out.len() < max
            && let Some(op) = self.r_queue.pop_front()
        {
            self.ar_active = true;
            self.ar_id = self.next_read_id();
            self.cur_ar = op;
        }
        self.ar_valid = self.ar_active;
        self.r_ready = !self.r_out.is_empty() && !stall;

        self.drive(ctx);
        Ok(())
    }

    /// Queues `count` random INCR burst writes into a `2^addr_bits`-byte
    /// window (lengths up to `max_len`), recording each beat for `verify_all`.
    fn random_burst_writes(
        &mut self,
        _ctx: &mut SimCtx,
        count: u64,
        addr_bits: u64,
        max_len: u64,
    ) -> Result<()> {
        let span = 1u64.checked_shl(addr_bits as u32).unwrap_or(u64::MAX);
        let bytes = self.data_bytes();
        let size_log = self.size_log();
        let full = self.full_strb();
        for _ in 0..count {
            let base = (next_rand(&mut self.traffic_lfsr) % span) & !(bytes - 1);
            let mut len = next_rand(&mut self.traffic_lfsr) % (max_len + 1);
            while (base & 0xfff) + (len + 1) * bytes > 0x1000 && len > 0 {
                len -= 1;
            }
            let mut data = Vec::new();
            let mut strb = Vec::new();
            for n in 0..=len {
                let d = self.rand_data();
                self.shadow
                    .insert(beat_addr(base, bytes, burst::INCR, len, n), d.clone());
                data.push(d);
                strb.push(full.clone());
            }
            self.w_queue.push_back(WriteOp {
                addr: base,
                len,
                size_log,
                kind: burst::INCR,
                lock: 0,
                data,
                strb,
                expect_ok: true,
            });
        }
        Ok(())
    }

    /// Queues `count` random self-checking bursts with random type
    /// (INCR/FIXED/WRAP) and random narrow size, per-beat byte strobes.
    fn random_bursts(
        &mut self,
        _ctx: &mut SimCtx,
        count: u64,
        addr_bits: u64,
        max_len: u64,
    ) -> Result<()> {
        let span = 1u64.checked_shl(addr_bits as u32).unwrap_or(u64::MAX);
        let full_size = self.size_log();
        for _ in 0..count {
            let mut kind = match next_rand(&mut self.traffic_lfsr) % 3 {
                0 => burst::FIXED,
                1 => burst::WRAP,
                _ => burst::INCR,
            };
            let size_log = next_rand(&mut self.traffic_lfsr) % (full_size + 1);
            let size_bytes = 1u64 << size_log;
            let mut len = next_rand(&mut self.traffic_lfsr) % (max_len + 1);
            if kind == burst::WRAP {
                // WRAP needs a 2/4/8/16-beat length; if none fits max_len (e.g.
                // max_len 0) fall back to INCR rather than exceeding max_len.
                let choices: Vec<u64> = [1, 3, 7, 15]
                    .into_iter()
                    .filter(|&l| l <= max_len)
                    .collect();
                match choices
                    .get((next_rand(&mut self.traffic_lfsr) as usize) % choices.len().max(1))
                {
                    Some(&l) => len = l,
                    None => kind = burst::INCR,
                }
            }
            let base = (next_rand(&mut self.traffic_lfsr) % span) & !(size_bytes - 1);
            if kind == burst::INCR {
                while (base & 0xfff) + (len + 1) * size_bytes > 0x1000 && len > 0 {
                    len -= 1;
                }
            }
            let mut data = Vec::new();
            let mut strb = Vec::new();
            for n in 0..=len {
                let a = beat_addr(base, size_bytes, kind, len, n);
                let d = self.rand_data();
                let s = self.narrow_strb(a, size_bytes);
                self.merge_shadow(a, &d, &s);
                data.push(d);
                strb.push(s);
            }
            self.w_queue.push_back(WriteOp {
                addr: base,
                len,
                size_log,
                kind,
                lock: 0,
                data,
                strb,
                expect_ok: true,
            });
        }
        Ok(())
    }

    /// Queues a single-beat checked read of every written address; the reads
    /// pipeline (multiple outstanding). Returns how many.
    fn verify_all(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        let mut entries: Vec<(u64, Vec<u64>)> =
            self.shadow.iter().map(|(&a, d)| (a, d.clone())).collect();
        entries.sort_by_key(|(a, _)| *a);
        let n = entries.len() as u64;
        let size_log = self.size_log();
        for (addr, data) in entries {
            self.r_queue.push_back(ReadOp {
                addr,
                len: 0,
                size_log,
                kind: burst::INCR,
                lock: 0,
                beat: 0,
                expect: Some(vec![data]),
            });
        }
        Ok(n)
    }

    /// Queues an INCR burst read of `len + 1` beats whose data is checked
    /// against `fill` (each word equals its address). Interleaves with other
    /// outstanding reads.
    fn read_check_incr(&mut self, _ctx: &mut SimCtx, addr: u64, len: u64) -> Result<()> {
        let bytes = self.data_bytes();
        let size_log = self.size_log();
        let expect: Vec<Vec<u64>> = (0..=len)
            .map(|n| self.scalar_words(beat_addr(addr, bytes, burst::INCR, len, n)))
            .collect();
        self.r_queue.push_back(ReadOp {
            addr,
            len,
            size_log,
            kind: burst::INCR,
            lock: 0,
            beat: 0,
            expect: Some(expect),
        });
        Ok(())
    }

    /// Queues an INCR burst read of `len + 1` beats; drain with `pop_read`.
    fn read_burst(&mut self, _ctx: &mut SimCtx, addr: u64, len: u64) -> Result<()> {
        let size_log = self.size_log();
        self.r_queue.push_back(ReadOp {
            addr,
            len,
            size_log,
            kind: burst::INCR,
            lock: 0,
            beat: 0,
            expect: None,
        });
        Ok(())
    }

    /// Pops the oldest read beat at full bus width, erroring if none.
    #[ret_width(axi.DATA_WIDTH_BYTES * 8)]
    fn pop_read(&mut self, _ctx: &mut SimCtx) -> Result<Value> {
        let beat = self
            .reads
            .pop_front()
            .ok_or_else(|| anyhow!("no read beat available"))?;
        let width = self.axi.rdata.width();
        Ok(data_value(beat, width))
    }

    /// 1 when every queued and in-flight transaction has completed, else 0.
    fn idle(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        let busy = !self.w_queue.is_empty()
            || !self.r_queue.is_empty()
            || self.w_active
            || self.ar_active
            || !self.b_out.is_empty()
            || !self.r_out.is_empty();
        Ok(u64::from(!busy))
    }

    /// Response code of the most recent write burst.
    fn last_bresp(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(self.last_bresp)
    }

    /// Queues a single-beat normal write of `data` to `addr`.
    fn write(&mut self, _ctx: &mut SimCtx, addr: u64, data: &Value) -> Result<()> {
        let data = arg_words(data, self.axi.wdata.width(), "write data")?;
        let size_log = self.size_log();
        self.w_queue.push_back(WriteOp {
            addr,
            len: 0,
            size_log,
            kind: burst::INCR,
            lock: 0,
            data: vec![data],
            strb: vec![self.full_strb()],
            expect_ok: true,
        });
        Ok(())
    }

    /// Queues a single-beat exclusive read of `addr` (`ARLOCK`), arming the
    /// slave's monitor. Its data drains through `pop_read` like any other read,
    /// sharing the same FIFO — pop it before issuing later reads if you need
    /// the read-modify-write value.
    fn exclusive_read(&mut self, _ctx: &mut SimCtx, addr: u64) -> Result<()> {
        let size_log = self.size_log();
        self.r_queue.push_back(ReadOp {
            addr,
            len: 0,
            size_log,
            kind: burst::INCR,
            lock: 1,
            beat: 0,
            expect: None,
        });
        Ok(())
    }

    /// Queues a single-beat exclusive write of `data` to `addr` (`AWLOCK`). It
    /// succeeds (EXOKAY) only if the address is still reserved; check the
    /// outcome with `exclusive_ok` once the write has drained.
    fn exclusive_write(&mut self, _ctx: &mut SimCtx, addr: u64, data: &Value) -> Result<()> {
        let data = arg_words(data, self.axi.wdata.width(), "write data")?;
        let size_log = self.size_log();
        self.w_queue.push_back(WriteOp {
            addr,
            len: 0,
            size_log,
            kind: burst::INCR,
            lock: 1,
            data: vec![data],
            strb: vec![self.full_strb()],
            expect_ok: false,
        });
        Ok(())
    }

    /// 1 if the most recent exclusive write got EXOKAY (succeeded), else 0.
    fn exclusive_ok(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(u64::from(self.last_excl_ok))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veryl_component::testing::MockSim;

    fn master_sim() -> MockSim {
        master_sim_cfg(32, 4)
    }

    fn master_sim_cfg(addr_w: u32, id_w: u32) -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .output("axi.awvalid", 1)
            .input("axi.awready", 1)
            .output("axi.awaddr", addr_w)
            .output("axi.awlen", 8)
            .output("axi.awsize", 3)
            .output("axi.awburst", 2)
            .output("axi.awid", id_w)
            .output("axi.awlock", 1)
            .output("axi.wvalid", 1)
            .input("axi.wready", 1)
            .output("axi.wdata", 32)
            .output("axi.wstrb", 4)
            .output("axi.wlast", 1)
            .input("axi.bvalid", 1)
            .output("axi.bready", 1)
            .input("axi.bresp", 2)
            .input("axi.bid", id_w)
            .output("axi.arvalid", 1)
            .input("axi.arready", 1)
            .output("axi.araddr", addr_w)
            .output("axi.arlen", 8)
            .output("axi.arsize", 3)
            .output("axi.arburst", 2)
            .output("axi.arid", id_w)
            .output("axi.arlock", 1)
            .input("axi.rvalid", 1)
            .output("axi.rready", 1)
            .input("axi.rdata", 32)
            .input("axi.rid", id_w)
            .input("axi.rlast", 1)
    }

    #[test]
    fn read_burst_drives_the_address_phase() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4Master>().unwrap();
        sim.set("rst", 0u64);
        assert_eq!(sim.call(&mut c, "idle", &[]).unwrap().as_u64().unwrap(), 1);
        sim.call(&mut c, "read_burst", &[0x40u64.into(), 3u64.into()])
            .unwrap();
        assert_eq!(sim.call(&mut c, "idle", &[]).unwrap().as_u64().unwrap(), 0);

        sim.clock(&mut c).unwrap(); // launch the AR address phase
        assert_eq!(sim.get("axi.arvalid").as_u64().unwrap(), 1);
        assert_eq!(sim.get("axi.araddr").as_u64().unwrap(), 0x40);
        assert_eq!(sim.get("axi.arlen").as_u64().unwrap(), 3);
        assert_eq!(sim.get("axi.arburst").as_u64().unwrap(), 1); // INCR
    }

    #[test]
    fn exclusive_ops_drive_the_lock_lines() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4Master>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "exclusive_read", &[0x40u64.into()])
            .unwrap();
        sim.clock(&mut c).unwrap(); // AR phase
        assert_eq!(sim.get("axi.arvalid").as_u64().unwrap(), 1);
        assert_eq!(sim.get("axi.arlock").as_u64().unwrap(), 1);

        sim.call(
            &mut c,
            "exclusive_write",
            &[0x40u64.into(), 0xabcdu64.into()],
        )
        .unwrap();
        sim.clock(&mut c).unwrap(); // AW phase
        assert_eq!(sim.get("axi.awvalid").as_u64().unwrap(), 1);
        assert_eq!(sim.get("axi.awlock").as_u64().unwrap(), 1);
    }

    #[test]
    fn two_reads_use_distinct_ids() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi4Master>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "read_burst", &[0x0u64.into(), 0u64.into()])
            .unwrap();
        sim.call(&mut c, "read_burst", &[0x10u64.into(), 0u64.into()])
            .unwrap();
        sim.clock(&mut c).unwrap(); // AR1 presented
        let id0 = sim.get("axi.arid").as_u64().unwrap();
        sim.set("axi.arready", 1u64);
        sim.clock(&mut c).unwrap(); // AR1 accepted, AR2 presented next
        sim.set("axi.arready", 0u64);
        sim.clock(&mut c).unwrap();
        let id1 = sim.get("axi.arid").as_u64().unwrap();
        assert_ne!(id0, id1, "concurrent reads must use distinct IDs");
    }

    #[test]
    fn a_read_does_not_alias_a_live_write_id() {
        // 1-bit ID space: a shared free-running counter would let the read
        // shift the second write onto the still-live first write's ID.
        let mut sim = master_sim_cfg(32, 1).param("MAX_OUTSTANDING", 2u64);
        let mut c = sim.build::<Axi4Master>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "write", &[0x10u64.into(), 0x1111u64.into()])
            .unwrap();
        sim.call(&mut c, "read_burst", &[0x0u64.into(), 0u64.into()])
            .unwrap();
        sim.clock(&mut c).unwrap(); // AW1 and AR1 presented together
        let w1 = sim.get("axi.awid").as_u64().unwrap();
        // Accept AW1/AR1; leave the read (no R) and write1's B pending, so
        // write1's ID stays live in the outstanding set.
        sim.set("axi.awready", 1u64);
        sim.set("axi.arready", 1u64);
        sim.set("axi.wready", 1u64);
        sim.clock(&mut c).unwrap(); // AW1 accepted -> W phase; AR1 accepted
        sim.set("axi.awready", 0u64);
        sim.set("axi.arready", 0u64);
        sim.call(&mut c, "write", &[0x20u64.into(), 0x2222u64.into()])
            .unwrap();
        sim.clock(&mut c).unwrap(); // W1 beat done -> write1 live; AW2 presented
        let w2 = sim.get("axi.awid").as_u64().unwrap();
        assert_ne!(w1, w2, "second write reused a live write ID");
    }

    #[test]
    fn address_wider_than_64_bits_is_rejected() {
        let mut sim = master_sim_cfg(96, 4);
        let err = sim.build::<Axi4Master>().err().unwrap();
        assert!(err.to_string().contains("64-bit address limit"), "{err}");
    }
}
