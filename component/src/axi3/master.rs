//! Active AXI3 master: issues bursts with IDs and **interleaves write data**
//! by driving `WID` per beat, round-robin across the outstanding writes.

use crate::axi4::{beat_addr, burst};
use crate::common::{
    arg_words, data_value, fail_at, mask_words, next_rand, resp, stall_now, words_for,
};
use std::collections::{HashMap, HashSet, VecDeque};
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

/// A write whose AW has been accepted and whose beats are streaming.
#[derive(Clone, Default)]
struct Work {
    id: u64,
    beat: u64,
    op: WriteOp,
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
#[interface(path = "$std::axi3_if", modport = "master")]
pub struct Axi3MasterPorts {
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
    wid: OutputPort,
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

/// Active AXI3 master. Connect to the `master` modport. It issues up to
/// `MAX_OUTSTANDING` write bursts with distinct IDs and interleaves their W
/// beats by driving `WID`, exercising a slave's write-data-interleaving path
/// (the AXI3-only feature dropped in AXI4). Reads pipeline out-of-order by ID
/// and are self-checked. `exclusive_read` / `exclusive_write` drive the 2-bit
/// `AxLOCK` and `exclusive_ok` reports the last exclusive write's outcome.
#[derive(Component)]
#[component(kind = clocked)]
pub struct Axi3Master {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; drops in-flight bursts and clears the queues.
    rst: ResetPort,

    /// The AXI3 bus, driven as master.
    #[interface]
    axi: Axi3MasterPorts,

    /// 0..=255 weight for randomly delaying BREADY/RREADY.
    #[param(name = "STALL")]
    stall: Option<u64>,
    /// Maximum outstanding transactions per direction; unset means 4.
    #[param(name = "MAX_OUTSTANDING")]
    max_outstanding: Option<u64>,

    w_queue: VecDeque<WriteOp>,
    active: VecDeque<Work>,
    r_queue: VecDeque<ReadOp>,
    b_out: HashMap<u64, (bool, u64)>,
    r_out: HashMap<u64, ReadOp>,
    reads: VecDeque<Vec<u64>>,
    shadow: HashMap<u64, Vec<u64>>,
    // Addresses written by more than one burst: with W data interleaved by WID
    // the surviving value is order-dependent, so verify_all skips them.
    ambiguous: HashSet<u64>,
    last_bresp: u64,
    last_excl_ok: bool,
    lfsr: u64,
    traffic_lfsr: u64,

    cur_aw: Option<Work>,
    ar_active: bool,
    ar_id: u64,
    cur_ar: ReadOp,

    aw_valid: bool,
    w_valid: bool,
    b_ready: bool,
    ar_valid: bool,
    r_ready: bool,
}

impl Axi3Master {
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

    /// A live write is either streaming in `active` or awaiting B in `b_out`.
    /// Allocating a free ID (not a running counter) keeps two live writes off
    /// the same `WID`; the build check guarantees a free ID exists.
    fn next_write_id(&self) -> u64 {
        (0..=self.id_mask())
            .find(|id| !self.b_out.contains_key(id) && !self.active.iter().any(|w| w.id == *id))
            .unwrap_or(0)
    }

    /// Read IDs are pooled apart from writes, so a read never takes a live
    /// write's ID.
    fn next_read_id(&self) -> u64 {
        (0..=self.id_mask())
            .find(|id| !self.r_out.contains_key(id))
            .unwrap_or(0)
    }

    /// A repeat write to an address makes its interleaved value order-dependent,
    /// so mark it for `verify_all` to skip.
    fn record_shadow(&mut self, addr: u64, data: Vec<u64>) {
        if self.shadow.insert(addr, data).is_some() {
            self.ambiguous.insert(addr);
        }
    }

    fn full_strb(&self) -> Vec<u64> {
        let bytes = self.data_bytes() as u32;
        let mut strb = vec![u64::MAX; words_for(bytes)];
        mask_words(&mut strb, bytes);
        strb
    }

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

    /// WID, data, strobe and WLAST of the beat currently presented on W.
    fn w_front(&self) -> (u64, Vec<u64>, Vec<u64>, bool) {
        match self.active.front() {
            Some(f) => {
                let data =
                    f.op.data
                        .get(f.beat as usize)
                        .cloned()
                        .unwrap_or_else(|| vec![0u64; self.data_words()]);
                let strb =
                    f.op.strb
                        .get(f.beat as usize)
                        .cloned()
                        .unwrap_or_else(|| self.full_strb());
                (f.id, data, strb, f.beat == f.op.len)
            }
            None => (0, vec![0u64; self.data_words()], self.full_strb(), false),
        }
    }

    fn reset_state(&mut self) {
        self.w_queue.clear();
        self.active.clear();
        self.r_queue.clear();
        self.b_out.clear();
        self.r_out.clear();
        self.reads.clear();
        self.shadow.clear();
        self.ambiguous.clear();
        self.cur_aw = None;
        self.ar_active = false;
        self.aw_valid = false;
        self.w_valid = false;
        self.b_ready = false;
        self.ar_valid = false;
        self.r_ready = false;
    }

    fn drive(&mut self, ctx: &mut SimCtx) {
        let (wid, wdata, wstrb, wlast) = self.w_front();
        let aw = self.cur_aw.clone().unwrap_or_default();
        ctx.write(self.axi.awvalid, self.aw_valid);
        ctx.write(self.axi.awaddr, aw.op.addr);
        ctx.write(self.axi.awlen, aw.op.len);
        ctx.write(self.axi.awsize, aw.op.size_log);
        ctx.write(self.axi.awburst, aw.op.kind);
        ctx.write(self.axi.awid, aw.id);
        ctx.write(self.axi.awlock, aw.op.lock);
        ctx.write(self.axi.wvalid, self.w_valid);
        ctx.write_words(self.axi.wdata, &wdata);
        ctx.write_words(self.axi.wstrb, &wstrb);
        ctx.write(self.axi.wlast, wlast);
        ctx.write(self.axi.wid, wid);
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
impl Axi3Master {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        // Addresses are driven from u64; a wider bus's high bits would be
        // silently dropped.
        for (name, w) in [
            ("awaddr", self.axi.awaddr.width()),
            ("araddr", self.axi.araddr.width()),
        ] {
            if w > 64 {
                bail!("axi3_master: {name} width {w} exceeds the 64-bit address limit");
            }
        }
        let seed = ctx.seed();
        self.lfsr = seed | 1;
        self.traffic_lfsr = seed.rotate_left(32) | 1;
        // More outstanding per direction than the ID space holds would leave
        // no free ID for next_write_id/next_read_id to pick.
        let id_space = 1u64.checked_shl(self.axi.awid.width()).unwrap_or(u64::MAX);
        if self.max() as u64 > id_space {
            return Err(anyhow!(
                "axi3_master: MAX_OUTSTANDING ({}) exceeds the {}-bit ID space ({id_space})",
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

        // --- write engine (AW in order, W data interleaved by WID) ---
        if aw_v
            && ctx.read(self.axi.awready).as_bool()
            && let Some(work) = self.cur_aw.take()
        {
            self.active.push_back(work);
        }
        if w_v
            && ctx.read(self.axi.wready).as_bool()
            && let Some(mut front) = self.active.pop_front()
        {
            front.beat += 1;
            if front.beat > front.op.len {
                self.b_out
                    .insert(front.id, (front.op.expect_ok, front.op.lock));
            } else {
                // Rotate to the back so the next beat serves another write.
                self.active.push_back(front);
            }
        }
        if b_r && ctx.read(self.axi.bvalid).as_bool() {
            let id = ctx.read_u64(self.axi.bid);
            match self.b_out.remove(&id) {
                Some((expect_ok, lock)) => {
                    self.last_bresp = ctx.read_u64(self.axi.bresp);
                    if lock == 1 {
                        self.last_excl_ok = self.last_bresp == resp::EXOKAY;
                    } else if expect_ok && self.last_bresp != 0 {
                        fail_at(
                            ctx,
                            format!("AXI3 write id {id}: response {}", self.last_bresp),
                        );
                    }
                }
                None => fail_at(ctx, format!("AXI3 B: unexpected BID {id}")),
            }
        }
        if self.cur_aw.is_none()
            && self.active.len() + self.b_out.len() < max
            && let Some(op) = self.w_queue.pop_front()
        {
            self.cur_aw = Some(Work {
                id: self.next_write_id(),
                beat: 0,
                op,
            });
        }
        self.aw_valid = self.cur_aw.is_some();
        self.w_valid = !self.active.is_empty();
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
                fail_at(ctx, format!("AXI3 R: unexpected RID {rid}"));
            }
            if last_bad {
                fail_at(ctx, format!("AXI3 read id {rid}: RLAST misaligned"));
            }
            if data_bad {
                fail_at(ctx, format!("AXI3 read id {rid}: data mismatch"));
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

    /// Queues a burst write whose beat values equal their addresses, recording
    /// them for `verify_all`. Queue several to see their W data interleave.
    fn burst_write_fill(&mut self, _ctx: &mut SimCtx, addr: u64, len: u64) -> Result<()> {
        if len > 15 {
            bail!(
                "axi3_master: burst length {} exceeds the 16-beat limit",
                len + 1
            );
        }
        let bytes = self.data_bytes();
        let size_log = self.size_log();
        let full = self.full_strb();
        let mut data = Vec::new();
        let mut strb = Vec::new();
        for n in 0..=len {
            let a = beat_addr(addr, bytes, burst::INCR, len, n);
            let d = self.scalar_words(a);
            self.record_shadow(a, d.clone());
            data.push(d);
            strb.push(full.clone());
        }
        self.w_queue.push_back(WriteOp {
            addr,
            len,
            size_log,
            kind: burst::INCR,
            lock: 0,
            data,
            strb,
            expect_ok: true,
        });
        Ok(())
    }

    /// Queues `count` random INCR burst writes (lengths up to `max_len`, capped
    /// at the AXI3 16-beat limit) into a `2^addr_bits`-byte window.
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
        let max_len = max_len.min(15);
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
                self.record_shadow(beat_addr(base, bytes, burst::INCR, len, n), d.clone());
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

    /// Queues a single-beat checked read of every written address. Returns how
    /// many; a read-back mismatch fails the test.
    fn verify_all(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        let mut entries: Vec<(u64, Vec<u64>)> = self
            .shadow
            .iter()
            .filter(|(a, _)| !self.ambiguous.contains(a))
            .map(|(&a, d)| (a, d.clone()))
            .collect();
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

    /// Queues an INCR burst read of `len + 1` beats; drain with `pop_read`.
    fn read_burst(&mut self, _ctx: &mut SimCtx, addr: u64, len: u64) -> Result<()> {
        if len > 15 {
            bail!(
                "axi3_master: burst length {} exceeds the 16-beat limit",
                len + 1
            );
        }
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

    /// Queues a single-beat exclusive read of `addr` (2-bit `ARLOCK` = 0b01).
    /// Its data drains through `pop_read` like any other read, sharing the same
    /// FIFO — pop it before issuing later reads if you need the value.
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

    /// Queues a single-beat exclusive write of `data` to `addr` (`AWLOCK` =
    /// 0b01); check the outcome with `exclusive_ok` once it has drained.
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

    /// 1 when every queued and in-flight transaction has completed, else 0.
    fn idle(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        let busy = !self.w_queue.is_empty()
            || !self.r_queue.is_empty()
            || self.cur_aw.is_some()
            || !self.active.is_empty()
            || self.ar_active
            || !self.b_out.is_empty()
            || !self.r_out.is_empty();
        Ok(u64::from(!busy))
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
            .output("axi.awlen", 4)
            .output("axi.awsize", 3)
            .output("axi.awburst", 2)
            .output("axi.awid", id_w)
            .output("axi.awlock", 2)
            .output("axi.wvalid", 1)
            .input("axi.wready", 1)
            .output("axi.wdata", 32)
            .output("axi.wstrb", 4)
            .output("axi.wlast", 1)
            .output("axi.wid", id_w)
            .input("axi.bvalid", 1)
            .output("axi.bready", 1)
            .input("axi.bresp", 2)
            .input("axi.bid", id_w)
            .output("axi.arvalid", 1)
            .input("axi.arready", 1)
            .output("axi.araddr", addr_w)
            .output("axi.arlen", 4)
            .output("axi.arsize", 3)
            .output("axi.arburst", 2)
            .output("axi.arid", id_w)
            .output("axi.arlock", 2)
            .input("axi.rvalid", 1)
            .output("axi.rready", 1)
            .input("axi.rdata", 32)
            .input("axi.rid", id_w)
            .input("axi.rlast", 1)
    }

    #[test]
    fn two_writes_interleave_their_beats_by_wid() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi3Master>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awready", 1u64);
        sim.set("axi.wready", 1u64);
        sim.call(&mut c, "burst_write_fill", &[0x40u64.into(), 1u64.into()])
            .unwrap();
        sim.call(&mut c, "burst_write_fill", &[0x80u64.into(), 1u64.into()])
            .unwrap();

        // Collect the (WID, WLAST) of each accepted W beat.
        let mut seen: Vec<(u64, u64)> = Vec::new();
        for _ in 0..12 {
            if sim.get("axi.wvalid").as_u64().unwrap() == 1 {
                seen.push((
                    sim.get("axi.wid").as_u64().unwrap(),
                    sim.get("axi.wlast").as_u64().unwrap(),
                ));
            }
            sim.clock(&mut c).unwrap();
            if sim.call(&mut c, "idle", &[]).unwrap().as_u64().unwrap() == 1 {
                break;
            }
        }
        // Two distinct WIDs appear and the second beat interleaves the first.
        let ids: std::collections::HashSet<u64> = seen.iter().map(|(w, _)| *w).collect();
        assert_eq!(ids.len(), 2, "both write IDs drive W beats: {seen:?}");
        assert!(
            seen.len() >= 2 && seen[0].0 != seen[1].0,
            "beats interleave across IDs: {seen:?}"
        );
    }

    #[test]
    fn exclusive_read_drives_2bit_lock() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi3Master>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "exclusive_read", &[0x40u64.into()])
            .unwrap();
        sim.clock(&mut c).unwrap();
        assert_eq!(sim.get("axi.arvalid").as_u64().unwrap(), 1);
        assert_eq!(sim.get("axi.arlock").as_u64().unwrap(), 1); // 0b01
    }

    #[test]
    fn a_read_does_not_alias_a_live_write_id() {
        // 1-bit ID space: a shared free-running counter would let the read
        // shift the second write onto the still-live first write's ID.
        let mut sim = master_sim_cfg(32, 1).param("MAX_OUTSTANDING", 2u64);
        let mut c = sim.build::<Axi3Master>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "write", &[0x10u64.into(), 0x1111u64.into()])
            .unwrap();
        sim.call(&mut c, "read_burst", &[0x0u64.into(), 0u64.into()])
            .unwrap();
        sim.clock(&mut c).unwrap(); // AW1 and AR1 presented together
        let w1 = sim.get("axi.awid").as_u64().unwrap();
        sim.set("axi.awready", 1u64);
        sim.set("axi.arready", 1u64);
        sim.set("axi.wready", 1u64);
        sim.clock(&mut c).unwrap(); // AW1 accepted -> active; AR1 accepted
        sim.set("axi.awready", 0u64);
        sim.set("axi.arready", 0u64);
        sim.call(&mut c, "write", &[0x20u64.into(), 0x2222u64.into()])
            .unwrap();
        sim.clock(&mut c).unwrap(); // W1 beat done -> write1 live; AW2 presented
        let w2 = sim.get("axi.awid").as_u64().unwrap();
        assert_ne!(w1, w2, "second write reused a live write ID");
    }

    #[test]
    fn verify_all_skips_overlapping_addresses() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi3Master>().unwrap();
        sim.set("rst", 0u64);
        // Two bursts overlap at 0x44; under interleaving its surviving value is
        // order-dependent, so it is excluded from the read-back check.
        sim.call(&mut c, "burst_write_fill", &[0x40u64.into(), 1u64.into()])
            .unwrap();
        sim.call(&mut c, "burst_write_fill", &[0x44u64.into(), 1u64.into()])
            .unwrap();
        let n = sim
            .call(&mut c, "verify_all", &[])
            .unwrap()
            .as_u64()
            .unwrap();
        assert_eq!(n, 2, "overlapping address 0x44 should be skipped");
    }

    #[test]
    fn burst_length_over_16_is_rejected() {
        let mut sim = master_sim();
        let mut c = sim.build::<Axi3Master>().unwrap();
        sim.set("rst", 0u64);
        let err = sim
            .call(&mut c, "burst_write_fill", &[0x40u64.into(), 16u64.into()])
            .err()
            .unwrap();
        assert!(err.to_string().contains("16-beat limit"), "{err}");
    }

    #[test]
    fn address_wider_than_64_bits_is_rejected() {
        let mut sim = master_sim_cfg(96, 4);
        let err = sim.build::<Axi3Master>().err().unwrap();
        assert!(err.to_string().contains("64-bit address limit"), "{err}");
    }
}
