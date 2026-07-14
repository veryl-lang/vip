//! AXI3 burst-aware golden memory (slave) with write-data interleaving:
//! W beats are routed to their transaction by `WID`, so several write bursts
//! can stream their data concurrently. Reads are interleaved out-of-order.

use crate::axi4::beat_addr;
use crate::common::{arg_words, data_value, resp, stall_now, words_for};
use std::collections::{HashMap, HashSet, VecDeque};
use veryl_component::*;

/// An accepted burst; write bursts keep their commit decision and response.
#[derive(Clone, Default)]
struct Burst {
    addr: u64,
    len: u64,
    size: u64,
    kind: u64,
    id: u64,
    lock: u64,
    beat: u64,
    commit: bool,
    wresp: u64,
}

#[derive(VerylInterface)]
#[interface(path = "$std::axi3_if", modport = "slave")]
pub struct Axi3SlavePorts {
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
    wid: InputPort,
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

/// AXI3 slave memory. Connect to the `slave` modport. Unlike AXI4 it accepts
/// **interleaved write data**: each W beat carries a `WID` that selects which
/// outstanding write burst it belongs to, so up to `MAX_OUTSTANDING` writes
/// can stream concurrently. It keeps an exclusive-access monitor (2-bit
/// `AxLOCK`, `0b01` = exclusive), interleaves reads out-of-order, and answers
/// `DECERR` past `SIZE` or an injected `SLVERR`/`DECERR` (`set_resp`).
#[derive(Component)]
#[component(kind = clocked)]
pub struct Axi3Ram {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; clears in-flight bursts but keeps memory.
    rst: ResetPort,

    /// The AXI3 bus, answered as a slave.
    #[interface]
    axi: Axi3SlavePorts,

    /// 0..=255 weight for randomly dropping the ready outputs.
    #[param(name = "STALL")]
    stall: Option<u64>,
    /// Concurrent writes / reads / buffered responses; unset means 4.
    #[param(name = "MAX_OUTSTANDING")]
    max_outstanding: Option<u64>,
    /// Memory size in bytes; accesses at or above it answer DECERR. Unset
    /// means unbounded.
    #[param(name = "SIZE")]
    size_limit: Option<u64>,

    mem: HashMap<u64, Vec<u64>>,
    lfsr: u64,
    reserved: HashSet<u64>,
    // Injected error responses, keyed by aligned address (SLVERR / DECERR).
    err: HashMap<u64, u64>,

    // Write side: bursts awaiting data, keyed by ID; W beats route by WID.
    // One burst per ID is modelled, so two write bursts with the same AWID may
    // not be outstanding at once (the paired master issues distinct IDs).
    writes: HashMap<u64, Burst>,
    b_queue: VecDeque<(u64, u64)>,
    aw_ready: bool,
    w_ready: bool,
    b_valid: bool,

    // Read side: concurrent reads, whose beats are round-robin interleaved.
    reads: VecDeque<Burst>,
    ar_ready: bool,
    r_valid: bool,
    r_data: Vec<u64>,
    r_id: u64,
    r_resp: u64,
    r_last: bool,
}

impl Axi3Ram {
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
}

#[component_impl]
impl Axi3Ram {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        // Addresses are read as u64; a wider address bus would be silently
        // truncated.
        for (name, w) in [
            ("awaddr", self.axi.awaddr.width()),
            ("araddr", self.axi.araddr.width()),
        ] {
            if w > 64 {
                bail!("axi3_ram: {name} width {w} exceeds the 64-bit address limit");
            }
        }
        self.lfsr = ctx.seed() | 1;
        self.r_data = vec![0; self.data_words()];
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            self.writes.clear();
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

        // --- write engine (data interleaved, routed by WID) ---
        if ctx.read(self.axi.awvalid).as_bool() && aw_r {
            let id = ctx.read_u64(self.axi.awid);
            let mut req = Burst {
                addr: ctx.read_u64(self.axi.awaddr),
                len: ctx.read_u64(self.axi.awlen),
                size: 1 << ctx.read_u64(self.axi.awsize),
                kind: ctx.read_u64(self.axi.awburst),
                id,
                lock: ctx.read_u64(self.axi.awlock),
                ..Default::default()
            };
            let base = self.align(req.addr);
            if req.lock == 1 {
                req.commit = self.reserved.remove(&base);
                req.wresp = if req.commit { resp::EXOKAY } else { resp::OKAY };
            } else {
                self.reserved.remove(&base);
                req.commit = true;
                req.wresp = resp::OKAY;
            }
            self.writes.insert(id, req);
        }
        if ctx.read(self.axi.wvalid).as_bool() && w_r {
            let wid = ctx.read_u64(self.axi.wid);
            let mut data = vec![0u64; self.data_words()];
            ctx.read_words(self.axi.wdata, &mut data);
            let mut strb = vec![0u64; words_for(self.data_bytes() as u32)];
            ctx.read_words(self.axi.wstrb, &mut strb);
            let last = ctx.read(self.axi.wlast).as_bool();
            if let Some(mut req) = self.writes.remove(&wid) {
                let addr = beat_addr(req.addr, req.size, req.kind, req.len, req.beat);
                let err = self.resp_for(addr);
                if req.commit && err == resp::OKAY {
                    self.write_mem(addr, &data, &strb);
                }
                req.wresp = req.wresp.max(err);
                req.beat += 1;
                if last {
                    self.b_queue.push_back((req.id, req.wresp));
                } else {
                    self.writes.insert(wid, req);
                }
            }
        }
        if ctx.read(self.axi.bready).as_bool() && b_v {
            self.b_queue.pop_front();
        }
        self.aw_ready = self.writes.len() < max && self.b_queue.len() < max && !stall;
        self.w_ready = !self.writes.is_empty() && !stall;
        self.b_valid = !self.b_queue.is_empty();
        let (b_id, b_resp) = self.b_queue.front().copied().unwrap_or((0, resp::OKAY));

        // --- read engine (interleaved) ---
        if ctx.read(self.axi.arvalid).as_bool() && ar_r {
            let req = Burst {
                addr: ctx.read_u64(self.axi.araddr),
                len: ctx.read_u64(self.axi.arlen),
                size: 1 << ctx.read_u64(self.axi.arsize),
                kind: ctx.read_u64(self.axi.arburst),
                id: ctx.read_u64(self.axi.arid),
                lock: ctx.read_u64(self.axi.arlock),
                ..Default::default()
            };
            if req.lock == 1 {
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
            let err = self.resp_for(addr);
            self.r_resp = if err != resp::OKAY {
                err
            } else if lock == 1 {
                resp::EXOKAY
            } else {
                resp::OKAY
            };
            self.r_last = last;
        }

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
            .input("axi.awlen", 4)
            .input("axi.awsize", 3)
            .input("axi.awburst", 2)
            .input("axi.awid", 4)
            .input("axi.awlock", 2)
            .input("axi.wvalid", 1)
            .output("axi.wready", 1)
            .input("axi.wdata", 32)
            .input("axi.wstrb", 4)
            .input("axi.wlast", 1)
            .input("axi.wid", 4)
            .output("axi.bvalid", 1)
            .input("axi.bready", 1)
            .output("axi.bresp", 2)
            .output("axi.bid", 4)
            .input("axi.arvalid", 1)
            .output("axi.arready", 1)
            .input("axi.araddr", 32)
            .input("axi.arlen", 4)
            .input("axi.arsize", 3)
            .input("axi.arburst", 2)
            .input("axi.arid", 4)
            .input("axi.arlock", 2)
            .output("axi.rvalid", 1)
            .input("axi.rready", 1)
            .output("axi.rdata", 32)
            .output("axi.rresp", 2)
            .output("axi.rid", 4)
            .output("axi.rlast", 1)
    }

    /// Drives one W beat with the given WID; returns whether WREADY was high.
    fn w_beat(sim: &mut MockSim, c: &mut Axi3Ram, wid: u64, data: u64, last: bool) -> bool {
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wid", wid);
        sim.set("axi.wdata", data);
        sim.set("axi.wstrb", 0xfu64);
        sim.set("axi.wlast", u64::from(last));
        let ready = sim.get("axi.wready").as_u64().unwrap() == 1;
        sim.clock(c).unwrap();
        sim.set("axi.wvalid", 0u64);
        ready
    }

    /// Presents an AW address phase and clocks until it is accepted.
    fn aw(sim: &mut MockSim, c: &mut Axi3Ram, id: u64, addr: u64, len: u64) {
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awid", id);
        sim.set("axi.awaddr", addr);
        sim.set("axi.awlen", len);
        sim.set("axi.awsize", 2u64);
        sim.set("axi.awburst", 1u64);
        for _ in 0..10 {
            let hs = sim.get("axi.awready").as_u64().unwrap() == 1;
            sim.clock(c).unwrap();
            if hs {
                break;
            }
        }
        sim.set("axi.awvalid", 0u64);
    }

    #[test]
    fn interleaved_write_data_routes_by_wid() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi3Ram>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.bready", 1u64);

        // Two concurrent 2-beat writes, IDs 1 (@0x40) and 2 (@0x80).
        aw(&mut sim, &mut c, 1, 0x40, 1);
        aw(&mut sim, &mut c, 2, 0x80, 1);

        // Interleave their beats by WID: 1.0, 2.0, 1.1(last), 2.1(last).
        assert!(w_beat(&mut sim, &mut c, 1, 0xa0, false));
        assert!(w_beat(&mut sim, &mut c, 2, 0xb0, false));
        assert!(w_beat(&mut sim, &mut c, 1, 0xa1, true));
        assert!(w_beat(&mut sim, &mut c, 2, 0xb1, true));

        assert_eq!(peek(&mut sim, &mut c, 0x40), 0xa0);
        assert_eq!(peek(&mut sim, &mut c, 0x44), 0xa1);
        assert_eq!(peek(&mut sim, &mut c, 0x80), 0xb0);
        assert_eq!(peek(&mut sim, &mut c, 0x84), 0xb1);
    }

    fn peek(sim: &mut MockSim, c: &mut Axi3Ram, addr: u64) -> u64 {
        sim.call(c, "peek", &[addr.into()])
            .unwrap()
            .as_u64()
            .unwrap()
    }

    #[test]
    fn backdoor_poke_peek() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi3Ram>().unwrap();
        sim.call(&mut c, "poke", &[0x40u64.into(), 0x1234u64.into()])
            .unwrap();
        assert_eq!(peek(&mut sim, &mut c, 0x40), 0x1234);
    }

    #[test]
    fn injected_slverr_write_does_not_land() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi3Ram>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.bready", 1u64);
        sim.call(&mut c, "set_resp", &[0x40u64.into(), resp::SLVERR.into()])
            .unwrap();
        aw(&mut sim, &mut c, 1, 0x40, 0);
        let mut bresp = 0;
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wid", 1u64);
        sim.set("axi.wdata", 0xbadu64);
        sim.set("axi.wstrb", 0xfu64);
        sim.set("axi.wlast", 1u64);
        for _ in 0..10 {
            let w_hs = sim.get("axi.wready").as_u64().unwrap() == 1;
            sim.clock(&mut c).unwrap();
            if w_hs {
                sim.set("axi.wvalid", 0u64);
            }
            if sim.get("axi.bvalid").as_u64().unwrap() == 1 {
                bresp = sim.get("axi.bresp").as_u64().unwrap();
                break;
            }
        }
        assert_eq!(bresp, resp::SLVERR);
        assert_eq!(peek(&mut sim, &mut c, 0x40), 0);
    }

    #[test]
    fn decerr_past_size_on_read() {
        let mut sim = ram_sim().param("SIZE", 0x100u64);
        let mut c = sim.build::<Axi3Ram>().unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.rready", 1u64);
        sim.set("axi.arvalid", 1u64);
        sim.set("axi.arid", 1u64);
        sim.set("axi.araddr", 0x200u64);
        sim.set("axi.arlen", 0u64);
        sim.set("axi.arsize", 2u64);
        sim.set("axi.arburst", 1u64);
        let mut rresp = 0;
        let mut ar_done = false;
        for _ in 0..10 {
            let ar_hs = !ar_done && sim.get("axi.arready").as_u64().unwrap() == 1;
            let r_hs = sim.get("axi.rvalid").as_u64().unwrap() == 1;
            sim.clock(&mut c).unwrap();
            if ar_hs {
                ar_done = true;
                sim.set("axi.arvalid", 0u64);
            }
            if r_hs {
                rresp = sim.get("axi.rresp").as_u64().unwrap();
                break;
            }
        }
        assert_eq!(rresp, resp::DECERR);
    }
}
