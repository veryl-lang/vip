//! AXI4-Lite slave memory model with a backdoor.

use crate::common::{arg_words, data_value, mask_words, resp, stall_now, words_for};
use std::collections::HashMap;
use veryl_component::*;

/// AXI4-Lite slave that answers reads and writes from an internal sparse
/// memory. Connect to the `slave` modport. Handshakes use registered
/// outputs (ready/valid asserted one cycle after the condition holds), so
/// it models a realistic single-outstanding slave rather than a
/// combinational one.
///
/// Parameters (`#(...)`) tune it for stress testing:
/// * `READ_LATENCY` / `WRITE_LATENCY` — extra cycles before a response,
/// * `STALL` — 0..=255 probability weight for randomly dropping READY
///   (backpressure), seeded per instance.
///
#[derive(VerylInterface)]
#[interface(path = "$std::axi4_lite_if", modport = "slave")]
pub struct Axi4LiteSlavePorts {
    awvalid: InputPort,
    awready: OutputPort,
    awaddr: InputPort,
    wvalid: InputPort,
    wready: OutputPort,
    wdata: InputPort,
    wstrb: InputPort,
    bvalid: OutputPort,
    bready: InputPort,
    bresp: OutputPort,
    arvalid: InputPort,
    arready: OutputPort,
    araddr: InputPort,
    rvalid: OutputPort,
    rready: InputPort,
    rdata: OutputPort,
    rresp: OutputPort,
}

/// Backdoor `poke`/`peek`/`load_hex`/`set_resp` methods let a testbench
/// preload memory, inspect it, and inject error responses in zero time.
#[derive(Component)]
#[component(kind = clocked, requires(file))]
pub struct Axi4LiteRam {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; clears in-flight transactions but keeps memory contents.
    rst: ResetPort,

    /// The AXI4-Lite bus, answered as a slave.
    #[interface]
    axi: Axi4LiteSlavePorts,

    /// Extra cycles before a read response.
    #[param(name = "READ_LATENCY")]
    read_latency: Option<u64>,
    /// Extra cycles before a write response.
    #[param(name = "WRITE_LATENCY")]
    write_latency: Option<u64>,
    /// 0..=255 weight for randomly dropping READY; unset means never.
    #[param(name = "STALL")]
    stall: Option<u64>,
    /// Memory size in bytes; accesses at or above it answer DECERR. Unset
    /// means unbounded.
    #[param(name = "SIZE")]
    size: Option<u64>,

    // Data is stored as LSB-first word vectors so any bus width works.
    mem: HashMap<u64, Vec<u64>>,
    err: HashMap<u64, u64>,
    // Write-protected `[start, end)` byte ranges: writes answer SLVERR.
    readonly: Vec<(u64, u64)>,
    lfsr: u64,

    // Registered output shadows and captured request state.
    aw_ready: bool,
    w_ready: bool,
    b_valid: bool,
    b_resp: u64,
    ar_ready: bool,
    r_valid: bool,
    r_data: Vec<u64>,
    r_resp: u64,
    r_addr: u64,
    have_aw: bool,
    have_w: bool,
    addr: u64,
    data: Vec<u64>,
    strb: Vec<u64>,
    write_delay: Option<u64>,
    read_delay: Option<u64>,
    // Waveform trace: bit0 = a write is in flight, bit1 = a read is.
    tr_busy: Option<TraceVar>,
}

impl Axi4LiteRam {
    fn data_bytes(&self) -> u64 {
        (self.axi.wdata.width() as u64 / 8).max(1)
    }

    fn data_words(&self) -> usize {
        words_for(self.axi.wdata.width())
    }

    fn strb_words(&self) -> usize {
        words_for(self.data_bytes() as u32)
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

    fn resp_for(&self, addr: u64) -> u64 {
        if self.size.is_some_and(|size| self.align(addr) >= size) {
            return resp::DECERR;
        }
        *self.err.get(&self.align(addr)).unwrap_or(&resp::OKAY)
    }

    /// Write response: a write-protected region answers SLVERR (reads of it
    /// still succeed), otherwise the same as a read.
    fn write_resp_for(&self, addr: u64) -> u64 {
        let base = self.resp_for(addr);
        if base != resp::OKAY {
            return base;
        }
        let a = self.align(addr);
        if self.readonly.iter().any(|(s, e)| a >= *s && a < *e) {
            resp::SLVERR
        } else {
            resp::OKAY
        }
    }

    /// Applies a strobed write, merging only the enabled bytes across words.
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
                let shift = (byte % 8) * 8;
                let mask = 0xffu64 << shift;
                word[dword] = (word[dword] & !mask) | (data[dword] & mask);
            }
        }
        self.mem.insert(key, word);
    }

    fn clear_transactions(&mut self) {
        self.aw_ready = false;
        self.w_ready = false;
        self.b_valid = false;
        self.ar_ready = false;
        self.r_valid = false;
        self.have_aw = false;
        self.have_w = false;
        self.write_delay = None;
        self.read_delay = None;
    }

    fn drive_idle(&mut self, ctx: &mut SimCtx) {
        ctx.write(self.axi.awready, false);
        ctx.write(self.axi.wready, false);
        ctx.write(self.axi.bvalid, false);
        ctx.write(self.axi.arready, false);
        ctx.write(self.axi.rvalid, false);
    }
}

#[component_impl]
impl Axi4LiteRam {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        // Addresses are read as u64; a wider address bus would be silently
        // truncated.
        for (name, w) in [
            ("awaddr", self.axi.awaddr.width()),
            ("araddr", self.axi.araddr.width()),
        ] {
            if w > 64 {
                bail!("axi4_lite_ram: {name} width {w} exceeds the 64-bit address limit");
            }
        }
        self.lfsr = ctx.seed() | 1;
        self.r_data = vec![0; self.data_words()];
        self.data = vec![0; self.data_words()];
        self.strb = vec![0; self.strb_words()];
        self.tr_busy = ctx.trace_var("busy", 2).ok();
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            self.clear_transactions();
            self.drive_idle(ctx);
            return Ok(());
        }

        let stall = stall_now(&mut self.lfsr, self.stall);

        // Sample the bus against the outputs currently on the wire.
        let aw_fire = ctx.read(self.axi.awvalid).as_bool() && self.aw_ready;
        if aw_fire {
            self.addr = ctx.read_u64(self.axi.awaddr);
            self.have_aw = true;
        }
        let w_fire = ctx.read(self.axi.wvalid).as_bool() && self.w_ready;
        if w_fire {
            ctx.read_words(self.axi.wdata, &mut self.data);
            ctx.read_words(self.axi.wstrb, &mut self.strb);
            self.have_w = true;
        }
        if ctx.read(self.axi.bready).as_bool() && self.b_valid {
            self.b_valid = false;
        }
        // Start the write once both halves are captured; respond after the
        // configured latency.
        if self.have_aw && self.have_w && !self.b_valid && self.write_delay.is_none() {
            self.write_delay = Some(self.write_latency.unwrap_or(0));
        }
        if let Some(d) = self.write_delay {
            if d == 0 {
                self.b_resp = self.write_resp_for(self.addr);
                if self.b_resp == resp::OKAY {
                    let data = self.data.clone();
                    let strb = self.strb.clone();
                    self.write_mem(self.addr, &data, &strb);
                }
                self.have_aw = false;
                self.have_w = false;
                self.b_valid = true;
                self.write_delay = None;
            } else {
                self.write_delay = Some(d - 1);
            }
        }

        let ar_fire = ctx.read(self.axi.arvalid).as_bool() && self.ar_ready;
        let ar_addr = ctx.read_u64(self.axi.araddr);
        if ctx.read(self.axi.rready).as_bool() && self.r_valid {
            self.r_valid = false;
        }
        if ar_fire && !self.r_valid && self.read_delay.is_none() {
            self.r_addr = ar_addr;
            self.read_delay = Some(self.read_latency.unwrap_or(0));
        }
        if let Some(d) = self.read_delay {
            if d == 0 {
                self.r_data = self.read_mem(self.r_addr);
                self.r_resp = self.resp_for(self.r_addr);
                self.r_valid = true;
                self.read_delay = None;
            } else {
                self.read_delay = Some(d - 1);
            }
        }

        // Compute and register the next outputs.
        self.aw_ready = !self.have_aw && !stall;
        self.w_ready = !self.have_w && !stall;
        self.ar_ready = !self.r_valid && self.read_delay.is_none() && !stall;
        ctx.write(self.axi.awready, self.aw_ready);
        ctx.write(self.axi.wready, self.w_ready);
        ctx.write(self.axi.bvalid, self.b_valid);
        ctx.write(self.axi.bresp, self.b_resp);
        ctx.write(self.axi.arready, self.ar_ready);
        ctx.write(self.axi.rvalid, self.r_valid);
        ctx.write_words(self.axi.rdata, &self.r_data);
        ctx.write(self.axi.rresp, self.r_resp);
        if let Some(v) = self.tr_busy {
            let busy = (self.have_aw || self.have_w) as u64 | ((self.r_valid as u64) << 1);
            ctx.trace(v, busy);
        }
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

    /// Makes the slave answer a given address with a response code
    /// (`0` OKAY, `2` SLVERR, `3` DECERR). OKAY clears any injected error.
    fn set_resp(&mut self, _ctx: &mut SimCtx, addr: u64, code: u64) -> Result<()> {
        let key = self.align(addr);
        if code == resp::OKAY {
            self.err.remove(&key);
        } else {
            self.err.insert(key, code);
        }
        Ok(())
    }

    /// Marks the `[start, start + len)` byte range write-protected: writes
    /// there answer SLVERR while reads still succeed (models a ROM region).
    fn set_readonly(&mut self, _ctx: &mut SimCtx, start: u64, len: u64) -> Result<()> {
        self.readonly.push((start, start.saturating_add(len)));
        Ok(())
    }

    /// Writes the memory contents (the low 64 bits of each written word) out
    /// as `addr data` hex pairs, sorted by address — the `load_hex` format.
    fn dump_hex(&mut self, ctx: &mut SimCtx, path: &str) -> Result<()> {
        use std::io::Write;
        let mut file = ctx.create(path)?;
        let mut addrs: Vec<u64> = self.mem.keys().copied().collect();
        addrs.sort_unstable();
        for addr in addrs {
            let low = self
                .mem
                .get(&addr)
                .and_then(|w| w.first().copied())
                .unwrap_or(0);
            writeln!(file, "{addr:x} {low:x}")?;
        }
        Ok(())
    }

    /// Loads `addr data` hex pairs, one per line, into memory. Lines that
    /// are blank or start with `#` are ignored.
    fn load_hex(&mut self, ctx: &mut SimCtx, path: &str) -> Result<()> {
        use std::io::Read;
        let mut text = String::new();
        ctx.open(path)?.read_to_string(&mut text)?;
        for (n, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.split_whitespace();
            let addr = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());
            let data = parts.next().and_then(|s| u64::from_str_radix(s, 16).ok());
            match (addr, data) {
                (Some(addr), Some(data)) => {
                    let key = self.align(addr);
                    let mut words = vec![0u64; self.data_words()];
                    words[0] = data;
                    mask_words(&mut words, self.axi.wdata.width());
                    self.mem.insert(key, words);
                }
                _ => bail!("{path}:{}: expected two hex fields", n + 1),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veryl_component::testing::MockSim;

    fn ram_sim() -> MockSim {
        ram_sim_addr(32)
    }

    fn ram_sim_addr(addr_w: u32) -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .input("axi.awvalid", 1)
            .output("axi.awready", 1)
            .input("axi.awaddr", addr_w)
            .input("axi.wvalid", 1)
            .output("axi.wready", 1)
            .input("axi.wdata", 32)
            .input("axi.wstrb", 4)
            .output("axi.bvalid", 1)
            .input("axi.bready", 1)
            .output("axi.bresp", 2)
            .input("axi.arvalid", 1)
            .output("axi.arready", 1)
            .input("axi.araddr", addr_w)
            .output("axi.rvalid", 1)
            .input("axi.rready", 1)
            .output("axi.rdata", 32)
            .output("axi.rresp", 2)
    }

    /// Drives a single held write and clocks until the response, returning
    /// the cycle count and the observed BRESP.
    fn run_write(sim: &mut MockSim, c: &mut Axi4LiteRam, addr: u64, data: u64) -> (u32, u64) {
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", addr);
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wdata", data);
        sim.set("axi.wstrb", 0xfu64);
        sim.set("axi.bready", 1u64);
        for cycle in 1..=40 {
            sim.clock(c).unwrap();
            if sim.get("axi.bvalid").as_u64().unwrap() == 1 {
                let bresp = sim.get("axi.bresp").as_u64().unwrap();
                sim.set("axi.awvalid", 0u64);
                sim.set("axi.wvalid", 0u64);
                return (cycle, bresp);
            }
        }
        panic!("write never responded");
    }

    #[test]
    fn backdoor_poke_and_peek() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        sim.call(&mut c, "poke", &[0x10u64.into(), 0x1234u64.into()])
            .unwrap();
        let v = sim.call(&mut c, "peek", &[0x10u64.into()]).unwrap();
        assert_eq!(v.as_u64().unwrap(), 0x1234);
    }

    #[test]
    fn bus_write_lands_in_memory() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        let (_, bresp) = run_write(&mut sim, &mut c, 0x20, 0xdeadbeef);
        assert_eq!(bresp, resp::OKAY);
        let v = sim.call(&mut c, "peek", &[0x20u64.into()]).unwrap();
        assert_eq!(v.as_u64().unwrap(), 0xdeadbeef);
    }

    #[test]
    fn partial_strobe_merges_bytes() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        sim.call(&mut c, "poke", &[0x0u64.into(), 0x1111_2222u64.into()])
            .unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x0u64);
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wdata", 0xaaaa_bbbbu64);
        sim.set("axi.wstrb", 0b0011u64);
        sim.set("axi.bready", 1u64);
        sim.clock(&mut c).unwrap();
        sim.clock(&mut c).unwrap();
        let v = sim.call(&mut c, "peek", &[0x0u64.into()]).unwrap();
        assert_eq!(v.as_u64().unwrap(), 0x1111_bbbb);
    }

    #[test]
    fn bus_read_returns_memory() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        sim.call(&mut c, "poke", &[0x30u64.into(), 0xcafeu64.into()])
            .unwrap();
        sim.set("rst", 0u64);
        sim.set("axi.arvalid", 1u64);
        sim.set("axi.araddr", 0x30u64);
        sim.set("axi.rready", 1u64);
        sim.clock(&mut c).unwrap(); // arready asserts
        sim.clock(&mut c).unwrap(); // ar handshake + data driven
        assert_eq!(sim.get("axi.rvalid").as_u64().unwrap(), 1);
        assert_eq!(sim.get("axi.rdata").as_u64().unwrap(), 0xcafe);
        assert_eq!(sim.get("axi.rresp").as_u64().unwrap(), resp::OKAY);
    }

    #[test]
    fn write_latency_delays_the_response() {
        let mut sim = ram_sim().param("WRITE_LATENCY", 3u64);
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        let (fast_cycle, _) = {
            let mut base = ram_sim();
            let mut bc = base.build::<Axi4LiteRam>().unwrap();
            run_write(&mut base, &mut bc, 0x20, 0x1)
        };
        let (slow_cycle, _) = run_write(&mut sim, &mut c, 0x20, 0x1);
        assert_eq!(slow_cycle, fast_cycle + 3, "latency should add 3 cycles");
    }

    #[test]
    fn injected_error_response() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        sim.call(&mut c, "set_resp", &[0x20u64.into(), resp::SLVERR.into()])
            .unwrap();
        let (_, bresp) = run_write(&mut sim, &mut c, 0x20, 0x1);
        assert_eq!(bresp, resp::SLVERR);
    }

    #[test]
    fn out_of_range_access_decerrs() {
        let mut sim = ram_sim().param("SIZE", 0x100u64);
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        // A write beyond SIZE returns DECERR and does not land in memory.
        let (_, bresp) = run_write(&mut sim, &mut c, 0x200, 0x1);
        assert_eq!(bresp, resp::DECERR);
        assert_eq!(
            sim.call(&mut c, "peek", &[0x200u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0
        );
        // A read beyond SIZE also returns DECERR.
        sim.set("axi.awvalid", 0u64);
        sim.set("axi.wvalid", 0u64);
        sim.set("axi.arvalid", 1u64);
        sim.set("axi.araddr", 0x200u64);
        sim.set("axi.rready", 1u64);
        for _ in 0..8 {
            sim.clock(&mut c).unwrap();
            if sim.get("axi.rvalid").as_u64().unwrap() == 1 {
                break;
            }
        }
        assert_eq!(sim.get("axi.rresp").as_u64().unwrap(), resp::DECERR);
    }

    #[test]
    fn write_completes_under_backpressure() {
        let mut sim = ram_sim().param("STALL", 200u64);
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        let (_, bresp) = run_write(&mut sim, &mut c, 0x20, 0xbeef);
        assert_eq!(bresp, resp::OKAY);
        let v = sim.call(&mut c, "peek", &[0x20u64.into()]).unwrap();
        assert_eq!(v.as_u64().unwrap(), 0xbeef);
    }

    #[test]
    fn load_hex_populates_memory() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        let path = std::env::temp_dir().join("axi4_lite_ram_load_hex.hex");
        std::fs::write(&path, "# preload\n40 aa\n44 bb\n\n").unwrap();
        sim.call(&mut c, "load_hex", &[Value::from(path.to_str().unwrap())])
            .unwrap();
        assert_eq!(
            sim.call(&mut c, "peek", &[0x40u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0xaa
        );
        assert_eq!(
            sim.call(&mut c, "peek", &[0x44u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0xbb
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn readonly_region_rejects_writes() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        sim.call(&mut c, "poke", &[0x40u64.into(), 0x1234u64.into()])
            .unwrap();
        sim.call(&mut c, "set_readonly", &[0x40u64.into(), 0x10u64.into()])
            .unwrap();
        let (_, bresp) = run_write(&mut sim, &mut c, 0x40, 0xdead);
        assert_eq!(bresp, resp::SLVERR);
        // The protected word keeps its original value; reads still work.
        assert_eq!(
            sim.call(&mut c, "peek", &[0x40u64.into()])
                .unwrap()
                .as_u64()
                .unwrap(),
            0x1234
        );
    }

    #[test]
    fn dump_hex_writes_memory() {
        let mut sim = ram_sim();
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        sim.call(&mut c, "poke", &[0x40u64.into(), 0xaau64.into()])
            .unwrap();
        sim.call(&mut c, "poke", &[0x44u64.into(), 0xbbu64.into()])
            .unwrap();
        let path = std::env::temp_dir().join("axi4_lite_ram_dump.hex");
        sim.call(&mut c, "dump_hex", &[Value::from(path.to_str().unwrap())])
            .unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("40 aa"), "{text}");
        assert!(text.contains("44 bb"), "{text}");
        std::fs::remove_file(&path).ok();
    }

    /// A two-state bits value from LSB-first words.
    fn wide(words: &[u64], width: u32) -> Value {
        Value::from_bits(
            words.iter().copied().collect(),
            words.iter().map(|_| 0u64).collect(),
            width,
        )
    }

    #[test]
    fn wide_data_roundtrips_over_the_bus() {
        // A 128-bit data bus, wider than a u64.
        let mut sim = MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .input("axi.awvalid", 1)
            .output("axi.awready", 1)
            .input("axi.awaddr", 32)
            .input("axi.wvalid", 1)
            .output("axi.wready", 1)
            .input("axi.wdata", 128)
            .input("axi.wstrb", 16)
            .output("axi.bvalid", 1)
            .input("axi.bready", 1)
            .output("axi.bresp", 2)
            .input("axi.arvalid", 1)
            .output("axi.arready", 1)
            .input("axi.araddr", 32)
            .output("axi.rvalid", 1)
            .input("axi.rready", 1)
            .output("axi.rdata", 128)
            .output("axi.rresp", 2);
        let mut c = sim.build::<Axi4LiteRam>().unwrap();
        sim.set("rst", 0u64);

        let value = wide(&[0xdead_beef_cafe_f00d, 0x0123_4567_89ab_cdef], 128);
        sim.set("axi.awvalid", 1u64);
        sim.set("axi.awaddr", 0x20u64);
        sim.set("axi.wvalid", 1u64);
        sim.set("axi.wdata", value.clone());
        sim.set("axi.wstrb", 0xffffu64);
        sim.set("axi.bready", 1u64);
        sim.clock(&mut c).unwrap();
        sim.clock(&mut c).unwrap();
        sim.set("axi.awvalid", 0u64);
        sim.set("axi.wvalid", 0u64);
        sim.clock(&mut c).unwrap();

        sim.set("axi.arvalid", 1u64);
        sim.set("axi.araddr", 0x20u64);
        sim.set("axi.rready", 1u64);
        for _ in 0..6 {
            sim.clock(&mut c).unwrap();
            if sim.get("axi.rvalid").as_u64().unwrap() == 1 {
                break;
            }
        }
        assert_eq!(sim.get("axi.rdata"), value);
    }

    #[test]
    fn address_wider_than_64_bits_is_rejected() {
        let mut sim = ram_sim_addr(96);
        let err = sim.build::<Axi4LiteRam>().err().unwrap();
        assert!(err.to_string().contains("64-bit address limit"), "{err}");
    }
}
