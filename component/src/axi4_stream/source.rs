//! Active AXI4-Stream source (transmitter).

use crate::common::{arg_words, mask_words, next_rand, stall_now, words_for};
use std::collections::VecDeque;
use veryl_component::*;

/// A queued stream beat.
#[derive(Clone, Default)]
struct Beat {
    data: Vec<u64>,
    last: bool,
}

/// Active AXI4-Stream source. Connect to the `transmitter` modport. Beats
/// queued in zero time are driven onto the bus one per accepted handshake;
/// `TLAST` marks packet boundaries. `TKEEP`/`TSTRB` are driven all-ones.
///
/// ```veryl
/// src.send(0x11);        // a beat
/// src.send_last(0x22);   // last beat of the packet
/// clk.next(10);
/// ```
///
#[derive(VerylInterface)]
#[interface(path = "$std::axi4_stream_if", modport = "transmitter")]
pub struct AxiStreamTransmitterPorts {
    tvalid: OutputPort,
    tready: InputPort,
    tdata: OutputPort,
    tstrb: OutputPort,
    tkeep: OutputPort,
    tlast: OutputPort,
    tid: OutputPort,
    tdest: OutputPort,
    tuser: OutputPort,
}

/// The `STALL` parameter randomly inserts idle cycles between beats (`TVALID`
/// itself is never dropped mid-beat, as AXI4-Stream requires).
#[derive(Component)]
#[component(kind = clocked)]
pub struct Axi4StreamSource {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; drops in-flight beats and clears the queue.
    rst: ResetPort,

    /// The AXI4-Stream bus, driven as the transmitter.
    #[interface]
    axi: AxiStreamTransmitterPorts,

    /// 0..=255 weight for randomly gapping the stream between beats.
    #[param(name = "STALL")]
    stall: Option<u64>,

    beats: VecDeque<Beat>,
    lfsr: u64,
    traffic_lfsr: u64,

    // Registered output shadow and the beat currently presented.
    t_valid: bool,
    cur: Beat,
    tr_queued: Option<TraceVar>,
}

impl Axi4StreamSource {
    fn data_words(&self) -> usize {
        words_for(self.axi.tdata.width())
    }

    fn keep_words(&self) -> usize {
        words_for((self.axi.tdata.width() / 8).max(1))
    }

    fn full_keep(&self) -> Vec<u64> {
        let bytes = (self.axi.tdata.width() / 8).max(1);
        let mut keep = vec![u64::MAX; self.keep_words()];
        mask_words(&mut keep, bytes);
        keep
    }

    fn rand_data(&mut self) -> Vec<u64> {
        let mut data = vec![0u64; self.data_words()];
        for word in data.iter_mut() {
            *word = next_rand(&mut self.traffic_lfsr);
        }
        mask_words(&mut data, self.axi.tdata.width());
        data
    }

    fn drive(&mut self, ctx: &mut SimCtx) {
        let keep = self.full_keep();
        ctx.write(self.axi.tvalid, self.t_valid);
        ctx.write_words(self.axi.tdata, &self.cur.data);
        ctx.write_words(self.axi.tstrb, &keep);
        ctx.write_words(self.axi.tkeep, &keep);
        ctx.write(self.axi.tlast, self.cur.last);
        ctx.write(self.axi.tid, 0u64);
        ctx.write(self.axi.tdest, 0u64);
        ctx.write(self.axi.tuser, 0u64);
    }
}

#[component_impl]
impl Axi4StreamSource {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        let seed = ctx.seed();
        self.lfsr = seed | 1;
        self.traffic_lfsr = seed.rotate_left(32) | 1;
        self.cur = Beat {
            data: vec![0; self.data_words()],
            last: false,
        };
        self.tr_queued = ctx.trace_var("queued", 16).ok();
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            self.beats.clear();
            self.t_valid = false;
            self.drive(ctx);
            return Ok(());
        }
        let stall = stall_now(&mut self.lfsr, self.stall);

        // Accept the presented beat, then present the next one (unless a gap
        // is injected this cycle).
        if self.t_valid && ctx.read(self.axi.tready).as_bool() {
            self.t_valid = false;
        }
        if !self.t_valid
            && !stall
            && let Some(beat) = self.beats.pop_front()
        {
            self.cur = beat;
            self.t_valid = true;
        }

        if let Some(v) = self.tr_queued {
            ctx.trace(v, self.beats.len() as u64);
        }
        self.drive(ctx);
        Ok(())
    }

    /// Queues a beat (not the last of a packet).
    fn send(&mut self, _ctx: &mut SimCtx, data: &Value) -> Result<()> {
        let data = arg_words(data, self.axi.tdata.width(), "beat data")?;
        self.beats.push_back(Beat { data, last: false });
        Ok(())
    }

    /// Queues the last beat of a packet (asserts `TLAST`).
    fn send_last(&mut self, _ctx: &mut SimCtx, data: &Value) -> Result<()> {
        let data = arg_words(data, self.axi.tdata.width(), "beat data")?;
        self.beats.push_back(Beat { data, last: true });
        Ok(())
    }

    /// Queues `count` random beats forming packets of about `packet_len`
    /// beats (a `TLAST` roughly every `packet_len`). Deterministic per seed.
    fn random_traffic(&mut self, _ctx: &mut SimCtx, count: u64, packet_len: u64) -> Result<()> {
        let len = packet_len.max(1);
        for i in 0..count {
            let data = self.rand_data();
            let last = (i + 1) % len == 0 || i + 1 == count;
            self.beats.push_back(Beat { data, last });
        }
        Ok(())
    }

    /// 1 when every queued beat has been accepted, else 0.
    fn idle(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(u64::from(self.beats.is_empty() && !self.t_valid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veryl_component::testing::MockSim;

    fn source_sim() -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .output("axi.tvalid", 1)
            .input("axi.tready", 1)
            .output("axi.tdata", 32)
            .output("axi.tstrb", 4)
            .output("axi.tkeep", 4)
            .output("axi.tlast", 1)
            .output("axi.tid", 4)
            .output("axi.tdest", 2)
            .output("axi.tuser", 5)
    }

    fn u(sim: &mut MockSim, name: &str) -> u64 {
        sim.get(name).as_u64().unwrap()
    }

    #[test]
    fn drives_beats_with_tlast() {
        let mut sim = source_sim();
        let mut c = sim.build::<Axi4StreamSource>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "send", &[0x11u64.into()]).unwrap();
        sim.call(&mut c, "send_last", &[0x22u64.into()]).unwrap();

        sim.set("axi.tready", 1u64);
        sim.clock(&mut c).unwrap(); // present first beat
        assert_eq!(u(&mut sim, "axi.tvalid"), 1);
        assert_eq!(u(&mut sim, "axi.tdata"), 0x11);
        assert_eq!(u(&mut sim, "axi.tlast"), 0);
        assert_eq!(u(&mut sim, "axi.tkeep"), 0xf);

        sim.clock(&mut c).unwrap(); // first accepted, present last beat
        assert_eq!(u(&mut sim, "axi.tdata"), 0x22);
        assert_eq!(u(&mut sim, "axi.tlast"), 1);

        sim.clock(&mut c).unwrap(); // last accepted -> idle
        assert_eq!(u(&mut sim, "axi.tvalid"), 0);
        assert_eq!(sim.call(&mut c, "idle", &[]).unwrap().as_u64().unwrap(), 1);
    }

    #[test]
    fn holds_tvalid_until_tready() {
        let mut sim = source_sim();
        let mut c = sim.build::<Axi4StreamSource>().unwrap();
        sim.set("rst", 0u64);
        sim.call(&mut c, "send", &[0x11u64.into()]).unwrap();
        sim.set("axi.tready", 0u64);
        sim.clock(&mut c).unwrap();
        sim.clock(&mut c).unwrap();
        // Still presenting the same beat while TREADY is low.
        assert_eq!(u(&mut sim, "axi.tvalid"), 1);
        assert_eq!(u(&mut sim, "axi.tdata"), 0x11);
    }
}
