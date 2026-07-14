//! Golden AXI4-Stream sink (receiver).

use crate::common::{arg_words, data_value, fail_at, stall_now, words_for};
use std::collections::VecDeque;
use veryl_component::*;

/// Golden AXI4-Stream sink. Connect to the `receiver` modport. It drives
/// `TREADY` (with optional random backpressure) and captures accepted beats.
/// `recv` drains data; `expect` turns it into a self-checking scoreboard.
///
/// ```veryl
/// snk.expect(0x11);      // fail the test if the next beat isn't 0x11
/// clk.next(10);
/// ```
///
#[derive(VerylInterface)]
#[interface(path = "$std::axi4_stream_if", modport = "receiver")]
pub struct AxiStreamReceiverPorts {
    tvalid: InputPort,
    tready: OutputPort,
    tdata: InputPort,
    tlast: InputPort,
}

/// The `STALL` parameter randomly drops `TREADY` to backpressure the source.
#[derive(Component)]
#[component(kind = clocked)]
pub struct Axi4StreamSink {
    /// Bus clock.
    clk: ClockPort,
    /// Bus reset; clears the receive and expect queues.
    rst: ResetPort,

    /// The AXI4-Stream bus, consumed as the receiver.
    #[interface]
    axi: AxiStreamReceiverPorts,

    /// 0..=255 weight for randomly dropping TREADY; unset is always ready.
    #[param(name = "STALL")]
    stall: Option<u64>,

    received: VecDeque<Vec<u64>>,
    expect: VecDeque<Vec<u64>>,
    lfsr: u64,
    beats: u64,
    packets: u64,

    // Registered TREADY shadow.
    t_ready: bool,
    tr_beats: Option<TraceVar>,
}

impl Axi4StreamSink {
    fn data_words(&self) -> usize {
        words_for(self.axi.tdata.width())
    }
}

#[component_impl]
impl Axi4StreamSink {
    fn on_build(&mut self, ctx: &mut BuildCtx) -> Result<()> {
        self.lfsr = ctx.seed() | 1;
        self.t_ready = true;
        self.tr_beats = ctx.trace_var("beats", 32).ok();
        Ok(())
    }

    fn on_clock(&mut self, ctx: &mut SimCtx) -> Result<()> {
        let _ = ctx.fired(self.clk);
        if ctx.read(self.rst).as_bool() {
            self.received.clear();
            self.expect.clear();
            self.t_ready = false;
            ctx.write(self.axi.tready, false);
            return Ok(());
        }

        // Capture a beat on the current committed TREADY.
        if self.t_ready && ctx.read(self.axi.tvalid).as_bool() {
            let mut data = vec![0u64; self.data_words()];
            ctx.read_words(self.axi.tdata, &mut data);
            self.beats += 1;
            if ctx.read(self.axi.tlast).as_bool() {
                self.packets += 1;
            }
            match self.expect.pop_front() {
                Some(want) if want != data => fail_at(
                    ctx,
                    format!(
                        "stream beat {}: expected {want:x?}, got {data:x?}",
                        self.beats
                    ),
                ),
                Some(_) => {}
                None => self.received.push_back(data),
            }
        }

        self.t_ready = !stall_now(&mut self.lfsr, self.stall);
        ctx.write(self.axi.tready, self.t_ready);
        if let Some(v) = self.tr_beats {
            ctx.trace(v, self.beats);
        }
        Ok(())
    }

    /// Pops the oldest received beat at full bus width, erroring if none.
    #[ret_width(axi.TDATA_WIDTH)]
    fn recv(&mut self, _ctx: &mut SimCtx) -> Result<Value> {
        let words = self
            .received
            .pop_front()
            .ok_or_else(|| anyhow!("no beat received"))?;
        let width = self.axi.tdata.width();
        Ok(data_value(words, width))
    }

    /// Self-checks the next received beat against `data`; a mismatch fails
    /// the test.
    fn expect(&mut self, _ctx: &mut SimCtx, data: &Value) -> Result<()> {
        let want = arg_words(data, self.axi.tdata.width(), "expected beat data")?;
        self.expect.push_back(want);
        Ok(())
    }

    /// Number of received beats not yet drained by `recv`.
    fn num_received(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(self.received.len() as u64)
    }

    /// Total beats accepted so far.
    fn beats(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(self.beats)
    }

    /// Total packets (TLAST beats) accepted so far.
    fn packets(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(self.packets)
    }

    /// 1 when no self-check is still pending, else 0.
    fn idle(&mut self, _ctx: &mut SimCtx) -> Result<u64> {
        Ok(u64::from(self.expect.is_empty()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use veryl_component::testing::MockSim;

    fn sink_sim() -> MockSim {
        MockSim::new()
            .clock_port("clk")
            .reset_port("rst")
            .input("axi.tvalid", 1)
            .output("axi.tready", 1)
            .input("axi.tdata", 32)
            .input("axi.tlast", 1)
    }

    /// Drives one beat from the source side and clocks once.
    fn send_beat(sim: &mut MockSim, c: &mut Axi4StreamSink, data: u64, last: bool) {
        sim.set("axi.tvalid", 1u64);
        sim.set("axi.tdata", data);
        sim.set("axi.tlast", u64::from(last));
        sim.clock(c).unwrap();
        sim.set("axi.tvalid", 0u64);
    }

    #[test]
    fn receives_and_counts_packets() {
        let mut sim = sink_sim();
        let mut c = sim.build::<Axi4StreamSink>().unwrap();
        sim.set("rst", 0u64);
        sim.clock(&mut c).unwrap(); // TREADY asserts
        send_beat(&mut sim, &mut c, 0x11, false);
        send_beat(&mut sim, &mut c, 0x22, true);
        assert_eq!(
            sim.call(&mut c, "recv", &[]).unwrap().as_u64().unwrap(),
            0x11
        );
        assert_eq!(
            sim.call(&mut c, "recv", &[]).unwrap().as_u64().unwrap(),
            0x22
        );
        assert_eq!(
            sim.call(&mut c, "packets", &[]).unwrap().as_u64().unwrap(),
            1
        );
    }

    #[test]
    fn expect_fails_on_mismatch() {
        let mut sim = sink_sim();
        let mut c = sim.build::<Axi4StreamSink>().unwrap();
        sim.set("rst", 0u64);
        sim.clock(&mut c).unwrap();
        sim.call(&mut c, "expect", &[0x11u64.into()]).unwrap();
        send_beat(&mut sim, &mut c, 0xdead, false);
        assert!(sim.failures().iter().any(|f| f.contains("expected")));
    }

    #[test]
    fn expect_passes_on_match() {
        let mut sim = sink_sim();
        let mut c = sim.build::<Axi4StreamSink>().unwrap();
        sim.set("rst", 0u64);
        sim.clock(&mut c).unwrap();
        sim.call(&mut c, "expect", &[0x11u64.into()]).unwrap();
        send_beat(&mut sim, &mut c, 0x11, false);
        assert!(!sim.failed(), "unexpected: {:?}", sim.failures());
    }
}
