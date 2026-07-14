//! Protocol-agnostic building blocks shared across the AXI verification
//! components: response codes, a deterministic RNG for backpressure, the
//! handshake-stability monitor, a latency accumulator and small helpers.

use veryl_component::*;

/// AXI4 response encodings. `EXOKAY` (exclusive OK) is the one the checker
/// rejects, since AXI4-Lite has no exclusive access.
pub(crate) mod resp {
    pub const OKAY: u64 = 0b00;
    pub const EXOKAY: u64 = 0b01;
    pub const SLVERR: u64 = 0b10;
    pub const DECERR: u64 = 0b11;
}

/// Advances an xorshift64 state and returns the next value. Seed from
/// `BuildCtx::seed` for a deterministic, per-instance sequence.
pub(crate) fn next_rand(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

/// Reports whether to stall this cycle: `true` with probability
/// `weight/256`. `weight` unset never stalls, so the state is only advanced
/// when backpressure is enabled.
pub(crate) fn stall_now(lfsr: &mut u64, weight: Option<u64>) -> bool {
    let Some(weight) = weight else {
        return false;
    };
    (next_rand(lfsr) & 0xff) < weight
}

/// Number of 64-bit words spanning `width` bits, the buffer length
/// `read_words`/`write_words` expect.
pub(crate) fn words_for(width: u32) -> usize {
    (width as usize).div_ceil(64).max(1)
}

/// Fails the test with the current cycle number prefixed, so a violation
/// says when it happened.
pub(crate) fn fail_at(ctx: &mut SimCtx, msg: impl Into<String>) {
    let cycle = ctx.cycle();
    ctx.fail(format!("cycle {cycle}: {}", msg.into()));
}

/// Clears the bits above `width` in the top word of an LSB-first vector.
pub(crate) fn mask_words(words: &mut [u64], width: u32) {
    let rem = width % 64;
    if rem != 0
        && let Some(last) = words.last_mut()
    {
        *last &= u64::MAX >> (64 - rem);
    }
}

/// True when a signal reads as a definite logic 1.
pub(crate) fn high(v: &Value) -> bool {
    v.as_bool()
}

/// A full-width data argument as bus data words: the value's own words
/// zero-extended to `width`. Rejects X/Z payloads and values whose set bits
/// do not fit the bus.
pub(crate) fn arg_words(v: &Value, width: u32, what: &str) -> Result<Vec<u64>> {
    if v.has_unknown() {
        bail!("{what} contains X/Z bits");
    }
    let Value::Bits { words, .. } = v else {
        bail!("{what} is not a bit value");
    };
    let mut out = vec![0u64; words_for(width)];
    for (i, w) in words.iter().enumerate() {
        if let Some(slot) = out.get_mut(i) {
            *slot = *w;
        } else if *w != 0 {
            bail!("{what} does not fit the {width}-bit bus");
        }
    }
    let masked = {
        let mut m = out.clone();
        mask_words(&mut m, width);
        m
    };
    if masked != out {
        bail!("{what} does not fit the {width}-bit bus");
    }
    Ok(out)
}

/// A full-width return value from bus data words.
pub(crate) fn data_value(words: Vec<u64>, width: u32) -> Value {
    Value::from_bits(words.into_iter().collect(), Default::default(), width)
}

/// OR-folds a value's words into one `u64` so a lane-activity coverage mask
/// stays valid past 64 bits, where `as_u64` fails and would read as zero.
pub(crate) fn fold_words(v: &Value) -> u64 {
    match v {
        Value::Bits { words, .. } => words.iter().fold(0u64, |acc, w| acc | w),
        _ => 0,
    }
}

/// Per-channel handshake monitor: remembers whether the channel was stalled
/// (VALID high, READY low) last cycle and the payload it presented, so the
/// next cycle can enforce the AMBA stability rules. The same rules apply to
/// every AXI channel, so this is shared. Also counts consecutive stall
/// cycles for the hang timeout and coverage.
#[derive(Default)]
pub(crate) struct Channel {
    stalled: bool,
    payload: Vec<Value>,
    pub(crate) stall_cycles: u64,
    pub(crate) max_stall: u64,
}

impl Channel {
    /// Applies the "VALID must hold and payload must stay stable until READY"
    /// rule and returns the violation reason, if any.
    pub(crate) fn check(
        &mut self,
        valid: bool,
        ready: bool,
        payload: &[Value],
    ) -> Option<&'static str> {
        let violation = if self.stalled {
            if !valid {
                Some("VALID deasserted before READY")
            } else if self.payload.as_slice() != payload {
                Some("payload changed while VALID was stalled")
            } else {
                None
            }
        } else {
            None
        };
        if valid && !ready {
            self.stall_cycles += 1;
        } else {
            self.stall_cycles = 0;
        }
        self.max_stall = self.max_stall.max(self.stall_cycles);
        self.stalled = valid && !ready;
        self.payload = payload.to_vec();
        violation
    }

    /// Clears the live handshake history but keeps the coverage maximum.
    pub(crate) fn clear(&mut self) {
        self.stalled = false;
        self.payload.clear();
        self.stall_cycles = 0;
    }
}

/// A running min / average / max of a latency series.
#[derive(Default)]
pub(crate) struct Latency {
    pub(crate) min: u64,
    pub(crate) max: u64,
    sum: u64,
    count: u64,
}

impl Latency {
    pub(crate) fn record(&mut self, v: u64) {
        if self.count == 0 {
            self.min = v;
            self.max = v;
        } else {
            self.min = self.min.min(v);
            self.max = self.max.max(v);
        }
        self.sum += v;
        self.count += 1;
    }

    pub(crate) fn avg(&self) -> u64 {
        self.sum.checked_div(self.count).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn arg_words_zero_extends_and_round_trips() {
        let v = Value::from_u64(0xdead, 64);
        let words = arg_words(&v, 128, "data").unwrap();
        assert_eq!(words, vec![0xdead, 0]);

        let wide = Value::from_bits([0x1, 0x2].into_iter().collect(), Default::default(), 128);
        let words = arg_words(&wide, 128, "data").unwrap();
        assert_eq!(data_value(words, 128), wide);
    }

    #[test]
    fn arg_words_rejects_oversized_and_xz() {
        let v = Value::from_u64(u64::MAX, 64);
        let err = arg_words(&v, 32, "data").unwrap_err();
        assert!(err.to_string().contains("does not fit the 32-bit bus"));

        let wide = Value::from_bits([0, 0, 1].into_iter().collect(), Default::default(), 192);
        assert!(arg_words(&wide, 128, "data").is_err());

        let xz = Value::from_bits([1].into_iter().collect(), [1].into_iter().collect(), 32);
        let err = arg_words(&xz, 32, "data").unwrap_err();
        assert!(err.to_string().contains("X/Z"));
    }
}
