//! A waveform of up to eight channels, built an edge at a time.
//!
//! The two-wire builder came first because I2C did. SPI wants four channels and
//! UART wants one, so the generic thing underneath is here and the protocol
//! builders sit on top of it.
//!
//! Everything is deterministic. No clock is read, nothing is random: the same
//! calls produce the same picoseconds on every machine, which is what makes a
//! golden file a test rather than a photograph of one afternoon.

use file::{Gap, SampleChunk, Session};
use schema::Picos;

/// Up to eight channels of digital waveform.
pub struct Wire {
    names: Vec<String>,
    times: Vec<Picos>,
    lines: Vec<u8>,
    gaps: Vec<Gap>,
    now: Picos,
    /// Current level of each channel, as a mask.
    state: u8,
}

impl Wire {
    /// `names` are the channel names in bit order: index 0 is bit 0.
    ///
    /// `idle` is the mask every channel starts at, and it matters: a bus idles
    /// high, a UART line idles high, and a chip select idles high, but SPI
    /// clock idles at whatever CPOL says. Getting it wrong makes the first
    /// transition of a capture a lie.
    pub fn new(names: &[&str], idle: u8, start: Picos) -> Self {
        assert!(names.len() <= 8, "eight channels is what a line mask holds");
        Wire {
            names: names.iter().map(|s| s.to_string()).collect(),
            // The initial state, which every chunk begins with - see
            // file::SampleChunk.
            times: vec![start],
            lines: vec![idle],
            gaps: Vec::new(),
            now: start,
            state: idle,
        }
    }

    pub fn now(&self) -> Picos {
        self.now
    }

    /// Let time pass with nothing moving.
    pub fn advance(&mut self, ps: Picos) {
        self.now += ps;
    }

    /// Set one channel, recording an edge if it actually changed.
    pub fn set(&mut self, channel: u8, level: bool) {
        let mask = 1u8 << channel;
        let next = if level { self.state | mask } else { self.state & !mask };
        self.set_mask(next);
    }

    /// Set every channel at once, which is how two lines that move together
    /// produce one entry rather than two.
    pub fn set_mask(&mut self, next: u8) {
        if next == self.state {
            return;
        }
        self.state = next;
        self.times.push(self.now);
        self.lines.push(next);
    }

    pub fn level(&self, channel: u8) -> bool {
        self.state & (1 << channel) != 0
    }

    /// A hole in the capture: time passes and nothing is recorded, and the gap
    /// says so explicitly.
    pub fn gap(&mut self, ps: Picos, reason: &str) {
        let start = self.now;
        self.now += ps;
        self.gaps.push(Gap { start, end: self.now, reason: reason.into(), lost: None });
    }

    /// Transitions, not counting the initial state entry.
    pub fn transitions(&self) -> usize {
        self.times.len().saturating_sub(1)
    }

    pub fn chunk(&self, id: u32) -> SampleChunk {
        SampleChunk {
            id,
            start: *self.times.first().unwrap_or(&0),
            // Where the generator's clock got to, not the last edge. A
            // generator that stopped watching at its last transition would make
            // every frame ending in an idle line look truncated - see the note
            // on SampleChunk::end.
            end: self.now.max(*self.times.last().unwrap_or(&0)),
            times: self.times.clone(),
            lines: self.lines.clone(),
        }
    }

    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }

    pub fn session(&self, script: &str) -> Session {
        Session {
            format_version: file::FORMAT_VERSION,
            schema_version: schema::SCHEMA_VERSION,
            source: format!("simulator:{script}"),
            device_id: "simulator".into(),
            firmware_version: env!("CARGO_PKG_VERSION").into(),
            host_software: concat!("sniffer ", env!("CARGO_PKG_VERSION")).into(),
            // Fixed, not the wall clock: a golden file that changes every run is
            // not a golden file.
            started_utc: "1970-01-01T00:00:00Z".into(),
            channels: self.names.clone(),
            tick_hz: 1_000_000_000_000,
            // The simulator places every edge itself, but it places them on a
            // real time axis at a stated rate - the waveform it writes is what
            // a bus running that script would have looked like. That is a
            // modelled recording, not a reconstruction missing its times.
            timing: file::Timing::Measured,
        }
    }

    /// A whole capture, ready to decode or write.
    pub fn capture(&self, script: &str) -> file::Capture {
        let chunk = self.chunk(0);
        let index = file::rebuild_index(
            std::slice::from_ref(&chunk), self.gaps(), &schema::Decoded::default());
        file::Capture {
            session: self.session(script),
            chunks: vec![chunk],
            gaps: self.gaps.clone(),
            decoders: vec![],
            decoded: schema::Decoded::default(),
            annotations: vec![],
            index,
            truncated_at: None,
        }
    }
}

/// Picoseconds in one period at `hz`.
pub fn period(hz: u64) -> Picos {
    1_000_000_000_000u64 / hz.max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wire_starts_with_its_idle_state() {
        let w = Wire::new(&["a", "b"], 0b11, 1_000);
        assert_eq!(w.chunk(0).times, vec![1_000]);
        assert_eq!(w.chunk(0).lines, vec![0b11]);
        assert_eq!(w.transitions(), 0);
    }

    #[test]
    fn setting_a_channel_to_what_it_already_is_records_nothing() {
        let mut w = Wire::new(&["a"], 1, 0);
        w.advance(10);
        w.set(0, true);
        assert_eq!(w.transitions(), 0);
        w.set(0, false);
        assert_eq!(w.transitions(), 1);
    }

    /// Two channels moving at the same instant must be one entry. Two would be
    /// a phantom intermediate state that the hardware never had - the same bug
    /// the firmware's coincident-edge handling exists for.
    #[test]
    fn channels_moving_together_make_one_entry() {
        let mut w = Wire::new(&["a", "b"], 0b11, 0);
        w.advance(10);
        w.set_mask(0b00);
        assert_eq!(w.transitions(), 1);
        assert_eq!(w.chunk(0).lines, vec![0b11, 0b00]);
    }

    #[test]
    fn a_gap_records_its_span_and_emits_nothing() {
        let mut w = Wire::new(&["a"], 1, 0);
        w.advance(10);
        w.set(0, false);
        let before = w.transitions();
        w.gap(1_000, "test");
        assert_eq!(w.transitions(), before, "a gap must not add entries");
        assert_eq!(w.gaps().len(), 1);
        assert_eq!(w.gaps()[0].end - w.gaps()[0].start, 1_000);
    }

    #[test]
    fn periods_come_out_in_picoseconds() {
        assert_eq!(period(1_000_000), 1_000_000);      // 1 MHz -> 1 us
        assert_eq!(period(100_000), 10_000_000);       // 100 kHz -> 10 us
    }
}
