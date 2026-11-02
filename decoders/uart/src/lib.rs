//! UART, decoded from raw edges.
//!
//! Section 5.6: baud rate, data bits, parity, stop bits, framing and parity
//! errors, and a terminal view linked to the waveform.
//!
//! # Why this one is different from the others
//!
//! Every other decoder here is driven by a clock on the wire. UART has none, so
//! the only thing that says where a bit boundary falls is the baud rate - and
//! getting it wrong does not fail loudly, it produces plausible bytes that are
//! wrong. That is the whole difficulty of the protocol.
//!
//! So a bit is sampled at the *middle* of its window rather than at its start,
//! which is what a real receiver does and what gives the most margin against a
//! baud rate that is slightly off. And the auto-detect below measures rather
//! than guesses.
//!
//! # Auto-detecting the baud rate
//!
//! The shortest interval between two edges in the capture is one bit time, or a
//! multiple of it if no single bit ever stood alone. Taking the shortest is
//! right whenever the traffic contains one isolated bit, which any text does -
//! and when it does not, the answer is a submultiple of the truth and the frames
//! do not line up, which shows as framing errors rather than as silent nonsense.

#![forbid(unsafe_code)]

use decode::{apply_gap_rule, span, BusDecoder, Edge, Fields, SearchField};
use schema::{
    BusId, Decoded, DecoderInfo, ErrorKind, Event, FieldKind, Picos, Protocol,
    Severity, Transaction,
};

pub const DECODER_NAME: &str = "uart";
pub const DECODER_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parity {
    None,
    Even,
    Odd,
}

impl Parity {
    fn as_str(self) -> &'static str {
        match self {
            Parity::None => "N",
            Parity::Even => "E",
            Parity::Odd => "O",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bus: BusId,
    /// Which channel carries the line.
    pub channel: u8,
    /// None means measure it from the capture.
    pub baud: Option<u64>,
    pub data_bits: u8,
    pub parity: Parity,
    pub stop_bits: u8,
    /// An idle-low line, for a receiver behind an inverting transceiver.
    pub inverted: bool,
    pub first_id: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bus: BusId(0),
            channel: 0,
            baud: None,
            data_bits: 8,
            parity: Parity::None,
            stop_bits: 1,
            inverted: false,
            first_id: 1,
        }
    }
}

pub struct Decoder {
    config: Config,
}

const FIELDS: &[SearchField] = &[
    SearchField { name: "data", help: "the byte value" },
    SearchField { name: "ascii", help: "the byte as a character, when printable" },
    SearchField { name: "parity", help: "ok or bad" },
    SearchField { name: "framing", help: "ok or bad" },
];

impl Decoder {
    pub fn new(config: Config) -> Self {
        Decoder { config }
    }

    /// The shortest gap between edges, which is one bit time.
    ///
    /// Public because it is worth being able to ask: a capture that decodes to
    /// nonsense is usually a baud rate, and seeing the measured figure is how
    /// that gets diagnosed.
    pub fn measure_baud(edges: &[Edge]) -> Option<u64> {
        let mut shortest = u64::MAX;
        for pair in edges.windows(2) {
            let d = pair[1].time.saturating_sub(pair[0].time);
            if d > 0 && d < shortest {
                shortest = d;
            }
        }
        (shortest != u64::MAX && shortest > 0)
            .then(|| 1_000_000_000_000u64 / shortest)
    }

    /// The level of the line at time `t`, from the last edge at or before it.
    fn level_at(&self, edges: &[Edge], from: usize, t: Picos) -> (bool, usize) {
        let mut i = from;
        while i + 1 < edges.len() && edges[i + 1].time <= t {
            i += 1;
        }
        let raw = edges[i].line(self.config.channel);
        (raw != self.config.inverted, i)
    }
}

impl BusDecoder for Decoder {
    fn info(&self) -> DecoderInfo {
        DecoderInfo {
            name: DECODER_NAME.into(),
            version: DECODER_VERSION.into(),
            protocol: Protocol::Uart,
            bus: self.config.bus,
            settings: vec![
                ("channel".into(), self.config.channel.to_string()),
                ("baud".into(), match self.config.baud {
                    Some(b) => b.to_string(),
                    None => "auto".into(),
                }),
                ("format".into(), format!("{}{}{}",
                    self.config.data_bits, self.config.parity.as_str(),
                    self.config.stop_bits)),
                ("inverted".into(), self.config.inverted.to_string()),
            ],
        }
    }

    fn search_fields(&self) -> &'static [SearchField] {
        FIELDS
    }

    fn decode_edges(&self, edges: &[Edge], capture: &file::Capture) -> Decoded {
        let mut out = Decoded::default();
        if edges.len() < 2 {
            return out;
        }

        let baud = match self.config.baud.or_else(|| Self::measure_baud(edges)) {
            Some(b) if b > 0 => b,
            _ => {
                out.events.push(Event {
                    start: edges[0].time,
                    end: edges[edges.len() - 1].time,
                    bus: Some(self.config.bus),
                    kind: "no_baud".into(),
                    message: "could not measure a baud rate: the capture has no \
                              two edges to measure between".into(),
                    severity: Severity::Error,
                    transaction: None,
                });
                return out;
            }
        };
        let bit = 1_000_000_000_000u64 / baud;

        let frame_bits = 1 + self.config.data_bits as u64
            + u64::from(self.config.parity != Parity::None)
            + self.config.stop_bits as u64;

        let mut id = self.config.first_id;
        let mut i = 0usize;
        // When the capture stopped, not when the last edge was. A frame whose
        // stop bit leaves the line idle has no edge at its end, and the levels
        // are known to have held until here.
        let last = capture.index.last_time.max(edges[edges.len() - 1].time);

        while i + 1 < edges.len() {
            // A start bit is the line going low from idle.
            let idle_before = edges[i].line(self.config.channel) != self.config.inverted;
            let low_now = edges[i + 1].line(self.config.channel) == self.config.inverted;
            if !(idle_before && low_now) {
                i += 1;
                continue;
            }

            let start_time = edges[i + 1].time;
            let start_edge = i + 1;

            // Everything is sampled at the middle of its bit window, which is
            // what a receiver does and what tolerates a baud rate slightly off.
            let mid = |n: u64| start_time + bit * n + bit / 2;

            if mid(frame_bits - 1) > last {
                // The frame runs past the end of the capture. Reported as a
                // truncated transaction rather than decoded from bits that were
                // never seen.
                let mut errors = vec![ErrorKind::Truncated];
                let mut complete = false;
                let mut severity = Severity::Warning;
                apply_gap_rule(capture, start_time, last, &mut errors,
                               &mut complete, &mut severity);
                out.transactions.push(Transaction {
                    id,
                    bus: self.config.bus,
                    protocol: Protocol::Uart,
                    start: start_time,
                    end: last,
                    kind: "FRAME".into(),
                    summary: "incomplete: the capture ends inside this frame".into(),
                    severity,
                    parent: None,
                    fields: vec![],
                    errors,
                    samples: span(edges, start_edge, edges.len() - 1),
                    complete: false,
                });
                break;
            }

            let mut cursor = i;
            let mut value: u16 = 0;
            let mut ones = 0u32;
            for b in 0..self.config.data_bits as u64 {
                let (level, at) = self.level_at(edges, cursor, mid(1 + b));
                cursor = at;
                if level {
                    // Least significant bit first, which is what UART sends.
                    value |= 1 << b;
                    ones += 1;
                }
            }

            let mut errors = Vec::new();
            let mut severity = Severity::Info;
            let mut fields = Fields::new();

            let end_time = start_time + bit * frame_bits;
            let end_edge = self.level_at(edges, cursor, end_time).1;
            let whole = span(edges, start_edge, end_edge);

            let byte = value as u8;
            fields.number("data", byte as u64, format!("0x{byte:02X}"),
                          FieldKind::Data, (start_time, end_time), whole);
            if (0x20..0x7F).contains(&byte) {
                fields.text("ascii", (byte as char).to_string(),
                            (start_time, end_time), whole);
            }

            if self.config.parity != Parity::None {
                let (level, at) = self.level_at(
                    edges, cursor, mid(1 + self.config.data_bits as u64));
                cursor = at;
                let want = match self.config.parity {
                    Parity::Even => ones % 2 == 1,
                    Parity::Odd => ones % 2 == 0,
                    Parity::None => unreachable!(),
                };
                let ok = level == want;
                fields.text("parity", if ok { "ok" } else { "bad" },
                            (start_time, end_time), whole);
                if !ok {
                    fields.flag(Severity::Warning);
                    errors.push(ErrorKind::CheckFailed);
                    severity = Severity::Warning;
                }
            }

            // Every stop bit must be high. One low is a framing error, and the
            // commonest cause is the baud rate being wrong - which is why the
            // message says so rather than just naming the bit.
            let mut framing_ok = true;
            for s in 0..self.config.stop_bits as u64 {
                let n = 1 + self.config.data_bits as u64
                    + u64::from(self.config.parity != Parity::None) + s;
                let (level, at) = self.level_at(edges, cursor, mid(n));
                cursor = at;
                if !level {
                    framing_ok = false;
                }
            }
            fields.text("framing", if framing_ok { "ok" } else { "bad" },
                        (start_time, end_time), whole);
            if !framing_ok {
                fields.flag(Severity::Warning);
                errors.push(ErrorKind::Framing);
                severity = Severity::Warning;
            }

            let mut complete = true;
            apply_gap_rule(capture, start_time, end_time, &mut errors,
                           &mut complete, &mut severity);

            let printable = if (0x20..0x7F).contains(&byte) {
                format!(" '{}'", byte as char)
            } else {
                String::new()
            };
            let note = if !framing_ok {
                "  framing error - check the baud rate"
            } else if errors.contains(&ErrorKind::CheckFailed) {
                "  parity error"
            } else {
                ""
            };

            out.transactions.push(Transaction {
                id,
                bus: self.config.bus,
                protocol: Protocol::Uart,
                start: start_time,
                end: end_time,
                kind: "FRAME".into(),
                summary: format!("0x{byte:02X}{printable}{note}"),
                severity,
                parent: None,
                fields: fields.take(),
                errors,
                samples: whole,
                complete,
            });
            id += 1;

            // Resume after the frame. A framing error means the boundaries are
            // probably wrong from here, but hunting for the next idle-to-low
            // edge is the same recovery a receiver performs.
            i = end_edge.max(start_edge);
        }

        out
    }
}

/// The decoded bytes as text, for the terminal view section 5.6 asks for.
pub fn terminal(decoded: &Decoded) -> String {
    decoded
        .transactions
        .iter()
        .filter_map(|t| t.fields.iter().find(|f| f.name == "data"))
        .filter_map(|f| f.value)
        .map(|v| {
            let b = v as u8;
            if (0x20..0x7F).contains(&b) || b == b'\n' || b == b'\r' {
                b as char
            } else {
                '.'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use simulator::{Parity as SimParity, Uart as Gen};

    fn decode_of(cap: &file::Capture, config: Config) -> Decoded {
        Decoder::new(config).decode(cap)
    }

    fn text_of(decoded: &Decoded) -> String {
        terminal(decoded)
    }

    #[test]
    fn plain_8n1_text_decodes() {
        let mut g = Gen::new(115_200, 8, SimParity::None, 1);
        g.text("Hello");
        let cap = g.wire.capture("t");

        let d = decode_of(&cap, Config::default());
        assert_eq!(d.transactions.len(), 5, "{:#?}", d.transactions);
        assert_eq!(text_of(&d), "Hello");
        assert!(d.transactions.iter().all(|t| t.errors.is_empty()));
    }

    #[test]
    fn the_baud_rate_is_measured_when_it_is_not_given() {
        let mut g = Gen::new(9_600, 8, SimParity::None, 1);
        g.text("AB");
        let cap = g.wire.capture("t");
        let edges = decode::edges_of(&cap);

        let measured = Decoder::measure_baud(&edges).unwrap();
        // Within a percent: the measurement is the shortest interval, which is
        // exact here, but the division rounds.
        assert!((measured as i64 - 9_600).abs() < 100,
                "measured {measured}, expected about 9600");
        assert_eq!(text_of(&decode_of(&cap, Config::default())), "AB");
    }

    #[test]
    fn even_parity_is_checked() {
        let mut g = Gen::new(115_200, 8, SimParity::Even, 1);
        g.byte(b'A');
        let cap = g.wire.capture("t");

        let config = Config { parity: Parity::Even, ..Config::default() };
        let d = decode_of(&cap, config);
        assert_eq!(d.transactions.len(), 1);
        assert!(d.transactions[0].errors.is_empty(), "{:?}", d.transactions[0]);
    }

    #[test]
    fn a_wrong_parity_bit_is_caught_and_the_byte_still_reported() {
        let mut g = Gen::new(115_200, 8, SimParity::Even, 1);
        g.byte_with_bad_parity(b'A');
        let cap = g.wire.capture("t");

        let config = Config { parity: Parity::Even, ..Config::default() };
        let d = decode_of(&cap, config);
        let t = &d.transactions[0];
        assert!(t.errors.contains(&ErrorKind::CheckFailed), "{:?}", t.errors);
        // The byte is still there: a parity error means one bit is suspect, not
        // that the frame should be thrown away.
        assert_eq!(t.fields.iter().find(|f| f.name == "data").unwrap().value,
                   Some(b'A' as u64));
    }

    #[test]
    fn a_missing_stop_bit_is_a_framing_error() {
        let mut g = Gen::new(115_200, 8, SimParity::None, 1);
        g.byte_with_framing_error(b'B');
        let cap = g.wire.capture("t");

        let d = decode_of(&cap, Config::default());
        assert!(d.transactions[0].errors.contains(&ErrorKind::Framing),
                "{:?}", d.transactions[0]);
        assert!(d.transactions[0].summary.contains("baud rate"),
                "the message should point at the likeliest cause");
    }

    #[test]
    fn an_inverted_line_decodes_the_same_bytes() {
        let mut g = Gen::new(115_200, 8, SimParity::None, 1);
        g.text("Hi");
        let mut cap = g.wire.capture("t");
        // Invert every sample, which is what a transceiver would do.
        for chunk in &mut cap.chunks {
            for l in &mut chunk.lines {
                *l ^= 0b1;
            }
        }

        let config = Config { inverted: true, ..Config::default() };
        assert_eq!(text_of(&decode_of(&cap, config)), "Hi");
    }

    #[test]
    fn a_frame_cut_off_by_the_end_of_the_capture_is_incomplete() {
        let mut g = Gen::new(115_200, 8, SimParity::None, 1);
        g.text("A");
        // Start a second frame and stop: the line goes low and the capture ends.
        g.byte(0x00);
        let mut cap = g.wire.capture("t");
        let keep = cap.chunks[0].len() - 1;
        cap.chunks[0].times.truncate(keep);
        cap.chunks[0].lines.truncate(keep);
        cap.chunks[0].end = *cap.chunks[0].times.last().unwrap();
        // The index has to be rebuilt to match, because that is what the
        // decoder reads for "when did the capture stop" - and a reader that
        // opens a truncated file rebuilds it for the same reason.
        cap.index = file::rebuild_index(&cap.chunks, &cap.gaps, &Decoded::default());

        let d = decode_of(&cap, Config::default());
        assert!(d.transactions.iter().any(|t| !t.complete),
                "nothing was marked incomplete: {:#?}", d.transactions);
    }

    #[test]
    fn decoding_is_deterministic() {
        let mut g = Gen::new(115_200, 8, SimParity::None, 1);
        g.text("determinism");
        let cap = g.wire.capture("t");
        assert_eq!(decode_of(&cap, Config::default()),
                   decode_of(&cap, Config::default()));
    }

    #[test]
    fn every_field_traces_to_samples() {
        let mut g = Gen::new(115_200, 8, SimParity::Even, 1);
        g.text("xyz");
        let cap = g.wire.capture("t");
        let edges = cap.chunks[0].len() as u32;
        let config = Config { parity: Parity::Even, ..Config::default() };
        for t in &decode_of(&cap, config).transactions {
            for f in &t.fields {
                assert!(f.samples.last >= f.samples.first, "{}", f.name);
                assert!(f.samples.last < edges, "{} points past the chunk", f.name);
            }
        }
    }
}
