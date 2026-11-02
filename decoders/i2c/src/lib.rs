//! I2C, decoded from raw edges.
//!
//! Section 5.3: START/repeated START/STOP, 7-bit addressing, direction, byte
//! values and ACK/NACK, clock stretching, transaction grouping across repeated
//! START.
//!
//! # What it reads
//!
//! Transitions, not decoded events. The board can do the decode itself and it
//! is much cheaper there - but a decoder that reads samples can be re-run on a
//! saved capture, tested against a golden corpus with no hardware, and made to
//! explain which edges produced which field. Appendix B requires all three.
//!
//! # The rules it applies
//!
//! SDA moving while SCL is high is a START or a STOP - falling is a START,
//! rising is a STOP. Everything else is read on the rising edge of SCL, where
//! the bus guarantees SDA is stable. Nine clocks make a byte and its
//! acknowledge. That is the whole protocol at this level.
//!
//! Clock stretching needs no special handling and that is worth saying, because
//! it is where a time-driven decoder goes wrong: this one is driven by edges,
//! so a clock held low for a millisecond is one longer interval between two
//! edges and nothing else changes.
//!
//! # What it refuses to guess
//!
//! A transaction that runs past the end of the capture, or across a gap, is
//! emitted with `complete: false` and the bytes it did see. It is never
//! completed by assumption. Appendix B again: a gap overlapping a transaction
//! must produce a clear incomplete result rather than false data.

#![forbid(unsafe_code)]

use decode::{BusDecoder, SearchField};
use schema::{
    BusId, Decoded, DecoderInfo, ErrorKind, Event, Field, FieldKind, Picos, Protocol,
    SampleRef, Severity, Transaction,
};

pub const DECODER_NAME: &str = "i2c";
pub const DECODER_VERSION: &str = "1.0.0";

/// Which channel is which, by index into a chunk's line mask.
#[derive(Debug, Clone, Copy)]
pub struct Channels {
    pub scl: u8,
    pub sda: u8,
}

impl Default for Channels {
    fn default() -> Self {
        Channels { scl: 0, sda: 1 }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bus: BusId,
    pub channels: Channels,
    /// Transaction ids start here, so two buses decoded into one capture do not
    /// collide. Determinism depends on this being a function of the input and
    /// not of when the decode ran.
    pub first_id: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config { bus: BusId(0), channels: Channels::default(), first_id: 1 }
    }
}

impl Config {
    pub fn info(&self) -> DecoderInfo {
        DecoderInfo {
            name: DECODER_NAME.into(),
            version: DECODER_VERSION.into(),
            protocol: Protocol::I2c,
            bus: self.bus,
            settings: vec![
                ("scl_channel".into(), self.channels.scl.to_string()),
                ("sda_channel".into(), self.channels.sda.to_string()),
            ],
        }
    }
}

/// One edge, flattened out of whatever chunk it came from.
///
/// The decoder works on a flat sequence but every edge remembers which chunk
/// and index it came from, because that is what a SampleRef is made of.
#[derive(Debug, Clone, Copy)]
pub struct Edge {
    pub time: Picos,
    pub scl: bool,
    pub sda: bool,
    pub chunk: u32,
    pub index: u32,
}

/// Flatten a capture into the two-wire view this decoder works in.
///
/// The walk over chunks belongs to the SDK - every decoder needs it - and this
/// only picks the two channels out of the line mask.
pub fn edges_of(capture: &file::Capture, channels: Channels) -> Vec<Edge> {
    decode::edges_of(capture)
        .into_iter()
        .map(|e| Edge {
            time: e.time,
            scl: e.line(channels.scl),
            sda: e.line(channels.sda),
            chunk: e.chunk,
            index: e.index,
        })
        .collect()
}

/// A byte being assembled.
struct Building {
    value: u8,
    bits: u8,
    first: usize,
}

/// A transaction being assembled.
struct Frame {
    id: u64,
    start: Picos,
    first_edge: usize,
    address: Option<u8>,
    read: bool,
    addr_acked: bool,
    bytes: Vec<u8>,
    acks: Vec<bool>,
    fields: Vec<Field>,
    errors: Vec<ErrorKind>,
    restart: bool,
}

pub struct Decoder {
    config: Config,
}

impl Decoder {
    pub fn new(config: Config) -> Self {
        Decoder { config }
    }

    /// Decode a whole capture.
    ///
    /// Deterministic: the same edges and the same configuration produce the
    /// same transactions with the same ids, which is the acceptance criterion
    /// for replay.
    pub fn decode(&self, capture: &file::Capture) -> Decoded {
        let edges = edges_of(capture, self.config.channels);
        self.decode_edges(&edges, capture)
    }

    pub fn decode_edges(&self, edges: &[Edge], capture: &file::Capture) -> Decoded {
        let mut out = Decoded::default();
        let mut next_id = self.config.first_id;
        let mut frame: Option<Frame> = None;
        let mut building: Option<Building> = None;

        for i in 1..edges.len() {
            let prev = edges[i - 1];
            let now = edges[i];

            let scl_rose = !prev.scl && now.scl;
            let sda_moved = prev.sda != now.sda;

            // A move on SDA while SCL is high, and stays high, is framing.
            if sda_moved && prev.scl && now.scl {
                if now.sda {
                    // Released: STOP.
                    if let Some(f) = frame.take() {
                        out.transactions.push(self.finish(f, now.time, i, capture, true));
                    } else {
                        out.events.push(Event {
                            start: now.time,
                            end: now.time,
                            bus: Some(self.config.bus),
                            kind: "stop_without_start".into(),
                            message: "STOP with no open transaction".into(),
                            severity: Severity::Warning,
                            transaction: None,
                        });
                    }
                    building = None;
                } else {
                    // Pulled low: START, or a repeated START inside a frame.
                    let restart = frame.is_some();
                    if let Some(f) = frame.take() {
                        // The previous frame ends here, at the repeated start.
                        out.transactions.push(self.finish(f, now.time, i, capture, true));
                    }
                    frame = Some(Frame {
                        id: next_id,
                        start: now.time,
                        first_edge: i,
                        address: None,
                        read: false,
                        addr_acked: false,
                        bytes: Vec::new(),
                        acks: Vec::new(),
                        fields: Vec::new(),
                        errors: Vec::new(),
                        restart,
                    });
                    next_id += 1;
                    building = None;
                }
                continue;
            }

            if !scl_rose {
                continue;
            }
            let Some(f) = frame.as_mut() else { continue };

            let b = building.get_or_insert(Building { value: 0, bits: 0, first: i });
            if b.bits < 8 {
                b.value = (b.value << 1) | u8::from(now.sda);
                b.bits += 1;
                continue;
            }

            // The ninth clock is the acknowledge.
            let acked = !now.sda;
            let value = b.value;
            let first_edge = b.first;
            building = None;

            let samples = SampleRef {
                chunk: edges[first_edge].chunk,
                first: edges[first_edge].index,
                last: now.index,
            };
            let start = edges[first_edge].time;

            if f.address.is_none() {
                let addr = value >> 1;
                let read = value & 1 != 0;
                f.address = Some(addr);
                f.read = read;
                f.addr_acked = acked;
                f.fields.push(Field {
                    name: "address".into(),
                    value: Some(addr as u64),
                    display: format!("0x{addr:02X}"),
                    kind: FieldKind::Address,
                    start,
                    end: now.time,
                    samples,
                    severity: Severity::Info,
                });
                f.fields.push(Field {
                    name: "direction".into(),
                    value: Some(u64::from(read)),
                    display: if read { "R".into() } else { "W".into() },
                    kind: FieldKind::Flag,
                    start,
                    end: now.time,
                    samples,
                    severity: Severity::Info,
                });
                f.fields.push(Field {
                    name: "ack".into(),
                    value: Some(u64::from(acked)),
                    display: if acked { "ACK".into() } else { "NACK".into() },
                    kind: FieldKind::Flag,
                    start,
                    end: now.time,
                    samples,
                    // A NACK on the address is how a scan discovers nothing is
                    // there, so it is a notice and not a warning. It is still
                    // in the error list, because a filter for "anything that
                    // did not get answered" is a thing people want.
                    severity: if acked { Severity::Info } else { Severity::Notice },
                });
                if !acked {
                    f.errors.push(ErrorKind::Nack);
                }
            } else {
                f.bytes.push(value);
                f.acks.push(acked);
                f.fields.push(Field {
                    name: format!("data[{}]", f.bytes.len() - 1),
                    value: Some(value as u64),
                    display: format!("0x{value:02X}"),
                    kind: FieldKind::Data,
                    start,
                    end: now.time,
                    samples,
                    severity: Severity::Info,
                });
                // A write whose data byte is not acknowledged has been refused
                // by the target. A read's last byte is normally NACKed by the
                // controller to say "no more", so that is not an error.
                if !acked && !f.read && !f.errors.contains(&ErrorKind::Nack) {
                    f.errors.push(ErrorKind::Nack);
                }
            }
        }

        // A frame still open when the edges run out did not finish inside this
        // capture. It is emitted with what was seen and marked incomplete -
        // never completed by assumption.
        if let Some(f) = frame {
            let last = edges.last().map(|e| e.time).unwrap_or(f.start);
            let mut t = self.finish(f, last, edges.len(), capture, false);
            t.complete = false;
            t.errors.push(ErrorKind::Truncated);
            t.severity = Severity::Warning;
            out.transactions.push(t);
        }

        out
    }

    fn finish(
        &self,
        f: Frame,
        end: Picos,
        end_edge: usize,
        capture: &file::Capture,
        complete: bool,
    ) -> Transaction {
        let addr = f.address;
        let kind = match (f.restart, f.read) {
            (true, true) => "READ-RS",
            (true, false) => "WRITE-RS",
            (false, true) => "READ",
            (false, false) => "WRITE",
        };

        let mut errors = f.errors;
        let mut severity = if errors.is_empty() { Severity::Info } else { Severity::Notice };

        // A gap anywhere inside the transaction means bytes may be missing.
        // Checked against the capture's gap records rather than inferred from
        // suspicious timing: an inference would also fire on clock stretching,
        // which is legal and common.
        let mut complete = complete;
        if capture.gap_overlaps(f.start, end) {
            errors.push(ErrorKind::GapOverlap);
            severity = Severity::Error;
            complete = false;
        }
        if errors.iter().any(|e| matches!(e, ErrorKind::Nack)) && !f.addr_acked {
            severity = severity.max(Severity::Notice);
        }

        let summary = match addr {
            Some(a) => {
                let dir = if f.read { "R" } else { "W" };
                let bytes = f
                    .bytes
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                if !f.addr_acked {
                    format!("0x{a:02X} {dir} — no acknowledge")
                } else if bytes.is_empty() {
                    format!("0x{a:02X} {dir} (address only)")
                } else {
                    format!("0x{a:02X} {dir} {bytes}")
                }
            }
            // A START with no address at all: the frame ended before nine
            // clocks. Real, and worth showing as what it is.
            None => "incomplete: no address".into(),
        };
        if addr.is_none() {
            errors.push(ErrorKind::Framing);
            severity = Severity::Warning;
        }

        let first = f.first_edge.min(end_edge.saturating_sub(1));
        Transaction {
            id: f.id,
            bus: self.config.bus,
            protocol: Protocol::I2c,
            start: f.start,
            end,
            kind: kind.into(),
            summary,
            severity,
            parent: None,
            fields: f.fields,
            errors,
            samples: SampleRef {
                chunk: 0,
                first: first as u32,
                last: end_edge.saturating_sub(1) as u32,
            },
            complete,
        }
    }
}

const FIELDS: &[SearchField] = &[
    SearchField { name: "address", help: "the seven-bit target address" },
    SearchField { name: "direction", help: "R or W" },
    SearchField { name: "ack", help: "ACK or NACK on the address" },
    SearchField { name: "data", help: "a payload byte, as data[n]" },
];

impl BusDecoder for Decoder {
    fn info(&self) -> DecoderInfo {
        self.config.info()
    }

    fn search_fields(&self) -> &'static [SearchField] {
        FIELDS
    }

    fn decode_edges(&self, edges: &[decode::Edge], capture: &file::Capture)
        -> Decoded
    {
        let channels = self.config.channels;
        let mine: Vec<Edge> = edges
            .iter()
            .map(|e| Edge {
                time: e.time,
                scl: e.line(channels.scl),
                sda: e.line(channels.sda),
                chunk: e.chunk,
                index: e.index,
            })
            .collect();
        Decoder::decode_edges(self, &mine, capture)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the edges an I2C transaction would produce, so the decoder can be
    /// tested against traffic whose content is known exactly.
    ///
    /// Deliberately not shared with tools/simulator: a decoder tested only
    /// against its own project's generator can agree with a shared mistake.
    /// This one is written straight from the protocol rules.
    struct Wire {
        times: Vec<Picos>,
        lines: Vec<u8>,
        t: Picos,
        step: Picos,
        scl: bool,
        sda: bool,
    }

    impl Wire {
        fn new() -> Self {
            // Begins with the initial state, as every chunk must.
            Wire {
                times: vec![1_000_000],
                lines: vec![0b11],
                t: 1_000_000,
                step: 1_000_000,
                scl: true,
                sda: true,
            }
        }

        fn edge(&mut self, scl: bool, sda: bool) {
            self.t += self.step;
            if scl == self.scl && sda == self.sda {
                return;
            }
            self.scl = scl;
            self.sda = sda;
            self.times.push(self.t);
            self.lines.push(u8::from(scl) | (u8::from(sda) << 1));
        }

        fn start(&mut self) {
            self.edge(true, true);
            self.edge(true, false);   // SDA falls while SCL high
            self.edge(false, false);
        }

        fn restart(&mut self) {
            self.edge(false, true);
            self.edge(true, true);
            self.edge(true, false);
            self.edge(false, false);
        }

        fn bit(&mut self, v: bool) {
            self.edge(false, v);
            self.edge(true, v);       // sampled here
            self.edge(false, v);
        }

        fn byte(&mut self, value: u8, ack: bool) {
            for i in (0..8).rev() {
                self.bit(value & (1 << i) != 0);
            }
            self.bit(!ack);           // ACK is SDA low
        }

        fn stop(&mut self) {
            self.edge(false, false);
            self.edge(true, false);
            self.edge(true, true);    // SDA rises while SCL high
        }

        fn capture(&self) -> file::Capture {
            let chunk = file::SampleChunk {
                id: 0,
                start: *self.times.first().unwrap_or(&0),
                end: *self.times.last().unwrap_or(&0),
                times: self.times.clone(),
                lines: self.lines.clone(),
            };
            let session = file::Session {
                format_version: file::FORMAT_VERSION,
                schema_version: schema::SCHEMA_VERSION,
                source: "unit test".into(),
                device_id: "none".into(),
                firmware_version: "0".into(),
                host_software: "test".into(),
                started_utc: "1970-01-01T00:00:00Z".into(),
                channels: vec!["SCL".into(), "SDA".into()],
                tick_hz: 1_000_000_000_000,
                timing: file::Timing::Measured,
            };
            let index = file::rebuild_index(
                std::slice::from_ref(&chunk), &[], &Decoded::default());
            file::Capture {
                session,
                chunks: vec![chunk],
                gaps: vec![],
                decoders: vec![],
                decoded: Decoded::default(),
                annotations: vec![],
                index,
                truncated_at: None,
            }
        }
    }

    fn decode(w: &Wire) -> Decoded {
        Decoder::new(Config::default()).decode(&w.capture())
    }

    #[test]
    fn a_write_decodes_to_its_address_and_bytes() {
        let mut w = Wire::new();
        w.start();
        w.byte(0x52 << 1, true);      // 0x52 W
        w.byte(0xDE, true);
        w.byte(0xAD, true);
        w.stop();

        let d = decode(&w);
        assert_eq!(d.transactions.len(), 1, "{:#?}", d.transactions);
        let t = &d.transactions[0];
        assert_eq!(t.kind, "WRITE");
        assert_eq!(t.summary, "0x52 W DE AD");
        assert!(t.complete);
        assert!(t.errors.is_empty());
        assert_eq!(t.fields[0].name, "address");
        assert_eq!(t.fields[0].value, Some(0x52));
        assert_eq!(t.fields[1].display, "W");
    }

    #[test]
    fn a_read_is_marked_as_one() {
        let mut w = Wire::new();
        w.start();
        w.byte((0x52 << 1) | 1, true);
        w.byte(0x34, true);
        w.stop();

        let t = &decode(&w).transactions[0];
        assert_eq!(t.kind, "READ");
        assert_eq!(t.summary, "0x52 R 34");
    }

    /// A read's final byte is NACKed by the controller to end it. That is
    /// normal and must not be reported as an error, or every read in a capture
    /// would come back flagged.
    #[test]
    fn the_closing_nack_of_a_read_is_not_an_error() {
        let mut w = Wire::new();
        w.start();
        w.byte((0x52 << 1) | 1, true);
        w.byte(0x34, false);
        w.stop();

        let t = &decode(&w).transactions[0];
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        assert_eq!(t.severity, Severity::Info);
    }

    #[test]
    fn an_unanswered_address_is_a_nack() {
        let mut w = Wire::new();
        w.start();
        w.byte(0x52 << 1, false);
        w.stop();

        let t = &decode(&w).transactions[0];
        assert_eq!(t.errors, vec![ErrorKind::Nack]);
        assert!(t.summary.contains("no acknowledge"));
    }

    #[test]
    fn a_repeated_start_splits_the_transaction_and_marks_the_second() {
        let mut w = Wire::new();
        w.start();
        w.byte(0x52 << 1, true);
        w.byte(0x10, true);
        w.restart();
        w.byte((0x52 << 1) | 1, true);
        w.byte(0x99, false);
        w.stop();

        let d = decode(&w);
        assert_eq!(d.transactions.len(), 2);
        assert_eq!(d.transactions[0].kind, "WRITE");
        assert_eq!(d.transactions[1].kind, "READ-RS");
        assert_eq!(d.transactions[1].summary, "0x52 R 99");
        // Ids are assigned in order and are what a replay must reproduce.
        assert_eq!(d.transactions[0].id, 1);
        assert_eq!(d.transactions[1].id, 2);
    }

    /// Clock stretching is a longer interval and nothing else. A decoder driven
    /// by time rather than by edges gets this wrong, so it has a test.
    #[test]
    fn clock_stretching_changes_nothing() {
        let mut w = Wire::new();
        w.start();
        w.byte(0x52 << 1, true);
        w.step = 900_000_000;          // the target holds SCL low for ~1 ms
        w.byte(0xDE, true);
        w.step = 1_000_000;
        w.stop();

        let t = &decode(&w).transactions[0];
        assert_eq!(t.summary, "0x52 W DE");
        assert!(t.complete);
    }

    #[test]
    fn a_transaction_running_past_the_capture_is_incomplete_not_invented() {
        let mut w = Wire::new();
        w.start();
        w.byte(0x52 << 1, true);
        w.byte(0xDE, true);
        // No STOP: the capture ends mid-transaction.

        let t = &decode(&w).transactions[0];
        assert!(!t.complete);
        assert!(t.errors.contains(&ErrorKind::Truncated));
        // What it did see is still reported - the bytes are real.
        assert_eq!(t.summary, "0x52 W DE");
    }

    /// The rule from Appendix B: a gap overlapping a transaction produces an
    /// incomplete result rather than confident bytes.
    #[test]
    fn a_gap_over_a_transaction_makes_it_incomplete() {
        let mut w = Wire::new();
        w.start();
        w.byte(0x52 << 1, true);
        w.byte(0xDE, true);
        w.stop();

        let mut cap = w.capture();
        let mid = (cap.chunks[0].start + cap.chunks[0].end) / 2;
        cap.gaps.push(file::Gap {
            start: mid, end: mid + 1000,
            reason: "injected".into(), lost: None,
        });

        let d = Decoder::new(Config::default()).decode(&cap);
        let t = &d.transactions[0];
        assert!(!t.complete);
        assert!(t.errors.contains(&ErrorKind::GapOverlap));
        assert_eq!(t.severity, Severity::Error);
    }

    #[test]
    fn every_field_carries_a_sample_range() {
        let mut w = Wire::new();
        w.start();
        w.byte(0x52 << 1, true);
        w.byte(0xDE, true);
        w.stop();

        for t in &decode(&w).transactions {
            for f in &t.fields {
                assert!(f.samples.last >= f.samples.first,
                        "field {} has a backwards range", f.name);
                assert!(f.end >= f.start, "field {} ends before it starts", f.name);
            }
        }
    }

    #[test]
    fn a_stop_with_nothing_open_is_an_event_not_a_transaction() {
        let mut w = Wire::new();
        w.edge(true, true);
        w.stop();
        let d = decode(&w);
        assert!(d.transactions.is_empty());
        assert_eq!(d.events.len(), 1);
        assert_eq!(d.events[0].kind, "stop_without_start");
    }

    /// Determinism is the replay acceptance criterion, so it is asserted rather
    /// than assumed.
    #[test]
    fn decoding_twice_gives_identical_output() {
        let mut w = Wire::new();
        w.start();
        w.byte(0x52 << 1, true);
        w.byte(0xDE, true);
        w.restart();
        w.byte((0x52 << 1) | 1, true);
        w.byte(0x11, false);
        w.stop();

        let cap = w.capture();
        let a = Decoder::new(Config::default()).decode(&cap);
        let b = Decoder::new(Config::default()).decode(&cap);
        assert_eq!(a, b);
    }
}
