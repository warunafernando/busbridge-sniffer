//! CAN 2.0B, decoded from raw edges.
//!
//! Section 5.7: standard and extended identifiers, RTR/IDE, DLC and payload,
//! CRC and ACK interpretation, bit stuffing and error-frame visibility, and
//! frame-level error classification.
//!
//! # Destuffing comes first
//!
//! CAN has no clock line and stays synchronised by forbidding runs: after five
//! identical bits the transmitter inserts one of the opposite value. So the bits
//! on the wire are not the bits of the frame, and everything - field positions,
//! the CRC, the payload - is wrong until the stuff bits are removed. That is the
//! first thing this does, and a stuff bit that is not the expected complement is
//! a **stuff error**, which is a real bus fault and not a decoding difficulty.
//!
//! # The CRC and the acknowledge answer different questions
//!
//! The CRC says the bits arrived intact. The ACK slot says *somebody was
//! listening*: a transmitter drives it recessive and any receiver that liked the
//! frame pulls it dominant. A frame with a good CRC and no acknowledge is the
//! signature of a bus with one node on it - the commonest reason a CAN link will
//! not come up - and it is reported as exactly that rather than as a generic
//! error.
//!
//! # CAN-FD
//!
//! Detected and reported, not decoded. FD moves the CRC to 17 or 21 bits with a
//! stuff-bit counter, changes the DLC encoding above 8, and switches bit rate
//! mid-frame at BRS. Half-implementing that would produce confident wrong
//! payloads; an FD frame is labelled `FD` with its identifier and left at that.

#![forbid(unsafe_code)]

use decode::{apply_gap_rule, hex, span, BusDecoder, Edge, Fields, SearchField};
use schema::{
    BusId, Decoded, DecoderInfo, ErrorKind, Event, FieldKind, Picos, Protocol,
    Severity, Transaction,
};

pub const DECODER_NAME: &str = "can";
pub const DECODER_VERSION: &str = "1.0.0";

#[derive(Debug, Clone)]
pub struct Config {
    pub bus: BusId,
    /// Which channel carries the bus.
    pub channel: u8,
    /// None measures it from the capture.
    pub bitrate: Option<u64>,
    /// A capture taken downstream of an inverting transceiver.
    pub inverted: bool,
    pub first_id: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config { bus: BusId(0), channel: 0, bitrate: None, inverted: false,
                 first_id: 1 }
    }
}

const FIELDS: &[SearchField] = &[
    SearchField { name: "id", help: "the identifier, standard or extended" },
    SearchField { name: "dlc", help: "the data length code" },
    SearchField { name: "data", help: "a payload byte, as data[n]" },
    SearchField { name: "crc", help: "the fifteen-bit checksum as sent" },
    SearchField { name: "ack", help: "ack or none" },
    SearchField { name: "rtr", help: "1 for a remote request" },
    SearchField { name: "ide", help: "1 for an extended identifier" },
];

/// CRC-15, polynomial 0x4599, over destuffed bits.
pub fn crc15(bits: &[bool]) -> u16 {
    let mut crc: u16 = 0;
    for &b in bits {
        let top = (crc >> 14) & 1 == 1;
        crc = (crc << 1) & 0x7FFF;
        if top != b {
            crc ^= 0x4599;
        }
    }
    crc & 0x7FFF
}

pub struct Decoder {
    config: Config,
}

/// One bit off the wire, with the edge it was sampled from.
#[derive(Clone, Copy)]
struct WireBit {
    value: bool,
    edge: usize,
    time: Picos,
}

impl Decoder {
    pub fn new(config: Config) -> Self {
        Decoder { config }
    }

    /// The shortest interval between edges is one bit time.
    pub fn measure_bitrate(edges: &[Edge]) -> Option<u64> {
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

    fn level(&self, e: &Edge) -> bool {
        e.line(self.config.channel) != self.config.inverted
    }
}

/// What destuffing produced.
struct Destuffed {
    /// The frame's own bits, stuff bits removed.
    bits: Vec<WireBit>,
    /// How many wire bits that took, so the caller knows where the unstuffed
    /// tail - CRC delimiter, acknowledge, end of frame - begins.
    consumed: usize,
    /// False when six identical bits appeared where the rule forbids them.
    ok: bool,
}

/// Remove stuff bits, stopping after `want` frame bits.
///
/// Bounded rather than running to the end of the input, because stuffing stops
/// at the end of the CRC and the end of frame that follows is seven identical
/// recessive bits. Destuffing through that always finds a violation, and
/// reported a stuff error on every correct frame until this took a limit.
///
/// A stuff bit is the complement of the run before it, so one that is not is a
/// bus error rather than something to decode around.
fn destuff(bits: &[WireBit], want: usize) -> Destuffed {
    let mut out = Vec::with_capacity(want.min(bits.len()));
    let mut run = 0u8;
    let mut last: Option<bool> = None;
    let mut ok = true;
    let mut i = 0usize;

    while i < bits.len() && out.len() < want {
        let b = bits[i];
        if Some(b.value) == last {
            run += 1;
        } else {
            run = 1;
            last = Some(b.value);
        }
        out.push(b);
        i += 1;

        if out.len() == want {
            break;
        }
        if run == 5 {
            match bits.get(i) {
                Some(stuffed) => {
                    if stuffed.value == b.value {
                        // Six identical bits: the rule was broken.
                        ok = false;
                        break;
                    }
                    last = Some(stuffed.value);
                    run = 1;
                    i += 1;
                }
                None => break,
            }
        }
    }
    Destuffed { bits: out, consumed: i, ok }
}

/// Destuffed bits from the start of frame through the end of the CRC.
fn frame_length(extended: bool, payload_bytes: usize) -> usize {
    let header = if extended {
        // SOF, ID A, SRR, IDE, ID B, RTR, r1, r0, DLC
        1 + 11 + 1 + 1 + 18 + 1 + 1 + 1 + 4
    } else {
        // SOF, ID, RTR, IDE, r0, DLC
        1 + 11 + 1 + 1 + 1 + 4
    };
    header + payload_bytes * 8 + 15
}

impl BusDecoder for Decoder {
    fn info(&self) -> DecoderInfo {
        DecoderInfo {
            name: DECODER_NAME.into(),
            version: DECODER_VERSION.into(),
            protocol: Protocol::Can,
            bus: self.config.bus,
            settings: vec![
                ("channel".into(), self.config.channel.to_string()),
                ("bitrate".into(), match self.config.bitrate {
                    Some(b) => b.to_string(),
                    None => "auto".into(),
                }),
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

        let bitrate = match self.config.bitrate.or_else(|| Self::measure_bitrate(edges)) {
            Some(b) if b > 0 => b,
            _ => {
                out.events.push(Event {
                    start: edges[0].time,
                    end: edges[edges.len() - 1].time,
                    bus: Some(self.config.bus),
                    kind: "no_bitrate".into(),
                    message: "could not measure a bit rate from this capture".into(),
                    severity: Severity::Error,
                    transaction: None,
                });
                return out;
            }
        };
        let bit_ps = 1_000_000_000_000u64 / bitrate;
        let last_time = capture.index.last_time.max(edges[edges.len() - 1].time);

        // Sample the whole capture at bit centres. CAN resynchronises on every
        // recessive-to-dominant edge, and this does not - which is fine for a
        // capture whose bit rate is exact, and is why a wrong rate shows as
        // stuff errors rather than as quiet corruption.
        let mut id = self.config.first_id;
        let mut i = 0usize;

        while i + 1 < edges.len() {
            // A frame starts when the bus leaves idle: recessive to dominant.
            if !(self.level(&edges[i]) && !self.level(&edges[i + 1])) {
                i += 1;
                continue;
            }
            let sof_time = edges[i + 1].time;
            let sof_edge = i + 1;

            // Read bits until the bus has been idle for long enough that the
            // frame must have ended - eleven recessive bits is the interframe
            // space, and anything after that belongs to the next frame.
            let mut wire: Vec<WireBit> = Vec::new();
            let mut cursor = sof_edge;
            let mut n = 0u64;
            let mut recessive_run = 0u32;
            loop {
                let t = sof_time + bit_ps * n + bit_ps / 2;
                if t > last_time {
                    break;
                }
                while cursor + 1 < edges.len() && edges[cursor + 1].time <= t {
                    cursor += 1;
                }
                let value = self.level(&edges[cursor]);
                wire.push(WireBit { value, edge: cursor, time: t });
                recessive_run = if value { recessive_run + 1 } else { 0 };
                if recessive_run >= 11 && n > 20 {
                    break;
                }
                n += 1;
                if n > 200 {
                    break;               // longer than any 2.0B frame can be
                }
            }

            match self.parse(&wire, edges, capture, id, sof_time, sof_edge) {
                Some(t) => {
                    let consumed = t.1;
                    out.transactions.push(t.0);
                    id += 1;
                    // Resume *at* the frame's last edge, not past it. End of
                    // frame and the interframe space are recessive and record
                    // no edges, so the next edge is the next start of frame -
                    // and stepping one further lands on it and misses it.
                    i = consumed.max(sof_edge);
                    continue;
                }
                None => {
                    out.events.push(Event {
                        start: sof_time,
                        end: wire.last().map(|b| b.time).unwrap_or(sof_time),
                        bus: Some(self.config.bus),
                        kind: "not_a_frame".into(),
                        message: "the bus left idle but what followed does not \
                                  destuff into a frame - an error flag, a \
                                  collision, or the wrong bit rate".into(),
                        severity: Severity::Warning,
                        transaction: None,
                    });
                    i = sof_edge;
                }
            }
            // Step past what was consumed, at minimum one edge.
            i += 1;
        }

        out
    }
}

impl Decoder {
    /// Parse one frame's worth of wire bits. Returns the transaction and the
    /// edge index it ended at.
    #[allow(clippy::too_many_arguments)]
    fn parse(
        &self,
        wire: &[WireBit],
        edges: &[Edge],
        capture: &file::Capture,
        id: u64,
        sof_time: Picos,
        sof_edge: usize,
    ) -> Option<(Transaction, usize)> {
        if wire.len() < 20 {
            return None;
        }
        // Enough to read IDE, which decides how much further the header runs.
        let probe = destuff(wire, 39);
        if probe.bits.len() < 19 {
            return None;
        }
        let bits = probe.bits;

        let at = |n: usize| bits.get(n).map(|b| b.value).unwrap_or(true);
        let field = |from: usize, count: usize| -> u32 {
            let mut v = 0u32;
            for n in from..from + count {
                v = (v << 1) | u32::from(at(n));
            }
            v
        };

        if at(0) {
            return None;                 // the first bit must be dominant
        }

        // The bit layout, counted from the start of frame:
        //
        //   standard   0 SOF | 1..11 ID | 12 RTR | 13 IDE | 14 r0 | 15..18 DLC
        //   extended   0 SOF | 1..11 ID A | 12 SRR | 13 IDE | 14..31 ID B
        //              | 32 RTR | 33 r1 | 34 r0 | 35..38 DLC
        //
        // Written out because getting it off by one shifts every field after
        // it, and the frame still parses - it just decodes a data frame as a
        // remote one and reads the payload from the wrong place.
        let ide = at(13);
        let mut cursor;
        let identifier;
        let rtr;
        let extended;

        if !ide {
            identifier = field(1, 11);
            rtr = at(12);
            extended = false;
            cursor = 15;
        } else {
            // Extended: ID A, SRR, IDE, ID B, RTR, r1, r0.
            let id_a = field(1, 11);
            let id_b = field(14, 18);
            identifier = (id_a << 18) | id_b;
            rtr = at(32);
            extended = true;
            cursor = 35;
        }

        // The FD bit sits where r0 is in a 2.0B frame. Recessive there means
        // this is an FD frame, and everything after it is laid out differently.
        let fd = at(cursor - 1);

        let dlc = field(cursor, 4) as usize;
        cursor += 4;

        // Now the length is known, destuff exactly the frame - through the end
        // of the CRC and not one bit further.
        // A remote frame carries no data field whatever its DLC says, which is
        // the whole point of it. Taken from the RTR bit parsed above rather
        // than from a position relative to the DLC - that landed on r0, so a
        // remote frame was given a payload it does not have, the frame length
        // came out too long, and destuffing ran on into the end of frame and
        // reported a stuff error.
        let payload_bytes = if rtr { 0 } else { dlc.min(8) };
        let want = frame_length(extended, payload_bytes);
        let full = destuff(wire, want);
        let stuffing_ok = full.ok;
        let bits = full.bits;
        let tail = &wire[full.consumed.min(wire.len())..];
        let at = |n: usize| bits.get(n).map(|b| b.value).unwrap_or(true);
        let field = |from: usize, count: usize| -> u32 {
            let mut v = 0u32;
            for n in from..from + count {
                v = (v << 1) | u32::from(at(n));
            }
            v
        };

        let mut fields = Fields::new();
        let mut errors = Vec::new();
        let mut severity = Severity::Info;
        let mut complete = true;

        // The read ran on into the interframe space to find the end of the
        // frame; the transaction should not claim all of it.
        let end_bit = bits.len().saturating_sub(1);
        // The frame ends at its acknowledge delimiter, not out in the
        // interframe space the read ran on into looking for the end.
        let end_time = tail.get(2).map(|b| b.time)
            .unwrap_or_else(|| bits[end_bit].time);
        let end_edge = tail.get(2).map(|b| b.edge).unwrap_or(bits[end_bit].edge);
        let whole = span(edges, sof_edge, end_edge);
        let span_at = (sof_time, end_time);

        fields.number("id", identifier as u64,
                      if extended { format!("0x{identifier:08X}") }
                      else { format!("0x{identifier:03X}") },
                      FieldKind::Address, span_at, whole);
        fields.number("ide", u64::from(extended), if extended { "1" } else { "0" },
                      FieldKind::Flag, span_at, whole);
        fields.number("rtr", u64::from(rtr), if rtr { "1" } else { "0" },
                      FieldKind::Flag, span_at, whole);
        fields.number("dlc", dlc as u64, dlc.to_string(), FieldKind::Count,
                      span_at, whole);

        if fd {
            // Reported, not decoded. See the note at the top of the file.
            fields.text("format", "CAN-FD", span_at, whole);
            errors.push(ErrorKind::Other("fd_not_decoded".into()));
            severity = Severity::Notice;
            let t = Transaction {
                id,
                bus: self.config.bus,
                protocol: Protocol::Can,
                start: sof_time,
                end: span_at.1,
                kind: "FD".into(),
                summary: format!(
                    "0x{identifier:03X} CAN-FD frame — the identifier is decoded, \
                     the payload is not"),
                severity,
                parent: None,
                fields: fields.take(),
                errors,
                samples: whole,
                complete: true,
            };
            return Some((t, end_edge));
        }

        let payload_len = if rtr { 0 } else { dlc.min(8) };
        let mut data = Vec::with_capacity(payload_len);
        for n in 0..payload_len {
            let byte = field(cursor + n * 8, 8) as u8;
            data.push(byte);
        }
        cursor += payload_len * 8;

        if cursor + 15 > bits.len() {
            // The frame runs past what was captured.
            errors.push(ErrorKind::Truncated);
            severity = Severity::Warning;
            complete = false;
        }

        let sent_crc = if cursor + 15 <= bits.len() {
            field(cursor, 15) as u16
        } else {
            0
        };
        let computed = crc15(&bits[..cursor.min(bits.len())]
            .iter().map(|b| b.value).collect::<Vec<_>>());

        for (n, b) in data.iter().enumerate() {
            fields.number(format!("data[{n}]"), *b as u64, format!("0x{b:02X}"),
                          FieldKind::Data, span_at, whole);
        }
        fields.number("crc", sent_crc as u64, format!("0x{sent_crc:04X}"),
                      FieldKind::Data, span_at, whole);

        if complete && sent_crc != computed {
            fields.text("crc_check",
                        format!("failed: computed 0x{computed:04X}"), span_at, whole);
            fields.flag(Severity::Warning);
            errors.push(ErrorKind::CheckFailed);
            severity = Severity::Warning;
        }

        // The acknowledge slot is in the unstuffed tail: CRC delimiter, then
        // the slot. Read from there rather than from the frame, because
        // stuffing stopped at the CRC and these bits were never stuffed.
        let acked = complete && tail.get(1).map(|b| !b.value).unwrap_or(false);
        fields.text("ack", if acked { "ack" } else { "none" }, span_at, whole);
        if complete && !acked {
            fields.flag(Severity::Warning);
            errors.push(ErrorKind::Nack);
            severity = severity.max(Severity::Warning);
        }

        if !stuffing_ok {
            errors.push(ErrorKind::Framing);
            severity = Severity::Warning;
        }

        apply_gap_rule(capture, sof_time, span_at.1, &mut errors, &mut complete,
                       &mut severity);

        let kind = if rtr { "REMOTE" } else { "DATA" };
        let mut summary = if extended {
            format!("0x{identifier:08X} ext {kind}")
        } else {
            format!("0x{identifier:03X} {kind}")
        };
        if rtr {
            summary.push_str(&format!(" DLC {dlc}"));
        } else {
            summary.push_str(&format!(" {}", hex(&data)));
        }
        if complete && !acked {
            summary.push_str("  — nobody acknowledged");
        }
        if errors.contains(&ErrorKind::CheckFailed) {
            summary.push_str("  — CRC failed");
        }
        if !stuffing_ok {
            summary.push_str("  — stuff error");
        }

        let t = Transaction {
            id,
            bus: self.config.bus,
            protocol: Protocol::Can,
            start: sof_time,
            end: span_at.1,
            kind: kind.into(),
            summary,
            severity,
            parent: None,
            fields: fields.take(),
            errors,
            samples: whole,
            complete,
        };
        Some((t, end_edge))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simulator::Can as Gen;

    fn decode(cap: &file::Capture) -> Decoded {
        Decoder::new(Config::default()).decode(cap)
    }

    #[test]
    fn a_standard_data_frame_decodes() {
        let mut g = Gen::new(500_000);
        g.frame(0x123, false, &[0xDE, 0xAD, 0xBE, 0xEF], false);
        g.idle(20);

        let d = decode(&g.wire.capture("t"));
        assert_eq!(d.transactions.len(), 1, "{:#?}", d.transactions);
        let t = &d.transactions[0];
        assert_eq!(t.kind, "DATA");
        assert_eq!(t.summary, "0x123 DATA DE AD BE EF");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
        let f = |n: &str| t.fields.iter().find(|x| x.name == n).unwrap();
        assert_eq!(f("id").value, Some(0x123));
        assert_eq!(f("dlc").value, Some(4));
        assert_eq!(f("ack").display, "ack");
    }

    #[test]
    fn an_extended_identifier_decodes() {
        let mut g = Gen::new(500_000);
        g.frame(0x12AB_CDE, true, &[0x01], false);
        g.idle(20);

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert!(t.summary.contains("ext"), "{}", t.summary);
        let f = |n: &str| t.fields.iter().find(|x| x.name == n).unwrap();
        assert_eq!(f("id").value, Some(0x12AB_CDE));
        assert_eq!(f("ide").value, Some(1));
    }

    #[test]
    fn a_remote_frame_carries_no_payload() {
        let mut g = Gen::new(500_000);
        g.frame(0x200, false, &[0, 0, 0], true);
        g.idle(20);

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert_eq!(t.kind, "REMOTE");
        assert!(t.summary.contains("DLC 3"), "{}", t.summary);
        assert!(t.fields.iter().all(|f| !f.name.starts_with("data[")));
    }

    /// Bit stuffing is the rule that makes the wire bits differ from the frame
    /// bits, so a payload that forces stuffing is the test that matters.
    #[test]
    fn a_payload_that_forces_stuff_bits_still_decodes() {
        let mut g = Gen::new(500_000);
        // Runs of identical bits everywhere: 0x00 and 0xFF both force stuffing.
        g.frame(0x000, false, &[0x00, 0x00, 0xFF, 0xFF], false);
        g.idle(20);

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert_eq!(t.summary, "0x000 DATA 00 00 FF FF");
        assert!(t.errors.is_empty(), "{:?}", t.errors);
    }

    /// A good CRC and no acknowledge is a bus with one node on it, and saying
    /// so is more use than "error".
    #[test]
    fn a_frame_nobody_acknowledged_says_so() {
        let mut g = Gen::new(500_000);
        g.frame_unacked(0x321, &[0xAA]);
        g.idle(20);

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert!(t.errors.contains(&ErrorKind::Nack), "{:?}", t.errors);
        assert!(t.summary.contains("nobody acknowledged"), "{}", t.summary);
        // The CRC was fine, so that must not also be flagged.
        assert!(!t.errors.contains(&ErrorKind::CheckFailed));
    }

    #[test]
    fn a_wrong_crc_is_caught() {
        let mut g = Gen::new(500_000);
        g.frame_bad_crc(0x111, &[0x55]);
        g.idle(20);

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert!(t.errors.contains(&ErrorKind::CheckFailed), "{:?}", t.errors);
        assert!(t.summary.contains("CRC failed"), "{}", t.summary);
    }

    #[test]
    fn the_crc_matches_the_generators() {
        let bits: Vec<bool> = vec![false, true, false, false, true, true, true];
        assert_eq!(crc15(&bits), simulator::can::crc15(&bits),
                   "the decoder and the generator must compute the same CRC, or \
                    every test here is checking one mistake against itself");
    }

    #[test]
    fn several_frames_in_a_row_all_decode() {
        let mut g = Gen::new(500_000);
        g.frame(0x100, false, &[0x01], false);
        g.idle(20);
        g.frame(0x200, false, &[0x02, 0x03], false);
        g.idle(20);
        g.frame(0x300, false, &[], false);
        g.idle(20);

        let d = decode(&g.wire.capture("t"));
        assert_eq!(d.transactions.len(), 3, "{:#?}",
                   d.transactions.iter().map(|t| &t.summary).collect::<Vec<_>>());
        assert_eq!(d.transactions[1].summary, "0x200 DATA 02 03");
        assert_eq!(d.transactions.iter().map(|t| t.id).collect::<Vec<_>>(),
                   vec![1, 2, 3]);
    }

    #[test]
    fn the_bitrate_can_be_measured() {
        let mut g = Gen::new(250_000);
        g.frame(0x123, false, &[0xAA], false);
        g.idle(20);
        let cap = g.wire.capture("t");
        let edges = decode::edges_of(&cap);
        let measured = Decoder::measure_bitrate(&edges).unwrap();
        assert!((measured as i64 - 250_000).abs() < 2_000,
                "measured {measured}");
    }

    #[test]
    fn decoding_is_deterministic() {
        let mut g = Gen::new(500_000);
        g.frame(0x123, false, &[1, 2, 3], false);
        g.idle(20);
        let cap = g.wire.capture("t");
        assert_eq!(decode(&cap), decode(&cap));
    }

    #[test]
    fn every_field_traces_to_samples() {
        let mut g = Gen::new(500_000);
        g.frame(0x123, false, &[0xDE, 0xAD], false);
        g.idle(20);
        let cap = g.wire.capture("t");
        let edges = cap.chunks[0].len() as u32;
        for t in &decode(&cap).transactions {
            for f in &t.fields {
                assert!(f.samples.last >= f.samples.first, "{}", f.name);
                assert!(f.samples.last < edges, "{} points past the chunk", f.name);
            }
        }
    }
}
