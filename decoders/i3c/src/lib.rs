//! I3C SDR, decoded from raw edges.
//!
//! Section 5.2, and the one section 1.1 singles out: "excellent debug workflow
//! for I3C, including events that generic logic analyzers often present
//! poorly". That is the bar. A generic analyser shows I3C as I2C with odd
//! acknowledges; what it should show is ENTDAA assigning an address, a CCC by
//! name, and an in-band interrupt as an interrupt.
//!
//! # It looks like I2C and it is not
//!
//! Same two wires, same START and STOP, same nine bits to a byte. Three
//! differences, and every one of them is a place a generic decoder gets it
//! wrong:
//!
//! - **The ninth bit is not always an acknowledge.** On the address it is; in
//!   the data of an SDR transfer it is a T-bit, which is parity from the target
//!   on a read and an end-of-data signal from the controller on a write.
//!   Labelling a T-bit "NACK" is the single most misleading thing an I2C
//!   decoder does to an I3C capture.
//! - **0x7E is the broadcast address**, and a frame that begins with it is
//!   carrying a common command code rather than talking to a device.
//! - **A frame that opens with a target's own address and the read bit** is an
//!   in-band interrupt: the target asked, the controller did not.
//!
//! # What this does not do
//!
//! HDR modes. The architecture allows them - section 5.2 asks only that it does
//! - and this decodes SDR. An HDR entry pattern is recognised only insofar as it
//! does not decode as SDR, which shows as a framing error rather than as
//! confident nonsense.

#![forbid(unsafe_code)]

use decode::{apply_gap_rule, hex, span, BusDecoder, Edge, Fields, SearchField};
use schema::{
    BusId, Decoded, DecoderInfo, ErrorKind, Event, FieldKind, Picos, Protocol,
    Severity, Transaction,
};

pub const DECODER_NAME: &str = "i3c";
pub const DECODER_VERSION: &str = "1.0.0";

/// The broadcast address every CCC is addressed to.
pub const BROADCAST: u8 = 0x7E;

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
    pub first_id: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config { bus: BusId(0), channels: Channels::default(), first_id: 1 }
    }
}

const FIELDS: &[SearchField] = &[
    SearchField { name: "address", help: "the target's dynamic address" },
    SearchField { name: "ccc", help: "the common command code, by number" },
    SearchField { name: "command", help: "the common command code, by name" },
    SearchField { name: "pid", help: "the 48-bit provisional id seen in ENTDAA" },
    SearchField { name: "bcr", help: "bus characteristics register" },
    SearchField { name: "dcr", help: "device characteristics register" },
    SearchField { name: "mdb", help: "the mandatory data byte of an interrupt" },
];

/// The common command codes worth naming.
///
/// Not the whole table: a name is only worth having when it tells a reader
/// something the number does not, and the rest are shown as their number rather
/// than guessed at.
fn ccc_name(code: u8) -> Option<&'static str> {
    Some(match code {
        // Broadcast, 0x00-0x7F.
        0x00 => "ENEC",
        0x01 => "DISEC",
        0x02 => "ENTAS0",
        0x03 => "ENTAS1",
        0x04 => "ENTAS2",
        0x05 => "ENTAS3",
        0x06 => "RSTDAA",
        0x07 => "ENTDAA",
        0x08 => "DEFTGTS",
        0x09 => "SETMWL",
        0x0A => "SETMRL",
        0x0B => "ENTTM",
        0x0C => "SETBUSCON",
        0x1F => "ENDXFER",
        // 0x20-0x27 enter an HDR mode. ENTHDR0 is HDR-DDR, and seeing it is
        // the point at which SDR decoding stops meaning anything - see the
        // caller. This used to read 0x20 as SETAASA, which is 0x29, so every
        // HDR-DDR entry was reported as an address-assignment command with the
        // DDR frame behind it decoded as its arguments.
        0x20 => "ENTHDR0",
        0x21 => "ENTHDR1",
        0x22 => "ENTHDR2",
        0x23 => "ENTHDR3",
        0x24 => "ENTHDR4",
        0x25 => "ENTHDR5",
        0x26 => "ENTHDR6",
        0x27 => "ENTHDR7",
        0x28 => "SETXTIME",
        0x29 => "SETAASA",
        0x2A => "RSTACT",
        // Directed, 0x80-0xFF. The GET block was shifted by one here, so
        // GETBCR read as 0x8B when it is 0x8E - checked against this bench,
        // where `I3C:CCC:R 0x09 0x8E` returns the same BCR that ENTDAA
        // reported, and the same for GETDCR against the DCR.
        0x80 => "ENEC",
        0x81 => "DISEC",
        0x82 => "ENTAS0",
        0x83 => "ENTAS1",
        0x84 => "ENTAS2",
        0x85 => "ENTAS3",
        0x87 => "SETDASA",
        0x88 => "SETNEWDA",
        0x89 => "SETMWL",
        0x8A => "SETMRL",
        0x8B => "GETMWL",
        0x8C => "GETMRL",
        0x8D => "GETPID",
        0x8E => "GETBCR",
        0x8F => "GETDCR",
        0x90 => "GETSTATUS",
        0x91 => "GETACCCR",
        0x93 => "ENDXFER",
        0x94 => "GETMXDS",
        0x95 => "GETCAPS",
        _ => return None,
    })
}

pub struct Decoder {
    config: Config,
}

impl Decoder {
    pub fn new(config: Config) -> Self {
        Decoder { config }
    }
}

/// One byte and its ninth bit, lifted off the wire.
struct Byte {
    value: u8,
    ninth: bool,
    first_edge: usize,
    last_edge: usize,
    start: Picos,
    end: Picos,
}

/// One frame between a START and whatever ended it.
struct Frame {
    start: Picos,
    first_edge: usize,
    bytes: Vec<Byte>,
    restart: bool,
}

impl BusDecoder for Decoder {
    fn info(&self) -> DecoderInfo {
        DecoderInfo {
            name: DECODER_NAME.into(),
            version: DECODER_VERSION.into(),
            protocol: Protocol::I3c,
            bus: self.config.bus,
            settings: vec![
                ("scl_channel".into(), self.config.channels.scl.to_string()),
                ("sda_channel".into(), self.config.channels.sda.to_string()),
            ],
        }
    }

    fn search_fields(&self) -> &'static [SearchField] {
        FIELDS
    }

    fn decode_edges(&self, edges: &[Edge], capture: &file::Capture) -> Decoded {
        let mut out = Decoded::default();
        let scl = self.config.channels.scl;
        let sda = self.config.channels.sda;

        let mut frames: Vec<(Frame, Option<Picos>)> = Vec::new();
        let mut frame: Option<Frame> = None;
        let mut value: u8 = 0;
        let mut nbits: u8 = 0;
        let mut byte_first = 0usize;

        for i in 1..edges.len() {
            let prev = edges[i - 1];
            let now = edges[i];

            // SDA moving while SCL stays high is framing, exactly as in I2C.
            if prev.line(sda) != now.line(sda) && prev.line(scl) && now.line(scl) {
                /*
                 * Except once per read, where it is the bus changing hands.
                 *
                 * A private read hands SDA to the target as soon as its address
                 * has been acknowledged, and SDA moving while the clock is held
                 * is exactly the shape of a START or a STOP. It is neither: it
                 * is the turnaround, and it falls at one identifiable place -
                 * the frame has its address byte and nothing since.
                 *
                 * Left in, the frame ends at its address and the payload after
                 * it is discarded for want of a START: `0x09 R` where the bus
                 * carried `0x09 R 40 11`. Measured, with the guard disabled -
                 * see a_read_handover_does_not_split_the_transfer, which fails
                 * exactly that way without this and is the only thing in the
                 * suite that does.
                 *
                 * Only the first one, and only after a read address. Later in
                 * the frame the controller takes SDA back to raise the STOP,
                 * and that one is real: suppressing it too would run every read
                 * into whatever followed. A zero-length read ends at the same
                 * boundary this fires on and is deliberately not swallowed -
                 * a_zero_length_read_still_ends_where_it_ends pins that.
                 *
                 * What this guard is *not*: evidenced from this bench. It was
                 * written against captures that were being corrupted upstream
                 * by a host-library bug - the `0x08 W 88 91 99 A2` it used to
                 * cite was that corruption, not a turnaround - and with clean
                 * captures nothing here triggers it. Every SDA move with the
                 * clock held is accounted for as a START, a STOP or a STOP's
                 * setup, at 1.07 and 1.96 MHz, with none at this byte boundary.
                 *
                 * So it is kept on the strength of the protocol rather than of
                 * a capture: a target that releases SDA under a held clock is
                 * permitted, the resulting mis-decode is silent and plausible,
                 * and the simulator can produce the waveform even though this
                 * bench cannot. Anyone deleting it should reproduce that test
                 * first, not reason about it.
                 */
                let turnaround = frame.as_ref().is_some_and(|f| {
                    nbits == 0
                        && f.bytes.len() == 1
                        && (f.bytes[0].value & 1) == 1
                });
                if turnaround {
                    continue;
                }
                if now.line(sda) {
                    if let Some(f) = frame.take() {
                        /*
                         * A frame that closed without completing a byte is not
                         * a transfer, and at the end of a read it is the STOP's
                         * own setup.
                         *
                         * To raise a STOP the controller needs SDA low while
                         * SCL is high, and the target has just left SDA high.
                         * So it takes the line back, pulls it down with the
                         * clock already held, and releases it one period later.
                         * The pull has the exact shape of a START.
                         *
                         * Measured on a 1 MHz capture: the fall 14 ticks before
                         * a clock edge, the rise 33 after it. A clock does land
                         * in between, so bits are notionally sampled - which is
                         * why "no bits" is the wrong test and "no completed
                         * byte" is the right one. Reported as a frame it put
                         * "a START with no byte after it" after every read, on
                         * ten captures of known-good traffic out of ten.
                         *
                         * This is the capture firmware's rule, and matching it
                         * is what makes the two decoders agree on identical
                         * input: dec_i3c_stop() drops a frame whose START is
                         * still held - held being exactly "no byte has
                         * completed" - and records the reason as
                         * short-frame-dropped.
                         *
                         * Dropped from the transactions, not from the output. A
                         * frame can also be cut short because the bus glitched
                         * or a device let go mid-byte, and that is worth
                         * seeing; it just is not a transfer and does not belong
                         * in a list of them. A frame still open when the edges
                         * run out is a different thing again - unfinished
                         * rather than never begun - and is handled after this
                         * loop with its own Truncated error.
                         */
                        if f.bytes.is_empty() {
                            out.events.push(Event {
                                start: f.start,
                                end: now.time,
                                bus: Some(self.config.bus),
                                kind: "framing_setup".into(),
                                message: "START and STOP with no complete byte \
                                          between them - the setup for the \
                                          STOP, not a transfer"
                                    .into(),
                                severity: Severity::Info,
                                transaction: None,
                            });
                        } else {
                            frames.push((f, Some(now.time)));
                        }
                    }
                } else {
                    let restart = frame.is_some();
                    if let Some(f) = frame.take() {
                        frames.push((f, Some(now.time)));
                    }
                    frame = Some(Frame {
                        start: now.time,
                        first_edge: i,
                        bytes: Vec::new(),
                        restart,
                    });
                }
                value = 0;
                nbits = 0;
                continue;
            }

            let rose = !prev.line(scl) && now.line(scl);
            if !rose || frame.is_none() {
                continue;
            }

            if nbits == 0 {
                byte_first = i;
            }
            if nbits < 8 {
                value = (value << 1) | u8::from(now.line(sda));
                nbits += 1;
                continue;
            }

            // The ninth bit. What it means depends on where in the frame it
            // falls, which is decided below rather than here - here it is only
            // recorded.
            let f = frame.as_mut().unwrap();
            f.bytes.push(Byte {
                value,
                ninth: now.line(sda),
                first_edge: byte_first,
                last_edge: i,
                start: edges[byte_first].time,
                end: now.time,
            });
            value = 0;
            nbits = 0;
        }

        if let Some(f) = frame {
            frames.push((f, None));
        }

        // ENTDAA carries its discovery data in a second frame, after a
        // repeated START. Merged here rather than reported as two, because two
        // is what a generic analyser shows and it is unreadable: the first byte
        // of the provisional id lands where an address would be, so the second
        // frame appears to address a device that does not exist.
        let is_entdaa = |f: &Frame| {
            f.bytes.first().map(|b| b.value >> 1) == Some(BROADCAST)
                && f.bytes.get(1).map(|b| b.value) == Some(0x07)
        };

        let mut merged: Vec<(Frame, Option<Picos>)> = Vec::new();
        let mut pending: Option<(Frame, Option<Picos>)> = None;

        for (f, ended) in frames {
            if let Some((mut acc, acc_end)) = pending.take() {
                if f.restart {
                    // Part of the same ENTDAA: take its bytes and its end.
                    acc.bytes.extend(f.bytes);
                    pending = Some((acc, ended));
                    continue;
                }
                merged.push((acc, acc_end));
            }
            if is_entdaa(&f) {
                pending = Some((f, ended));
            } else {
                merged.push((f, ended));
            }
        }
        if let Some(rest) = pending {
            merged.push(rest);
        }

        let mut id = self.config.first_id;
        for (f, ended) in merged {
            let complete = ended.is_some();
            let end = ended.unwrap_or_else(|| {
                f.bytes.last().map(|b| b.end).unwrap_or(f.start)
            });
            out.transactions.push(self.interpret(edges, capture, id, f, end,
                                                 complete, &mut out.events));
            id += 1;
        }

        out
    }
}

impl Decoder {
    #[allow(clippy::too_many_arguments)]
    fn interpret(
        &self,
        edges: &[Edge],
        capture: &file::Capture,
        id: u64,
        f: Frame,
        end: Picos,
        complete: bool,
        _events: &mut Vec<Event>,
    ) -> Transaction {
        let mut fields = Fields::new();
        let mut errors = Vec::new();
        let mut severity = Severity::Info;
        let mut complete = complete;
        let samples = span(edges, f.first_edge,
                           f.bytes.last().map(|b| b.last_edge).unwrap_or(f.first_edge));

        let Some(first) = f.bytes.first() else {
            errors.push(ErrorKind::Framing);
            return Transaction {
                id,
                bus: self.config.bus,
                protocol: Protocol::I3c,
                start: f.start,
                end,
                kind: "FRAMING".into(),
                summary: "a START with no byte after it".into(),
                severity: Severity::Warning,
                parent: None,
                fields: fields.take(),
                errors,
                samples,
                complete: false,
            };
        };

        let address = first.value >> 1;
        let read = first.value & 1 != 0;
        let acked = !first.ninth;
        let at = (first.start, first.end);
        let addr_samples = span(edges, first.first_edge, first.last_edge);

        fields.number("address", address as u64, format!("0x{address:02X}"),
                      FieldKind::Address, at, addr_samples);
        fields.text("direction", if read { "R" } else { "W" }, at, addr_samples);
        fields.text("ack", if acked { "ACK" } else { "NACK" }, at, addr_samples);
        if !acked {
            fields.flag(Severity::Notice);
            errors.push(ErrorKind::Nack);
        }

        let payload: Vec<u8> = f.bytes[1..].iter().map(|b| b.value).collect();

        /*
         * ENTDAA's payload has no T-bits to check.
         *
         * During dynamic address assignment the target drives its 48-bit
         * provisioned id, BCR and DCR as sixty-four *contiguous* bits - there
         * is no ninth bit between them, because those bytes are arbitration
         * data rather than a transfer. Testing them as parity flags a correct
         * ENTDAA, which is how the golden corpus caught this: the frame went
         * from `info` to `warning` with nothing wrong on the wire.
         *
         * The CCC byte itself is an ordinary write byte and is still checked;
         * only the discovery data behind it is exempt.
         */
        let entdaa = (address == 0x7E) && !read
            && payload.first().is_some_and(|c| *c == 0x07);

        for (n, b) in f.bytes[1..].iter().enumerate() {
            fields.number(format!("data[{n}]"), b.value as u64,
                          format!("0x{:02X}", b.value), FieldKind::Data,
                          (b.start, b.end), span(edges, b.first_edge, b.last_edge));
            // The ninth bit of a data byte is a T-bit, not an acknowledge -
            // and it does not mean the same thing in both directions.
            //
            // On a *write* the controller drives it, and it is odd parity over
            // the eight data bits: a mismatch is a real check failure and worth
            // reporting. On a *read* the target drives it, and it means "more
            // data follows" - 1 for every byte including the last when the
            // controller ends the transfer itself with RDTERM. It is not
            // parity, and testing it as parity flags perfectly good data.
            //
            // This was the wrong way round: parity was checked on reads only,
            // which is exactly the case where it does not apply. A capture of
            // six correct bytes came back as `check_failed`, and the bytes were
            // right - the rule was wrong. The same mistake is recorded on the
            // controller side of this bench, where assuming parity on reads
            // made a working capture look broken for a day.
            if read {
                // Recorded, not judged. A 0 before the last byte means the
                // target ended the transfer early, which is worth seeing.
                if !b.ninth {
                    fields.text(format!("tbit[{n}]"), "end of data",
                                (b.start, b.end),
                                span(edges, b.first_edge, b.last_edge));
                }
            } else if entdaa && n > 0 {
                // Arbitration data, not a transfer: nothing to check.
            } else if (b.value.count_ones() % 2 == 0) != b.ninth {
                fields.text(format!("tbit[{n}]"), "parity failed",
                            (b.start, b.end), span(edges, b.first_edge, b.last_edge));
                fields.flag(Severity::Warning);
                if !errors.contains(&ErrorKind::CheckFailed) {
                    errors.push(ErrorKind::CheckFailed);
                    severity = Severity::Warning;
                }
            }
        }

        // What kind of frame this is. The order matters: broadcast first,
        // because 0x7E with a read bit is still a CCC frame and not an
        // interrupt from device 0x7E.
        let (kind, summary) = if address == BROADCAST {
            let ccc = payload.first().copied();
            match ccc {
                Some(code) => {
                    let name = ccc_name(code);
                    fields.number("ccc", code as u64, format!("0x{code:02X}"),
                                  FieldKind::Data, at, addr_samples);
                    if let Some(n) = name {
                        fields.text("command", n, at, addr_samples);
                    }
                    let shown = name.unwrap_or("CCC");
                    if (0x20..=0x27).contains(&code) {
                        /*
                         * Entering an HDR mode. SDR decoding stops meaning
                         * anything here, and saying so is the whole point.
                         *
                         * HDR-DDR clocks data on both edges and frames it as
                         * 16-bit words with their own parity, so an SDR decoder
                         * pointed at the frame behind this command produces
                         * bytes that are wrong and look fine. This decoder does
                         * not support HDR, and the honest output is to name the
                         * entry, flag it, and stop - rather than to report the
                         * DDR payload as if it were arguments to a command.
                         */
                        fields.text("hdr", "enters HDR mode; SDR decoding stops here",
                                    at, addr_samples);
                        fields.flag(Severity::Notice);
                        ("CCC".to_string(),
                         format!("{shown} - enters HDR mode, not decoded"))
                    } else if code == 0x07 {
                        // ENTDAA. The bytes after the command are the target's
                        // 48-bit provisional id, its BCR and DCR, and then the
                        // address the controller assigned it - which is the
                        // thing an engineer opened the capture to see.
                        self.describe_entdaa(&payload, &mut fields, at, addr_samples)
                    } else {
                        ("CCC".to_string(),
                         format!("{shown} broadcast{}",
                                 if payload.len() > 1 {
                                     format!("  {}", hex(&payload[1..]))
                                 } else {
                                     String::new()
                                 }))
                    }
                }
                None => ("CCC".to_string(), "broadcast with no command".to_string()),
            }
        } else if read && payload.len() <= 2 && f.restart {
            // A short read that follows a repeated start is ordinary; an
            // interrupt is a frame of its own that opens with the target's
            // address. Distinguished by the restart, which is the only thing on
            // the wire that separates them.
            ("PRIVATE-R".to_string(),
             format!("0x{address:02X} R {}", hex(&payload)))
        } else if read && !f.restart && payload.len() == 1 {
            fields.number("mdb", payload[0] as u64, format!("0x{:02X}", payload[0]),
                          FieldKind::Data, at, addr_samples);
            ("IBI".to_string(),
             format!("0x{address:02X} in-band interrupt, MDB 0x{:02X}", payload[0]))
        } else if read {
            ("PRIVATE-R".to_string(),
             format!("0x{address:02X} R {}", hex(&payload)))
        } else {
            ("PRIVATE-W".to_string(),
             format!("0x{address:02X} W {}", hex(&payload)))
        };

        if !complete {
            errors.push(ErrorKind::Truncated);
            severity = severity.max(Severity::Warning);
        }
        apply_gap_rule(capture, f.start, end, &mut errors, &mut complete,
                       &mut severity);
        if !errors.is_empty() && severity == Severity::Info {
            severity = Severity::Notice;
        }

        Transaction {
            id,
            bus: self.config.bus,
            protocol: Protocol::I3c,
            start: f.start,
            end,
            kind,
            summary,
            severity,
            parent: None,
            fields: fields.take(),
            errors,
            samples,
            complete,
        }
    }

    /// ENTDAA's payload: PID, BCR, DCR, and the address assigned.
    fn describe_entdaa(
        &self,
        payload: &[u8],
        fields: &mut Fields,
        at: (Picos, Picos),
        samples: schema::SampleRef,
    ) -> (String, String) {
        // The payload is the command, then whatever the repeated START
        // re-addressed with, then six PID bytes, BCR, DCR and the address the
        // controller assigned. The re-addressing byte is skipped: it is 0x7E
        // again with the read bit set, and it is framing rather than data.
        let after_command = &payload[1..];
        let discovery = match after_command.first() {
            Some(&b) if b >> 1 == BROADCAST => &after_command[1..],
            _ => after_command,
        };
        if discovery.len() < 9 {
            return ("ENTDAA".to_string(),
                    format!("ENTDAA, {} byte(s) of discovery", discovery.len()));
        }
        let pid = &discovery[0..6];
        let bcr = discovery[6];
        let dcr = discovery[7];
        let assigned = discovery[8] >> 1;

        let pid_value = pid.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
        fields.number("pid", pid_value, hex(pid), FieldKind::Data, at, samples);
        fields.number("bcr", bcr as u64, format!("0x{bcr:02X}"), FieldKind::Data,
                      at, samples);
        fields.number("dcr", dcr as u64, format!("0x{dcr:02X}"), FieldKind::Data,
                      at, samples);
        fields.number("assigned", assigned as u64, format!("0x{assigned:02X}"),
                      FieldKind::Address, at, samples);

        ("ENTDAA".to_string(),
         format!("ENTDAA: PID {} BCR 0x{bcr:02X} DCR 0x{dcr:02X} → address \
                  0x{assigned:02X}", hex(pid)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simulator::I2c as Gen;

    fn decode(cap: &file::Capture) -> Decoded {
        Decoder::new(Config::default()).decode(cap)
    }

    #[test]
    fn a_broadcast_ccc_is_named() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte(BROADCAST << 1, true);
        g.byte(0x00, true);                     // ENEC
        g.byte(0x0B, true);
        g.stop();

        let d = decode(&g.wire.capture("t"));
        assert_eq!(d.transactions.len(), 1, "{:#?}", d.transactions);
        let t = &d.transactions[0];
        assert_eq!(t.kind, "CCC");
        assert!(t.summary.starts_with("ENEC broadcast"), "{}", t.summary);
        assert_eq!(t.fields.iter().find(|f| f.name == "command").unwrap().display,
                   "ENEC");
    }

    #[test]
    fn an_unknown_ccc_is_shown_by_number_rather_than_guessed() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte(BROADCAST << 1, true);
        g.byte(0x5E, true);                     // not in the table
        g.stop();

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert!(t.summary.starts_with("CCC broadcast"), "{}", t.summary);
        assert_eq!(t.fields.iter().find(|f| f.name == "ccc").unwrap().value,
                   Some(0x5E));
        assert!(t.fields.iter().all(|f| f.name != "command"));
    }

    /// The thing a generic analyser shows as a run of unexplained bytes.
    #[test]
    fn entdaa_reports_the_address_it_assigned() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte(BROADCAST << 1, true);
        g.byte(0x07, true);                     // ENTDAA
        for b in [0x04, 0xA0, 0x00, 0x00, 0x12, 0x34, 0x06, 0x2B] {
            g.byte(b, true);
        }
        g.byte(0x52 << 1, true);
        g.stop();

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert_eq!(t.kind, "ENTDAA");
        assert!(t.summary.contains("address 0x52"), "{}", t.summary);
        let field = |n: &str| t.fields.iter().find(|f| f.name == n).unwrap();
        assert_eq!(field("bcr").value, Some(0x06));
        assert_eq!(field("dcr").value, Some(0x2B));
        assert_eq!(field("assigned").value, Some(0x52));
    }

    #[test]
    fn a_private_write_and_read_decode() {
        let mut g = Gen::new(1_000_000);
        g.write(0x52, &[0x10, 0x20], true);
        g.idle(8);
        g.start();
        g.byte(0x52 << 1, true);
        g.repeated_start();
        g.byte((0x52 << 1) | 1, true);
        g.byte(0x34, true);
        g.byte(0x8A, true);
        g.stop();

        let d = decode(&g.wire.capture("t"));
        assert_eq!(d.transactions[0].kind, "PRIVATE-W");
        assert_eq!(d.transactions[0].summary, "0x52 W 10 20");
        let read = d.transactions.iter().find(|t| t.kind == "PRIVATE-R").unwrap();
        assert!(read.summary.contains("34 8A"), "{}", read.summary);
    }

    /// An interrupt is a frame the target started, and showing it as an
    /// ordinary read is exactly the "presented poorly" the specification means.
    #[test]
    fn an_in_band_interrupt_is_labelled_as_one() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte((0x52 << 1) | 1, true);
        g.byte(0x01, true);                     // the mandatory data byte
        g.stop();

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert_eq!(t.kind, "IBI");
        assert!(t.summary.contains("in-band interrupt"), "{}", t.summary);
        assert_eq!(t.fields.iter().find(|f| f.name == "mdb").unwrap().value, Some(1));
    }

    /// The T-bit is parity, not an acknowledge. A decoder that reads it as an
    /// acknowledge reports a NACK on perfectly good data.
    #[test]
    fn a_data_bytes_ninth_bit_is_not_treated_as_an_acknowledge() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte(0x52 << 1, true);
        // 0x03 has two bits set, so odd parity is 1, which on this generator is
        // written as "not acked". An I2C decoder would call that a NACK.
        g.byte(0x03, false);
        g.stop();

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert!(!t.errors.contains(&ErrorKind::Nack),
                "a T-bit was reported as a NACK: {:?}", t.errors);
        assert!(t.summary.contains("03"));
    }

    /// A read's T-bit is "more data follows", not parity, so bytes whose
    /// parity happens not to match must not be reported as a check failure.
    ///
    /// This is the case the rule had backwards: parity was tested on reads
    /// only, which is the one direction where it does not apply. Six correct
    /// bytes off a real bus came back flagged.
    #[test]
    fn a_reads_t_bit_is_not_parity() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte((0x09 << 1) | 1, true);          // address, read, acked
        // T = 1 on every byte, which is what a target drives on a read. This
        // generator writes the ninth bit as !ack, so `false` puts a 1 there.
        // 0x40 has one bit set, so odd parity would be 0 - if this were
        // checked as parity, the byte would be flagged.
        for v in [0x40u8, 0x11, 0x22] {
            g.byte(v, false);
        }
        g.stop();

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert!(!t.errors.contains(&ErrorKind::CheckFailed),
                "a read T-bit was tested as parity: {:?}", t.errors);
    }

    /// A write's T-bit *is* odd parity, and a mismatch there is a real finding.
    #[test]
    fn a_writes_t_bit_is_parity() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte(0x09 << 1, true);                // address, write, acked
        // Odd parity counts the T-bit too: 0x40 has one bit set, so T must be
        // 0 to keep the total odd. Measured on hardware, a write of 00 40 puts
        // T=1 on 0x00 and T=0 on 0x40. This generator writes the ninth bit as
        // !ack, so `false` drives the 1 that is wrong here.
        g.byte(0x40, false);
        g.stop();

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert!(t.errors.contains(&ErrorKind::CheckFailed),
                "a bad write parity bit went unreported: {:?}", t.errors);
    }

    /// CCC codes, against the ones this bench has confirmed on hardware:
    /// GETBCR at 0x8E returns the BCR that ENTDAA reported, and 0x20 is the
    /// entry an I3C controller emits to start HDR-DDR.
    #[test]
    fn ccc_codes_match_the_spec() {
        assert_eq!(ccc_name(0x20), Some("ENTHDR0"));
        assert_eq!(ccc_name(0x29), Some("SETAASA"));
        assert_eq!(ccc_name(0x8E), Some("GETBCR"));
        assert_eq!(ccc_name(0x8F), Some("GETDCR"));
        assert_eq!(ccc_name(0x8D), Some("GETPID"));
        assert_eq!(ccc_name(0x90), Some("GETSTATUS"));
        assert_eq!(ccc_name(0x87), Some("SETDASA"));
        // Unknown codes are shown as numbers rather than guessed at.
        assert_eq!(ccc_name(0x7A), None);
    }

    /// The handover at the start of a read's data phase does not split it.
    ///
    /// The target acknowledges the address and then lets SDA go before the data
    /// phase drives it. Released under a held clock the line rises with SCL
    /// high - a STOP's shape - and if the data phase takes it back down under
    /// the same held clock it falls again, a START's shape. Either lands one
    /// byte into a frame that is not ending; read as framing they end the
    /// transfer at the address and decode the payload as a second frame, a bit
    /// out of step.
    ///
    /// Note what this test is and is not. **No capture taken on this bench
    /// contains this edge.** Every SDA move with the clock held is accounted
    /// for as a START, a STOP, or a STOP's setup - checked at 1.07 and 1.96
    /// MHz, ten of ten each, with none at the byte boundary where a handover
    /// would land. So the guard protects against a target this bench does not
    /// have, and this is the only thing that exercises it. It is kept because
    /// the failure it prevents is silent and produces plausible bytes, which is
    /// the class of defect this decoder exists to avoid - but it is defended by
    /// construction, not by evidence, and that distinction belongs here where
    /// the next person will read it.
    #[test]
    fn a_read_handover_does_not_split_the_transfer() {
        for redrive in [false, true] {
            let mut g = Gen::new(1_000_000);
            g.start();
            g.read_address_with_handover(0x09, redrive);
            g.i3c_read_byte(0x40);
            g.i3c_read_byte(0x11);
            g.stop();

            let d = decode(&g.wire.capture("t"));
            let shape = if redrive { "released then re-driven" } else { "released" };
            assert_eq!(d.transactions.len(), 1,
                       "handover ({shape}) split the read: {:?}",
                       d.transactions.iter().map(|t| t.summary.clone())
                           .collect::<Vec<_>>());
            assert!(d.transactions[0].summary.contains("40 11"),
                    "handover ({shape}) lost the payload: {}",
                    d.transactions[0].summary);
        }
    }

    /// The guard must not swallow a STOP that genuinely belongs there.
    ///
    /// It fires at a byte boundary one byte into a read, and a zero-length
    /// read - address, acknowledge, STOP - ends at exactly that point. The two
    /// are the same shape, so suppressing the handover risks eating the end of
    /// a legitimate transfer, and that would be a worse bug than the one the
    /// guard was written for: a transfer reported as running on past its own
    /// end, rather than one reported twice.
    #[test]
    fn a_zero_length_read_still_ends_where_it_ends() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte((0x09 << 1) | 1, true);
        g.stop();
        g.idle(8);
        g.write(0x22, &[0xAB], true);

        let d = decode(&g.wire.capture("t"));
        assert_eq!(d.transactions.len(), 2,
                   "the zero-length read and the write after it did not both                     survive: {:?}",
                   d.transactions.iter().map(|t| t.summary.clone())
                       .collect::<Vec<_>>());
        assert!(d.transactions[0].summary.contains("0x09"),
                "{}", d.transactions[0].summary);
        assert!(d.transactions[1].summary.contains("AB"),
                "the write after the read was swallowed: {}",
                d.transactions[1].summary);
    }

    /// The fall that sets up a STOP is not a frame.
    ///
    /// At the end of a read the target leaves SDA high, so the controller
    /// pulls it low with the clock still high before releasing it - a fall
    /// shaped exactly like a START. Reported as one it put "a START with no
    /// byte after it" after every read on hardware, ten captures out of ten.
    #[test]
    fn a_stop_raised_from_a_high_line_is_not_a_frame() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte((0x09 << 1) | 1, true);
        g.i3c_read_byte(0x40);
        g.i3c_read_byte(0x11);
        g.stop_from_high();

        let d = decode(&g.wire.capture("t"));
        assert_eq!(d.transactions.len(), 1,
                   "the STOP's setup was decoded as a frame of its own: {:?}",
                   d.transactions.iter().map(|t| t.summary.clone())
                       .collect::<Vec<_>>());
        assert!(d.transactions[0].errors.is_empty(),
                "a clean read was flagged: {:?}", d.transactions[0].errors);
    }

    /// Dropped from the transactions, not from the output. A frame cut short
    /// mid-byte is not a transfer, but it is evidence and is still reported.
    #[test]
    fn a_frame_cut_off_mid_byte_is_reported_as_an_event() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.bits(0b1010, 4);
        g.stop();

        let d = decode(&g.wire.capture("t"));
        assert!(d.transactions.is_empty(),
                "a frame with no complete byte was listed as a transfer: {:?}",
                d.transactions.iter().map(|t| t.summary.clone())
                    .collect::<Vec<_>>());
        assert_eq!(d.events.len(), 1,
                   "a half-clocked frame vanished with nothing said");
    }

    #[test]
    fn a_frame_with_no_stop_is_incomplete() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte(0x52 << 1, true);
        g.byte(0xAA, true);

        let t = &decode(&g.wire.capture("t")).transactions[0];
        assert!(!t.complete);
        assert!(t.errors.contains(&ErrorKind::Truncated));
    }

    #[test]
    fn decoding_is_deterministic() {
        let mut g = Gen::new(1_000_000);
        g.start();
        g.byte(BROADCAST << 1, true);
        g.byte(0x07, true);
        g.stop();
        g.write(0x52, &[1, 2], true);
        let cap = g.wire.capture("t");
        assert_eq!(decode(&cap), decode(&cap));
    }
}
