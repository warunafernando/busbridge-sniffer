//! MDIO, decoded from raw edges.
//!
//! Section 5.5: clause 22 operations, the ST/OP/PHYAD/REGAD/TA/DATA fields,
//! preamble handling including the suppressed form, invalid turnaround
//! detection, and PHY/register-aware filtering.
//!
//! # The frame
//!
//! Thirty-two preamble ones, then ST, OP, PHYAD, REGAD, TA and sixteen data
//! bits. Data changes while MDC is low and is sampled on its rising edge, which
//! is the only timing rule in the protocol.
//!
//! # Turnaround is where the information is
//!
//! On a read, the controller stops driving for the first turnaround bit and the
//! PHY pulls the line low for the second. So a read whose second turnaround bit
//! is *high* means nothing answered - the bus is simply idling at its pull-up.
//! That is the difference between "register 2 of PHY 7 reads 0xFFFF" and "there
//! is no PHY 7", and a decoder that does not check it reports the first when it
//! should report the second. It is checked, and `no_turnaround` is why.
//!
//! # Clause 45
//!
//! Recognised by ST=00 and reported as such, with its five-bit device address
//! in place of a register address. The address/read/write/read-increment forms
//! are distinguished by OP. Full clause 45 sequencing - an address frame
//! followed by a data frame - is left to a later pass; each frame is decoded on
//! its own, which is correct and less than section 5.5 eventually wants.

#![forbid(unsafe_code)]

use decode::{apply_gap_rule, span, BusDecoder, Edge, Fields, SearchField};
use schema::{
    BusId, Decoded, DecoderInfo, ErrorKind, Event, FieldKind, Protocol, Severity,
    Transaction,
};

pub const DECODER_NAME: &str = "mdio";
pub const DECODER_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy)]
pub struct Channels {
    pub mdc: u8,
    pub mdio: u8,
}

impl Default for Channels {
    fn default() -> Self {
        Channels { mdc: 0, mdio: 1 }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bus: BusId,
    pub channels: Channels,
    /// How many preamble ones to require before a frame. Zero accepts the
    /// suppressed-preamble form that section 5.5 asks for.
    pub preamble_bits: u8,
    pub first_id: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bus: BusId(0),
            channels: Channels::default(),
            preamble_bits: 32,
            first_id: 1,
        }
    }
}

const FIELDS: &[SearchField] = &[
    SearchField { name: "phy", help: "the PHY address, 0 to 31" },
    SearchField { name: "reg", help: "the register address, 0 to 31" },
    SearchField { name: "dev", help: "the clause 45 device address" },
    SearchField { name: "data", help: "the sixteen-bit value" },
    SearchField { name: "op", help: "read, write, or a clause 45 form" },
];

pub struct Decoder {
    config: Config,
}

impl Decoder {
    pub fn new(config: Config) -> Self {
        Decoder { config }
    }
}

/// A bit sampled on a rising MDC edge, and where it came from.
struct Bit {
    value: bool,
    edge: usize,
    time: schema::Picos,
}

impl BusDecoder for Decoder {
    fn info(&self) -> DecoderInfo {
        DecoderInfo {
            name: DECODER_NAME.into(),
            version: DECODER_VERSION.into(),
            protocol: Protocol::Mdio,
            bus: self.config.bus,
            settings: vec![
                ("mdc_channel".into(), self.config.channels.mdc.to_string()),
                ("mdio_channel".into(), self.config.channels.mdio.to_string()),
                ("preamble_bits".into(), self.config.preamble_bits.to_string()),
            ],
        }
    }

    fn search_fields(&self) -> &'static [SearchField] {
        FIELDS
    }

    fn decode_edges(&self, edges: &[Edge], capture: &file::Capture) -> Decoded {
        let mut out = Decoded::default();

        // Every bit in the capture, sampled where the protocol says. Collected
        // first because a frame is found by looking at a run of them, and
        // walking edges twice is cheaper than the state machine it would take
        // to do it in one pass.
        let mut bits: Vec<Bit> = Vec::new();
        for i in 1..edges.len() {
            let rose = !edges[i - 1].line(self.config.channels.mdc)
                && edges[i].line(self.config.channels.mdc);
            if rose {
                bits.push(Bit {
                    value: edges[i].line(self.config.channels.mdio),
                    edge: i,
                    time: edges[i].time,
                });
            }
        }

        let mut id = self.config.first_id;
        let mut i = 0usize;

        while i + 32 <= bits.len() {
            // A frame starts at the first 0 after enough ones. With the
            // preamble suppressed, `preamble_bits` is 0 and any 0 will do.
            let mut ones = 0u8;
            while i < bits.len() && bits[i].value {
                ones = ones.saturating_add(1);
                i += 1;
            }
            if i >= bits.len() {
                break;
            }
            if ones < self.config.preamble_bits {
                // Not a preamble, so this zero is noise or the tail of
                // something else. Step over it rather than decoding rubbish.
                i += 1;
                continue;
            }

            let start = i;
            if start + 32 > bits.len() {
                out.events.push(Event {
                    start: bits[start].time,
                    end: bits[bits.len() - 1].time,
                    bus: Some(self.config.bus),
                    kind: "truncated_frame".into(),
                    message: format!(
                        "a frame started with only {} bits left in the capture",
                        bits.len() - start),
                    severity: Severity::Warning,
                    transaction: None,
                });
                break;
            }

            let take = |from: usize, count: usize| -> u32 {
                let mut v = 0u32;
                for b in &bits[from..from + count] {
                    v = (v << 1) | u32::from(b.value);
                }
                v
            };

            let st = take(start, 2);
            let op = take(start + 2, 2);
            let phy = take(start + 4, 5) as u8;
            let reg = take(start + 9, 5) as u8;
            let ta = take(start + 14, 2);
            let data = take(start + 16, 16) as u16;

            let first_edge = bits[start].edge;
            let last_edge = bits[start + 31].edge;
            let at = (bits[start].time, bits[start + 31].time);
            let samples = span(edges, first_edge, last_edge);

            let clause45 = st == 0b00;
            let mut errors = Vec::new();
            let mut severity = Severity::Info;
            let mut fields = Fields::new();

            let op_name = if clause45 {
                match op {
                    0b00 => "C45-ADDRESS",
                    0b01 => "C45-WRITE",
                    0b10 => "C45-READ-INC",
                    _ => "C45-READ",
                }
            } else if op == 0b10 {
                "READ"
            } else if op == 0b01 {
                "WRITE"
            } else {
                "BAD-OP"
            };

            if st != 0b01 && !clause45 {
                errors.push(ErrorKind::Framing);
                severity = Severity::Warning;
            }
            if op_name == "BAD-OP" {
                errors.push(ErrorKind::Framing);
                severity = Severity::Warning;
            }

            fields.text("op", op_name, at, samples);
            fields.number("phy", phy as u64, format!("{phy}"), FieldKind::Address,
                          at, samples);
            if clause45 {
                fields.number("dev", reg as u64, format!("{reg}"),
                              FieldKind::Address, at, samples);
            } else {
                fields.number("reg", reg as u64, format!("0x{reg:02X}"),
                              FieldKind::Address, at, samples);
            }
            fields.number("data", data as u64, format!("0x{data:04X}"),
                          FieldKind::Data, at, samples);

            // The turnaround check. On a read the PHY must pull the second bit
            // low; a high one means nothing answered, and the 0xFFFF that comes
            // with it is the pulled-up bus rather than a register value.
            let is_read = op_name == "READ" || op_name.contains("READ");
            let answered = ta & 0b01 == 0;
            if is_read && !answered {
                errors.push(ErrorKind::Framing);
                severity = Severity::Warning;
                fields.text("turnaround", "none", at, samples);
                fields.flag(Severity::Warning);
            } else {
                fields.text("turnaround", "ok", at, samples);
            }

            let mut complete = true;
            apply_gap_rule(capture, at.0, at.1, &mut errors, &mut complete,
                           &mut severity);

            let summary = if is_read && !answered {
                format!("{op_name} PHY {phy} REG 0x{reg:02X} — no turnaround: \
                         nothing answered")
            } else if clause45 {
                format!("{op_name} PORT {phy} DEV {reg} = 0x{data:04X}")
            } else {
                format!("{op_name} PHY {phy} REG 0x{reg:02X} = 0x{data:04X}")
            };

            out.transactions.push(Transaction {
                id,
                bus: self.config.bus,
                protocol: Protocol::Mdio,
                start: at.0,
                end: at.1,
                kind: op_name.into(),
                summary,
                severity,
                parent: None,
                fields: fields.take(),
                errors,
                samples,
                complete,
            });
            id += 1;
            i = start + 32;
        }

        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simulator::Mdio as Gen;

    fn decode(cap: &file::Capture) -> Decoded {
        Decoder::new(Config::default()).decode(cap)
    }

    #[test]
    fn a_clause_22_read_decodes_every_field() {
        let mut g = Gen::new(2_500_000);
        g.c22_read(1, 0x02, 0x0141, true);
        let d = decode(&g.wire.capture("t"));

        assert_eq!(d.transactions.len(), 1, "{:#?}", d.transactions);
        let t = &d.transactions[0];
        assert_eq!(t.kind, "READ");
        assert_eq!(t.summary, "READ PHY 1 REG 0x02 = 0x0141");
        assert!(t.errors.is_empty(), "{:?}", t.errors);

        let field = |name: &str| t.fields.iter().find(|f| f.name == name).unwrap();
        assert_eq!(field("phy").value, Some(1));
        assert_eq!(field("reg").value, Some(2));
        assert_eq!(field("data").value, Some(0x0141));
        assert_eq!(field("turnaround").display, "ok");
    }

    #[test]
    fn a_clause_22_write_decodes() {
        let mut g = Gen::new(2_500_000);
        g.c22_write(3, 0x00, 0x1200, true);
        let d = decode(&g.wire.capture("t"));
        assert_eq!(d.transactions[0].kind, "WRITE");
        assert_eq!(d.transactions[0].summary, "WRITE PHY 3 REG 0x00 = 0x1200");
    }

    /// The check that separates "the register reads all ones" from "nothing is
    /// there", which is the whole reason turnaround is decoded.
    #[test]
    fn a_read_with_no_turnaround_is_not_reported_as_data() {
        let mut g = Gen::new(2_500_000);
        g.c22_read_no_turnaround(7, 0x02, true);
        let d = decode(&g.wire.capture("t"));

        let t = &d.transactions[0];
        assert!(t.errors.contains(&ErrorKind::Framing), "{:?}", t.errors);
        assert!(t.summary.contains("no turnaround"), "{}", t.summary);
        assert_eq!(t.fields.iter().find(|f| f.name == "turnaround").unwrap().display,
                   "none");
    }

    #[test]
    fn several_frames_in_a_row_all_decode() {
        let mut g = Gen::new(2_500_000);
        g.c22_read(1, 0x02, 0x0141, true);
        g.c22_read(1, 0x03, 0x0DD1, true);
        g.c22_write(1, 0x00, 0x1200, true);
        let d = decode(&g.wire.capture("t"));

        assert_eq!(d.transactions.len(), 3, "{:#?}", d.transactions);
        assert_eq!(d.transactions[1].summary, "READ PHY 1 REG 0x03 = 0x0DD1");
        assert_eq!(d.transactions[2].kind, "WRITE");
        // Ids run in order, which replay depends on.
        assert_eq!(d.transactions.iter().map(|t| t.id).collect::<Vec<_>>(),
                   vec![1, 2, 3]);
    }

    #[test]
    fn a_suppressed_preamble_decodes_when_configured_for_it() {
        let mut g = Gen::new(2_500_000);
        g.c22_read(2, 0x05, 0xBEEF, false);       // no preamble at all
        let cap = g.wire.capture("t");

        // The default insists on 32 preamble bits, so it finds nothing.
        assert!(decode(&cap).transactions.is_empty());

        let config = Config { preamble_bits: 0, ..Config::default() };
        let d = Decoder::new(config).decode(&cap);
        assert_eq!(d.transactions.len(), 1, "{:#?}", d.transactions);
        assert_eq!(d.transactions[0].summary, "READ PHY 2 REG 0x05 = 0xBEEF");
    }

    #[test]
    fn every_field_traces_to_samples() {
        let mut g = Gen::new(2_500_000);
        g.c22_read(1, 0x02, 0x0141, true);
        let cap = g.wire.capture("t");
        let edges = cap.chunks[0].len() as u32;
        for t in &decode(&cap).transactions {
            for f in &t.fields {
                assert!(f.samples.last >= f.samples.first, "{}", f.name);
                assert!(f.samples.last < edges, "{} points past the chunk", f.name);
            }
        }
    }

    #[test]
    fn decoding_is_deterministic() {
        let mut g = Gen::new(2_500_000);
        g.c22_read(1, 0x02, 0x0141, true);
        g.c22_write(1, 0x00, 0x1200, true);
        let cap = g.wire.capture("t");
        assert_eq!(decode(&cap), decode(&cap));
    }
}
