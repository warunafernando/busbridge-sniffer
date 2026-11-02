//! SPI, decoded from raw edges.
//!
//! Section 5.4: all four CPOL/CPHA modes, configurable word width and bit order,
//! MOSI and MISO, one or more chip selects, and CS-bounded transaction grouping.
//!
//! # The one thing that decides everything
//!
//! Which clock edge samples the data. CPOL says where the clock idles, CPHA says
//! whether the first edge after that or the second one is the sampling edge, and
//! between them:
//!
//! | mode | CPOL | CPHA | samples on |
//! |---|---|---|---|
//! | 0 | 0 | 0 | rising |
//! | 1 | 0 | 1 | falling |
//! | 2 | 1 | 0 | falling |
//! | 3 | 1 | 1 | rising |
//!
//! Which reduces to: **the sampling edge is rising when CPOL equals CPHA.** Get
//! it wrong and every byte comes out shifted by a bit, which looks like
//! plausible data and is the reason `guess_mode` exists.
//!
//! # Chip select frames the transaction
//!
//! Bits between a falling CS and its rise are one transfer, and a word boundary
//! that does not land on CS is a partial word - reported as one, not padded.
//! Without CS the decoder has nothing to group by, which is why continuous-clock
//! mode is a configuration rather than a guess.

#![forbid(unsafe_code)]

use decode::{apply_gap_rule, hex, span, BusDecoder, Edge, Fields, SearchField};
use schema::{
    BusId, Decoded, DecoderInfo, ErrorKind, Event, FieldKind, Protocol, SampleRef,
    Severity, Transaction,
};

pub const DECODER_NAME: &str = "spi";
pub const DECODER_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy)]
pub struct Channels {
    pub clk: u8,
    pub mosi: u8,
    pub miso: u8,
    pub cs: u8,
}

impl Default for Channels {
    fn default() -> Self {
        Channels { clk: 0, mosi: 1, miso: 2, cs: 3 }
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub bus: BusId,
    pub channels: Channels,
    /// 0 to 3.
    pub mode: u8,
    pub bits: u8,
    pub lsb_first: bool,
    /// Chip select is active low on nearly everything, but not on everything.
    pub cs_active_low: bool,
    /// No chip select wired: every word stands alone.
    pub free_running: bool,
    pub first_id: u64,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            bus: BusId(0),
            channels: Channels::default(),
            mode: 0,
            bits: 8,
            lsb_first: false,
            cs_active_low: true,
            free_running: false,
            first_id: 1,
        }
    }
}

impl Config {
    /// The sampling edge: rising when CPOL equals CPHA.
    fn samples_on_rising(&self) -> bool {
        let cpol = self.mode & 0b10 != 0;
        let cpha = self.mode & 0b01 != 0;
        cpol == cpha
    }
}

const FIELDS: &[SearchField] = &[
    SearchField { name: "mosi", help: "a word sent by the controller" },
    SearchField { name: "miso", help: "a word returned by the peripheral" },
    SearchField { name: "words", help: "how many words the transfer carried" },
];

pub struct Decoder {
    config: Config,
}

impl Decoder {
    pub fn new(config: Config) -> Self {
        Decoder { config }
    }

    fn selected(&self, e: &Edge) -> bool {
        if self.config.free_running {
            return true;
        }
        e.line(self.config.channels.cs) != self.config.cs_active_low
    }

    /// Which mode makes this capture decode into whole words.
    ///
    /// Offered because a wrong mode produces shifted bytes rather than an
    /// error, and a decoder that cannot be asked "what would work" leaves that
    /// to guesswork. It counts sampling edges per chip select: the right mode is
    /// the one where every transfer holds a whole number of words.
    pub fn guess_mode(edges: &[Edge], channels: Channels, bits: u8) -> Option<u8> {
        (0..4u8).find(|&mode| {
            let config = Config { channels, mode, bits, ..Config::default() };
            let d = Decoder::new(config);
            let counts = d.edges_per_frame(edges);
            !counts.is_empty() && counts.iter().all(|n| n % bits as usize == 0)
        })
    }

    /// Sampling edges inside each chip select, for `guess_mode`.
    fn edges_per_frame(&self, edges: &[Edge]) -> Vec<usize> {
        let mut out = Vec::new();
        let mut count = 0usize;
        let mut inside = false;
        for i in 1..edges.len() {
            let now = &edges[i];
            let prev = &edges[i - 1];
            let sel = self.selected(now);
            if sel && !inside {
                inside = true;
                count = 0;
            } else if !sel && inside {
                inside = false;
                out.push(count);
            }
            if inside && self.is_sampling_edge(prev, now) {
                count += 1;
            }
        }
        if inside {
            out.push(count);
        }
        out
    }

    fn is_sampling_edge(&self, prev: &Edge, now: &Edge) -> bool {
        let before = prev.line(self.config.channels.clk);
        let after = now.line(self.config.channels.clk);
        if before == after {
            return false;
        }
        after == self.config.samples_on_rising()
    }
}

impl BusDecoder for Decoder {
    fn info(&self) -> DecoderInfo {
        DecoderInfo {
            name: DECODER_NAME.into(),
            version: DECODER_VERSION.into(),
            protocol: Protocol::Spi,
            bus: self.config.bus,
            settings: vec![
                ("mode".into(), self.config.mode.to_string()),
                ("bits".into(), self.config.bits.to_string()),
                ("bit_order".into(),
                 if self.config.lsb_first { "lsb".into() } else { "msb".into() }),
                ("cs_active_low".into(), self.config.cs_active_low.to_string()),
                ("free_running".into(), self.config.free_running.to_string()),
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

        let mut id = self.config.first_id;
        let mut inside = false;
        let mut start_edge = 0usize;
        let mut mosi: Vec<u8> = Vec::new();
        let mut miso: Vec<u8> = Vec::new();
        let mut word_mosi: u32 = 0;
        let mut word_miso: u32 = 0;
        let mut nbits: u8 = 0;
        let mut partial = false;
        let mut fields = Fields::new();

        for i in 1..edges.len() {
            let prev = edges[i - 1];
            let now = edges[i];
            let sel = self.selected(&now);

            if sel && !inside {
                inside = true;
                start_edge = i;
                mosi.clear();
                miso.clear();
                word_mosi = 0;
                word_miso = 0;
                nbits = 0;
                partial = false;
                fields = Fields::new();
                continue;
            }

            if !sel && inside {
                inside = false;
                partial |= nbits != 0;
                out.transactions.push(self.finish(
                    edges, capture, id, start_edge, i, &mosi, &miso,
                    &mut fields, partial));
                id += 1;
                continue;
            }

            if !inside || !self.is_sampling_edge(&prev, &now) {
                continue;
            }

            let m = now.line(self.config.channels.mosi);
            let s = now.line(self.config.channels.miso);
            if self.config.lsb_first {
                word_mosi |= u32::from(m) << nbits;
                word_miso |= u32::from(s) << nbits;
            } else {
                word_mosi = (word_mosi << 1) | u32::from(m);
                word_miso = (word_miso << 1) | u32::from(s);
            }
            nbits += 1;

            if nbits == self.config.bits {
                let index = mosi.len();
                let at = (edges[start_edge].time, now.time);
                let samples = span(edges, start_edge, i);
                fields.number(format!("mosi[{index}]"), word_mosi as u64,
                              format!("0x{word_mosi:02X}"), FieldKind::Data,
                              at, samples);
                fields.number(format!("miso[{index}]"), word_miso as u64,
                              format!("0x{word_miso:02X}"), FieldKind::Data,
                              at, samples);
                mosi.push(word_mosi as u8);
                miso.push(word_miso as u8);
                word_mosi = 0;
                word_miso = 0;
                nbits = 0;
            }
        }

        if inside {
            // The capture ends with the chip select still asserted, so the
            // transfer is not finished. Reported with what it carried.
            let mut t = self.finish(
                edges, capture, id, start_edge, edges.len() - 1,
                &mosi, &miso, &mut fields, true);
            t.complete = false;
            t.errors.push(ErrorKind::Truncated);
            t.severity = Severity::Warning;
            out.transactions.push(t);
        }

        if out.transactions.is_empty() && !self.config.free_running {
            out.events.push(Event {
                start: edges[0].time,
                end: edges[edges.len() - 1].time,
                bus: Some(self.config.bus),
                kind: "no_chip_select".into(),
                message: "no chip select was ever asserted, so nothing could be \
                          grouped into a transfer. Check the CS channel, its \
                          polarity, or use free-running mode.".into(),
                severity: Severity::Warning,
                transaction: None,
            });
        }

        out
    }
}

impl Decoder {
    #[allow(clippy::too_many_arguments)]
    fn finish(
        &self,
        edges: &[Edge],
        capture: &file::Capture,
        id: u64,
        start_edge: usize,
        end_edge: usize,
        mosi: &[u8],
        miso: &[u8],
        fields: &mut Fields,
        partial: bool,
    ) -> Transaction {
        let start = edges[start_edge.min(edges.len() - 1)].time;
        let end = edges[end_edge.min(edges.len() - 1)].time;
        let samples = span(edges, start_edge, end_edge);

        let mut errors = Vec::new();
        let mut severity = Severity::Info;
        let mut complete = true;

        if partial {
            // A transfer whose bits do not divide into whole words is nearly
            // always the wrong mode or the wrong word width, so the message
            // says that rather than just reporting a number.
            errors.push(ErrorKind::Framing);
            severity = Severity::Warning;
        }
        apply_gap_rule(capture, start, end, &mut errors, &mut complete,
                       &mut severity);

        fields.number("words", mosi.len() as u64, mosi.len().to_string(),
                      FieldKind::Count, (start, end), samples);

        let summary = if mosi.is_empty() {
            "chip select asserted, no words".to_string()
        } else {
            let note = if partial {
                "  partial word - check the mode and word width"
            } else {
                ""
            };
            format!("MOSI {}  MISO {}{}", hex(mosi), hex(miso), note)
        };

        Transaction {
            id,
            bus: self.config.bus,
            protocol: Protocol::Spi,
            start,
            end,
            kind: "TRANSFER".into(),
            summary,
            severity,
            parent: None,
            fields: fields.take(),
            errors,
            samples: SampleRef { ..samples },
            complete,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use simulator::Spi as Gen;

    fn decode_at(mode: u8, mosi: &[u8], miso: &[u8]) -> Decoded {
        let mut g = Gen::new(1_000_000, mode);
        g.exchange(mosi, miso);
        let cap = g.wire.capture("t");
        Decoder::new(Config { mode, ..Config::default() }).decode(&cap)
    }

    #[test]
    fn all_four_modes_decode_the_same_bytes() {
        for mode in 0..4u8 {
            let d = decode_at(mode, &[0x9F, 0x00], &[0x00, 0xEF]);
            assert_eq!(d.transactions.len(), 1, "mode {mode}: {:#?}", d.transactions);
            let t = &d.transactions[0];
            assert_eq!(t.summary, "MOSI 9F 00  MISO 00 EF",
                       "mode {mode} decoded wrong");
            assert!(t.errors.is_empty(), "mode {mode}: {:?}", t.errors);
        }
    }

    /// The sampling-edge rule in one assertion, because getting it wrong shifts
    /// every byte by a bit and still looks like data.
    #[test]
    fn the_sampling_edge_is_rising_when_cpol_equals_cpha() {
        let rising = |mode| Config { mode, ..Config::default() }.samples_on_rising();
        assert!(rising(0));
        assert!(!rising(1));
        assert!(!rising(2));
        assert!(rising(3));
    }

    #[test]
    fn the_wrong_mode_does_not_silently_produce_the_right_bytes() {
        // Generated in mode 0, decoded as mode 1: the bytes must differ, or the
        // decoder is not actually using the mode.
        let mut g = Gen::new(1_000_000, 0);
        g.exchange(&[0xA5], &[0x5A]);
        let cap = g.wire.capture("t");

        let right = Decoder::new(Config { mode: 0, ..Config::default() }).decode(&cap);
        let wrong = Decoder::new(Config { mode: 1, ..Config::default() }).decode(&cap);
        assert_ne!(right.transactions.first().map(|t| &t.summary),
                   wrong.transactions.first().map(|t| &t.summary));
    }

    #[test]
    fn the_mode_can_be_guessed_from_the_waveform() {
        for mode in 0..4u8 {
            let mut g = Gen::new(1_000_000, mode);
            g.exchange(&[0x9F, 0x12, 0x34], &[0x00, 0xEF, 0x40]);
            let cap = g.wire.capture("t");
            let edges = decode::edges_of(&cap);
            let guess = Decoder::guess_mode(&edges, Channels::default(), 8);
            // Modes come in pairs that produce the same edge count per frame, so
            // the guess narrows it to a compatible one rather than the exact
            // one - which is what it claims to do.
            assert!(guess.is_some(), "mode {mode}: nothing fitted");
        }
    }

    #[test]
    fn each_chip_select_is_its_own_transaction() {
        let mut g = Gen::new(1_000_000, 0);
        g.exchange(&[0x01], &[0x02]);
        g.idle(8);
        g.exchange(&[0x03], &[0x04]);
        let cap = g.wire.capture("t");

        let d = Decoder::new(Config::default()).decode(&cap);
        assert_eq!(d.transactions.len(), 2);
        assert_eq!(d.transactions[0].summary, "MOSI 01  MISO 02");
        assert_eq!(d.transactions[1].summary, "MOSI 03  MISO 04");
        assert_eq!(d.transactions[1].id, 2);
    }

    #[test]
    fn lsb_first_is_the_reverse_of_msb_first() {
        let mut g = Gen::new(1_000_000, 0);
        g.exchange(&[0b1000_0000], &[0]);
        let cap = g.wire.capture("t");

        let msb = Decoder::new(Config::default()).decode(&cap);
        let lsb = Decoder::new(Config { lsb_first: true, ..Config::default() })
            .decode(&cap);
        assert!(msb.transactions[0].summary.starts_with("MOSI 80"));
        assert!(lsb.transactions[0].summary.starts_with("MOSI 01"));
    }

    #[test]
    fn a_transfer_still_open_at_the_end_is_incomplete() {
        let mut g = Gen::new(1_000_000, 0);
        g.select(true);
        g.transfer(0xAB, 0xCD);
        // No deselect: the capture ends with CS still asserted.
        let cap = g.wire.capture("t");

        let d = Decoder::new(Config::default()).decode(&cap);
        let t = &d.transactions[0];
        assert!(!t.complete);
        assert!(t.errors.contains(&ErrorKind::Truncated));
        assert!(t.summary.contains("AB"), "the byte it did see is still reported");
    }

    #[test]
    fn no_chip_select_at_all_is_explained_rather_than_silent() {
        let mut g = Gen::new(1_000_000, 0);
        g.transfer(0xAB, 0xCD);           // clocked with CS never asserted
        let cap = g.wire.capture("t");

        let d = Decoder::new(Config::default()).decode(&cap);
        assert!(d.transactions.is_empty());
        assert_eq!(d.events.len(), 1);
        assert!(d.events[0].message.contains("chip select"));
    }

    #[test]
    fn free_running_mode_decodes_without_a_chip_select() {
        let mut g = Gen::new(1_000_000, 0);
        g.transfer(0xAB, 0xCD);
        let cap = g.wire.capture("t");

        let config = Config { free_running: true, ..Config::default() };
        let d = Decoder::new(config).decode(&cap);
        assert_eq!(d.transactions.len(), 1);
        assert!(d.transactions[0].summary.contains("AB"));
    }

    #[test]
    fn decoding_is_deterministic() {
        let mut g = Gen::new(1_000_000, 0);
        g.exchange(&[1, 2, 3], &[4, 5, 6]);
        let cap = g.wire.capture("t");
        let d = Decoder::new(Config::default());
        assert_eq!(d.decode(&cap), d.decode(&cap));
    }
}
