//! The decoder SDK contract, and the pieces every decoder needs.
//!
//! Phase 0 lists this among the things to define before decoders exist, and the
//! reason showed up as soon as there was a second one: `Edge` and the walk over
//! a capture's chunks lived inside the I2C decoder, so UART would have had to
//! either depend on I2C or copy them.
//!
//! # What a decoder is
//!
//! A thing that turns edges into normalized transactions. It does not draw, it
//! does not know about files beyond reading one, and it never reports a byte it
//! did not see. Appendix B is the full list; the three that shape this
//! interface are:
//!
//!   - every field carries the sample range it came from;
//!   - a capture gap overlapping a transaction produces an incomplete result
//!     rather than confident data;
//!   - the same input produces the same output, ids included.
//!
//! # Registering search fields
//!
//! A decoder declares the fields it emits so the query language can offer them
//! without knowing the protocol. That is what makes search protocol-native
//! without the parser growing a case per protocol.

#![forbid(unsafe_code)]

use schema::{
    DecoderInfo, Decoded, ErrorKind, Field, FieldKind, Picos, SampleRef, Severity,
};

/// One entry of a capture, flattened out of whatever chunk it came from.
///
/// The first entry of a chunk is the initial state rather than a transition -
/// see `file::SampleChunk` - and it arrives here like any other, which is what
/// lets a decoder compare against the level before the first edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Edge {
    pub time: Picos,
    /// All channels, one bit each, at this moment.
    pub lines: u8,
    pub chunk: u32,
    pub index: u32,
}

impl Edge {
    pub fn line(&self, channel: u8) -> bool {
        self.lines & (1 << channel) != 0
    }
}

/// Flatten a capture into edges.
pub fn edges_of(capture: &file::Capture) -> Vec<Edge> {
    let mut out = Vec::new();
    for chunk in &capture.chunks {
        for i in 0..chunk.len() {
            out.push(Edge {
                time: chunk.times[i],
                lines: chunk.lines[i],
                chunk: chunk.id,
                index: i as u32,
            });
        }
    }
    out
}

/// A field the query language can offer and match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SearchField {
    pub name: &'static str,
    pub help: &'static str,
}

/// What every decoder implements.
pub trait BusDecoder {
    /// What this decoder is, recorded in the capture so a re-decode can be
    /// reproduced.
    fn info(&self) -> DecoderInfo;

    /// The fields it emits, for autocomplete and for `sniffer query` help.
    fn search_fields(&self) -> &'static [SearchField];

    /// Turn edges into transactions.
    ///
    /// Takes the capture as well as the edges because gap records live there,
    /// and a decoder that cannot see them cannot obey Appendix B.
    fn decode_edges(&self, edges: &[Edge], capture: &file::Capture) -> Decoded;

    fn decode(&self, capture: &file::Capture) -> Decoded {
        self.decode_edges(&edges_of(capture), capture)
    }
}

/// Assemble a transaction's fields without repeating the bookkeeping.
///
/// Every decoder was building the same `Field` by hand and every one of them
/// could forget the sample range, which is the one thing Appendix B insists on.
pub struct Fields {
    pub list: Vec<Field>,
}

impl Default for Fields {
    fn default() -> Self {
        Self::new()
    }
}

impl Fields {
    pub fn new() -> Self {
        Fields { list: Vec::new() }
    }

    /// A field with a number behind it, which search can compare against.
    #[allow(clippy::too_many_arguments)]
    pub fn number(
        &mut self,
        name: impl Into<String>,
        value: u64,
        display: impl Into<String>,
        kind: FieldKind,
        span: (Picos, Picos),
        samples: SampleRef,
    ) -> &mut Self {
        self.list.push(Field {
            name: name.into(),
            value: Some(value),
            display: display.into(),
            kind,
            start: span.0,
            end: span.1,
            samples,
            severity: Severity::Info,
        });
        self
    }

    /// A field that is only text - a decoded name, a message.
    pub fn text(
        &mut self,
        name: impl Into<String>,
        display: impl Into<String>,
        span: (Picos, Picos),
        samples: SampleRef,
    ) -> &mut Self {
        self.list.push(Field {
            name: name.into(),
            value: None,
            display: display.into(),
            kind: FieldKind::Text,
            start: span.0,
            end: span.1,
            samples,
            severity: Severity::Info,
        });
        self
    }

    /// Mark the field just added as worth attention.
    pub fn flag(&mut self, severity: Severity) -> &mut Self {
        if let Some(last) = self.list.last_mut() {
            last.severity = severity;
        }
        self
    }

    pub fn take(&mut self) -> Vec<Field> {
        std::mem::take(&mut self.list)
    }
}

/// The sample range spanned by two edge indices into `edges`.
pub fn span(edges: &[Edge], first: usize, last: usize) -> SampleRef {
    let first = first.min(edges.len().saturating_sub(1));
    let last = last.min(edges.len().saturating_sub(1));
    SampleRef {
        chunk: edges.get(first).map(|e| e.chunk).unwrap_or(0),
        first: edges.get(first).map(|e| e.index).unwrap_or(0),
        last: edges.get(last).map(|e| e.index).unwrap_or(0),
    }
}

/// Apply the gap rule to a finished transaction.
///
/// Appendix B in one function, so no decoder has to remember it: a gap
/// overlapping the span means the payload may be missing bytes, and that is an
/// error and an incomplete result rather than a quiet success.
pub fn apply_gap_rule(
    capture: &file::Capture,
    start: Picos,
    end: Picos,
    errors: &mut Vec<ErrorKind>,
    complete: &mut bool,
    severity: &mut Severity,
) {
    if capture.gap_overlaps(start, end) {
        errors.push(ErrorKind::GapOverlap);
        *complete = false;
        *severity = Severity::Error;
    }
}

/// Bytes formatted the way every summary shows them.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture_of(times: Vec<Picos>, lines: Vec<u8>) -> file::Capture {
        let chunk = file::SampleChunk {
            id: 3,
            start: *times.first().unwrap_or(&0),
            end: *times.last().unwrap_or(&0),
            times,
            lines,
        };
        file::Capture {
            session: file::Session {
                format_version: file::FORMAT_VERSION,
                schema_version: schema::SCHEMA_VERSION,
                source: "test".into(),
                device_id: String::new(),
                firmware_version: String::new(),
                host_software: String::new(),
                started_utc: String::new(),
                channels: vec!["a".into(), "b".into()],
                tick_hz: 1_000_000_000_000,
                timing: file::Timing::Measured,
            },
            index: file::rebuild_index(std::slice::from_ref(&chunk), &[],
                                       &Decoded::default()),
            chunks: vec![chunk],
            gaps: vec![],
            decoders: vec![],
            decoded: Decoded::default(),
            annotations: vec![],
            truncated_at: None,
        }
    }

    #[test]
    fn edges_keep_the_chunk_they_came_from() {
        let cap = capture_of(vec![0, 10, 20], vec![0b11, 0b01, 0b11]);
        let edges = edges_of(&cap);
        assert_eq!(edges.len(), 3);
        assert_eq!(edges[0].chunk, 3);
        assert_eq!(edges[1].index, 1);
        assert!(edges[0].line(0) && edges[0].line(1));
        assert!(edges[1].line(0) && !edges[1].line(1));
    }

    #[test]
    fn a_span_reads_the_indices_of_its_ends() {
        let cap = capture_of(vec![0, 10, 20, 30], vec![3, 1, 3, 1]);
        let edges = edges_of(&cap);
        let s = span(&edges, 1, 3);
        assert_eq!((s.chunk, s.first, s.last), (3, 1, 3));
    }

    /// Out-of-range indices clamp rather than panicking: a decoder that has run
    /// off the end of a truncated capture is a normal case, not a bug.
    #[test]
    fn a_span_past_the_end_clamps() {
        let cap = capture_of(vec![0, 10], vec![3, 1]);
        let edges = edges_of(&cap);
        let s = span(&edges, 5, 99);
        assert_eq!((s.first, s.last), (1, 1));
    }

    #[test]
    fn the_gap_rule_marks_and_downgrades() {
        let mut cap = capture_of(vec![0, 100], vec![3, 1]);
        cap.gaps.push(file::Gap {
            start: 40, end: 60, reason: "test".into(), lost: None });

        let mut errors = Vec::new();
        let mut complete = true;
        let mut severity = Severity::Info;
        apply_gap_rule(&cap, 0, 100, &mut errors, &mut complete, &mut severity);
        assert_eq!(errors, vec![ErrorKind::GapOverlap]);
        assert!(!complete);
        assert_eq!(severity, Severity::Error);

        // And a transaction clear of the gap is untouched.
        let mut errors = Vec::new();
        let mut complete = true;
        let mut severity = Severity::Info;
        apply_gap_rule(&cap, 70, 90, &mut errors, &mut complete, &mut severity);
        assert!(errors.is_empty() && complete && severity == Severity::Info);
    }

    #[test]
    fn hex_is_the_one_format_every_summary_uses() {
        assert_eq!(hex(&[0xDE, 0xAD, 0x00]), "DE AD 00");
        assert_eq!(hex(&[]), "");
    }
}
