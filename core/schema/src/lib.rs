//! The normalized model every decoder produces and everything else consumes.
//!
//! Appendix A of the specification lists this as a decision to lock early, and
//! the reason is in the list of what depends on it: the GUI, search, exports,
//! extensions, the API, the MCP adapter and every test. A change here is a
//! change to all of them, so it is versioned and deliberately small.
//!
//! # The timestamp model
//!
//! Picoseconds since the start of the capture, in a `u64`. Not ticks.
//!
//! A tick count is only meaningful next to the rate it was counted at, and that
//! rate belongs to one device - so two devices, or one device across a firmware
//! change, produce numbers that cannot be compared without carrying their
//! divisors everywhere. Picoseconds are absolute. `u64` of them is 213 days,
//! and the resolution is far below anything a digital capture can resolve: the
//! present hardware counts at 250 MHz, which is 4000 ps a tick.
//!
//! Relative to the capture, not to the wall clock. The wall clock is recorded
//! once in the session header for a human to read; nothing computes with it,
//! because it can step.
//!
//! # Severity, and why decoders do not get to invent one
//!
//! The overview strip, the filters, the test assertions and the automation all
//! branch on severity. If each decoder chose its own words, every consumer
//! would need a table of them. So the taxonomy lives here and a decoder picks
//! from it.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

/// Bumped when a field is removed or its meaning changes.
///
/// Adding an optional field does not bump it: readers ignore what they do not
/// know, and a capture written by a newer build must stay readable by an older
/// one for as long as the shape holds.
pub const SCHEMA_VERSION: u16 = 1;

/// Picoseconds since the start of the capture.
pub type Picos = u64;

/// Which bus a thing happened on. Stable across reconnects and saved
/// workspaces, which is why it is an assigned id and not a device path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BusId(pub u16);

impl std::fmt::Display for BusId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The protocols the first release decodes, plus room for the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    I2c,
    I3c,
    Spi,
    Mdio,
    Uart,
    Can,
}

impl Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::I2c => "i2c",
            Protocol::I3c => "i3c",
            Protocol::Spi => "spi",
            Protocol::Mdio => "mdio",
            Protocol::Uart => "uart",
            Protocol::Can => "can",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Some(match name.to_ascii_lowercase().as_str() {
            "i2c" => Protocol::I2c,
            "i3c" => Protocol::I3c,
            "spi" => Protocol::Spi,
            "mdio" => Protocol::Mdio,
            "uart" => Protocol::Uart,
            "can" => Protocol::Can,
            _ => return None,
        })
    }
}

/// How much attention something deserves.
///
/// Ordered, so a filter can ask for "warning and above" without a table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Normal traffic.
    Info,
    /// Legal but worth seeing: a NACK on a probe, an unusually long stretch.
    Notice,
    /// The bus did something a correct implementation should not.
    Warning,
    /// The decoder could not produce a trustworthy result.
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

/// The error taxonomy. Appendix A wants one, and this is it.
///
/// A closed list on purpose: these are what filters, the overview strip and the
/// test assertions match on, so a decoder inventing a new string would produce
/// something no consumer can act on. `Other` exists for a decoder that has
/// genuinely found something new, and carries its own text so the finding is
/// not lost while the taxonomy catches up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    /// A transaction the capture does not fully contain.
    Truncated,
    /// The capture has a hole overlapping this transaction, so what was decoded
    /// may be missing bytes. Never guessed around - see `Transaction::complete`.
    GapOverlap,
    /// Framing the protocol does not allow: a START mid-byte, a STOP with no
    /// START, a turnaround that never happened.
    Framing,
    /// The target did not acknowledge.
    Nack,
    /// A parity, T-bit, CRC or checksum that does not agree with the data.
    CheckFailed,
    /// Timing outside what the configured mode permits.
    Timing,
    /// The bus was left in a state the decoder cannot continue from.
    BusStuck,
    /// Something new. The text is the finding.
    Other(String),
}

impl ErrorKind {
    pub fn as_str(&self) -> &str {
        match self {
            ErrorKind::Truncated => "truncated",
            ErrorKind::GapOverlap => "gap_overlap",
            ErrorKind::Framing => "framing",
            ErrorKind::Nack => "nack",
            ErrorKind::CheckFailed => "check_failed",
            ErrorKind::Timing => "timing",
            ErrorKind::BusStuck => "bus_stuck",
            ErrorKind::Other(text) => text,
        }
    }
}

/// Where in the raw capture a decoded thing came from.
///
/// Appendix B makes this mandatory: every output field must have a raw
/// reference. It is what lets the UI highlight the exact interval that produced
/// a field, and what lets a disagreement between two decoder versions be
/// settled by looking at the samples rather than at the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleRef {
    /// The chunk holding these edges.
    pub chunk: u32,
    /// First edge index within the chunk, inclusive.
    pub first: u32,
    /// Last edge index within the chunk, inclusive.
    pub last: u32,
}

/// What a field means, for consumers that format or filter by type rather than
/// by name - a hex byte string and a bus address want different display and
/// different search behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Address,
    Data,
    Flag,
    Count,
    Duration,
    Text,
}

/// One decoded field of a transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Field {
    pub name: String,
    /// The value as a number where it is one. Search compares against this.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,
    /// The value as it should be shown. Kept beside the number rather than
    /// derived, because "0x52" and "82" and "R" are all correct renderings of
    /// different fields and only the decoder knows which it meant.
    pub display: String,
    pub kind: FieldKind,
    pub start: Picos,
    pub end: Picos,
    pub samples: SampleRef,
    #[serde(default = "info_severity", skip_serializing_if = "is_info")]
    pub severity: Severity,
}

fn info_severity() -> Severity {
    Severity::Info
}

fn is_info(s: &Severity) -> bool {
    *s == Severity::Info
}

/// What kind of thing a transaction is. Free text because it is
/// protocol-specific - "PRIVATE-R", "CCC", "C45-READ" - and a closed list here
/// would have to grow for every protocol added.
pub type TransactionKind = String;

/// One decoded transaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique within a capture, and stable across re-decodes of the same
    /// capture by the same decoder version. Replay determinism depends on it -
    /// see the acceptance criterion about identical transaction ids.
    pub id: u64,
    pub bus: BusId,
    pub protocol: Protocol,
    pub start: Picos,
    pub end: Picos,
    pub kind: TransactionKind,
    /// One line for a table row.
    pub summary: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<u64>,
    pub fields: Vec<Field>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<ErrorKind>,
    pub samples: SampleRef,
    /// False when the capture does not contain the whole transaction - it ran
    /// past the end, or a gap swallowed part of it.
    ///
    /// Appendix B: a gap overlapping a transaction must produce a clear
    /// incomplete result rather than false data. This is that flag, and nothing
    /// downstream may treat an incomplete transaction's payload as authoritative.
    pub complete: bool,
}

/// Something that happened which is not itself a transaction: a gap, a bus
/// event, a decoder giving up.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    pub start: Picos,
    pub end: Picos,
    pub bus: Option<BusId>,
    pub kind: String,
    pub message: String,
    pub severity: Severity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction: Option<u64>,
}

/// What a decoder was, so a re-decode can be reproduced.
///
/// Appendix A: re-decoding old captures must be reproducible and traceable, so
/// the version travels with the output rather than being whatever happens to be
/// installed when someone opens the file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoderInfo {
    pub name: String,
    pub version: String,
    pub protocol: Protocol,
    pub bus: BusId,
    /// Settings as name=value, so a decoder can record its own without this
    /// crate knowing what any of them mean.
    pub settings: Vec<(String, String)>,
}

/// Everything one decode pass produced.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Decoded {
    pub transactions: Vec<Transaction>,
    pub events: Vec<Event>,
}

impl Decoded {
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty() && self.events.is_empty()
    }

    /// Transactions carrying any error, or marked incomplete.
    pub fn with_errors(&self) -> impl Iterator<Item = &Transaction> {
        self.transactions
            .iter()
            .filter(|t| !t.errors.is_empty() || !t.complete)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_from_quiet_to_loud() {
        assert!(Severity::Info < Severity::Notice);
        assert!(Severity::Notice < Severity::Warning);
        assert!(Severity::Warning < Severity::Error);
    }

    #[test]
    fn protocol_names_round_trip() {
        for p in [Protocol::I2c, Protocol::I3c, Protocol::Spi,
                  Protocol::Mdio, Protocol::Uart, Protocol::Can] {
            assert_eq!(Protocol::parse(p.as_str()), Some(p));
        }
        assert_eq!(Protocol::parse("I2C"), Some(Protocol::I2c));
        assert_eq!(Protocol::parse("nonsense"), None);
    }

    /// The wire format is a contract with saved files, so a field being renamed
    /// has to be a deliberate act rather than a rename refactor that compiles.
    #[test]
    fn a_transaction_serialises_to_the_documented_shape() {
        let t = Transaction {
            id: 7,
            bus: BusId(0),
            protocol: Protocol::I2c,
            start: 1_000,
            end: 2_000,
            kind: "WRITE".into(),
            summary: "0x52 W 2 bytes".into(),
            severity: Severity::Info,
            parent: None,
            fields: vec![],
            errors: vec![],
            samples: SampleRef { chunk: 0, first: 3, last: 40 },
            complete: true,
        };
        let json = serde_json::to_value(&t).unwrap();
        assert_eq!(json["id"], 7);
        assert_eq!(json["protocol"], "i2c");
        assert_eq!(json["severity"], "info");
        assert_eq!(json["samples"]["first"], 3);
        assert_eq!(json["complete"], true);
        // Absent rather than null: an optional field that serialises as null
        // doubles the shapes every reader has to handle.
        assert!(json.get("parent").is_none());
        assert!(json.get("errors").is_none());
    }

    #[test]
    fn an_error_kind_keeps_its_text_when_it_is_new() {
        let e = ErrorKind::Other("i3c_hdr_unsupported".into());
        assert_eq!(e.as_str(), "i3c_hdr_unsupported");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("i3c_hdr_unsupported"), "{json}");
    }

    #[test]
    fn incomplete_transactions_count_as_errors_to_look_at() {
        let mut d = Decoded::default();
        d.transactions.push(Transaction {
            id: 1, bus: BusId(0), protocol: Protocol::I2c, start: 0, end: 1,
            kind: "WRITE".into(), summary: String::new(), severity: Severity::Info,
            parent: None, fields: vec![], errors: vec![],
            samples: SampleRef { chunk: 0, first: 0, last: 0 },
            complete: false,
        });
        assert_eq!(d.with_errors().count(), 1);
    }
}
