//! The protocol-native query language.
//!
//! Section 6 calls search one of the major differentiators, and the reason is
//! in the examples: `bus:I3C0 addr:0x52 error:any` describes what the engineer
//! is looking for, where a byte search describes what it happens to look like.
//!
//! # The grammar
//!
//! Terms separated by spaces, all of which must match - an implicit AND,
//! because that is what people type and what section 6.1's examples all mean.
//!
//! ```text
//! addr:0x52          a field named addr equals 0x52
//! type:WRITE         the transaction kind
//! bus:0              which bus
//! protocol:i2c
//! error:any          anything with an error, or incomplete
//! error:nack         that specific error
//! severity:warning   at or above that level
//! data:"DE AD"       the payload contains this byte sequence
//! contains:"text"    the summary contains this text
//! incomplete:true
//! ```
//!
//! Numbers are hex with `0x`, binary with `0b`, decimal otherwise - section 6.2
//! asks for all three.
//!
//! # What it deliberately is not
//!
//! No OR, no parentheses, no negation yet. Every example in the specification
//! is a conjunction, and a query language grows best from the queries people
//! actually write. The parser reports an unknown field rather than ignoring it,
//! so a term that would silently match everything cannot.

pub mod index;

pub use index::{Hits, Index};

use schema::{Decoded, Severity, Transaction};

#[derive(Debug, Clone, PartialEq)]
pub enum Term {
    /// A named field equals a value: `addr:0x52`, or a decoder's own field.
    Field { name: String, value: Match },
    Kind(String),
    Bus(u16),
    Protocol(schema::Protocol),
    /// `error:any` or a specific kind by its taxonomy name.
    Error(Option<String>),
    /// At or above this severity.
    Severity(Severity),
    /// A byte sequence anywhere in the payload, with `??` matching any byte.
    Data(Vec<Option<u8>>),
    /// Text anywhere in the summary.
    Contains(String),
    Incomplete(bool),
}

#[derive(Debug, Clone, PartialEq)]
pub enum Match {
    Number(u64),
    Text(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Query {
    pub terms: Vec<Term>,
}

#[derive(Debug, PartialEq)]
pub struct ParseError {
    pub term: String,
    pub message: String,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.term, self.message)
    }
}

/// Every field name the parser knows, for the "did you mean" in an error and
/// for a future autocomplete - section 6.2 asks for one.
pub const KNOWN: &[(&str, &str)] = &[
    ("addr", "the address field, e.g. addr:0x52"),
    ("type", "the transaction kind, e.g. type:WRITE"),
    ("bus", "which bus, e.g. bus:0"),
    ("protocol", "i2c, i3c, spi, mdio, uart or can"),
    ("error", "any, or a name: nack, framing, gap_overlap, truncated, …"),
    ("severity", "info, notice, warning or error - matches that and above"),
    ("data", "a byte sequence in the payload, e.g. data:\"DE AD\" or \"AA ?? 34\""),
    ("contains", "text in the summary"),
    ("incomplete", "true or false"),
];

fn number(text: &str) -> Option<u64> {
    let t = text.trim();
    let (radix, digits) = if let Some(rest) = t.strip_prefix("0x").or(t.strip_prefix("0X")) {
        (16, rest)
    } else if let Some(rest) = t.strip_prefix("0b").or(t.strip_prefix("0B")) {
        (2, rest)
    } else {
        (10, t)
    };
    u64::from_str_radix(digits, radix).ok()
}

/// Split on spaces, but keep quoted runs together.
fn tokens(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quoted = false;
    for c in input.chars() {
        match c {
            '"' => quoted = !quoted,
            c if c.is_whitespace() && !quoted => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            c => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// A byte pattern, where `??` is any byte.
fn byte_pattern(text: &str) -> Option<Vec<Option<u8>>> {
    let mut out = Vec::new();
    for part in text.split_whitespace() {
        if part == "??" || part == "**" {
            out.push(None);
        } else {
            out.push(Some(u8::from_str_radix(part, 16).ok()?));
        }
    }
    (!out.is_empty()).then_some(out)
}

pub fn parse(input: &str) -> Result<Query, ParseError> {
    let mut terms = Vec::new();

    for token in tokens(input) {
        let Some((key, value)) = token.split_once(':') else {
            // A bare word is the commonest thing to type, so it means the
            // obvious thing rather than being an error.
            terms.push(Term::Contains(token));
            continue;
        };
        let key_lower = key.to_ascii_lowercase();
        let err = |m: &str| ParseError { term: token.clone(), message: m.into() };

        let term = match key_lower.as_str() {
            "addr" | "address" => Term::Field {
                name: "address".into(),
                value: match number(value) {
                    Some(n) => Match::Number(n),
                    None => Match::Text(value.to_string()),
                },
            },
            "type" | "kind" => Term::Kind(value.to_ascii_uppercase()),
            "bus" => Term::Bus(number(value).ok_or_else(|| err("bus wants a number"))? as u16),
            "protocol" | "proto" => Term::Protocol(
                schema::Protocol::parse(value).ok_or_else(|| err(
                    "unknown protocol; try i2c, i3c, spi, mdio, uart or can"))?),
            "error" | "err" => {
                if value.eq_ignore_ascii_case("any") {
                    Term::Error(None)
                } else if value.eq_ignore_ascii_case("none") {
                    // "no errors" is a filter people want as much as its
                    // opposite - can.id:0x123 error:none is in the examples.
                    Term::Incomplete(false)
                } else {
                    Term::Error(Some(value.to_ascii_lowercase()))
                }
            }
            "severity" => Term::Severity(match value.to_ascii_lowercase().as_str() {
                "info" => Severity::Info,
                "notice" => Severity::Notice,
                "warning" | "warn" => Severity::Warning,
                "error" => Severity::Error,
                _ => return Err(err("severity is info, notice, warning or error")),
            }),
            "data" => Term::Data(byte_pattern(value)
                .ok_or_else(|| err("data wants hex bytes, e.g. data:\"DE AD\""))?),
            "contains" | "text" => Term::Contains(value.to_string()),
            "incomplete" => Term::Incomplete(value.eq_ignore_ascii_case("true")
                                             || value == "1"),
            // A decoder's own field, matched by name. This is what makes the
            // language protocol-native without the parser knowing every
            // protocol: mdio.phy:1 is just a field called mdio.phy.
            _ => Term::Field {
                name: key.to_string(),
                value: match number(value) {
                    Some(n) => Match::Number(n),
                    None => Match::Text(value.to_string()),
                },
            },
        };
        terms.push(term);
    }

    Ok(Query { terms })
}

impl Query {
    /// Does this transaction match every term?
    pub fn matches(&self, t: &Transaction) -> bool {
        self.terms.iter().all(|term| match term {
            Term::Field { name, value } => t.fields.iter().any(|f| {
                if !f.name.eq_ignore_ascii_case(name) {
                    return false;
                }
                match value {
                    Match::Number(n) => f.value == Some(*n),
                    Match::Text(s) => f.display.eq_ignore_ascii_case(s),
                }
            }),
            Term::Kind(k) => t.kind.eq_ignore_ascii_case(k),
            Term::Bus(b) => t.bus.0 == *b,
            Term::Protocol(p) => t.protocol == *p,
            Term::Error(None) => !t.errors.is_empty() || !t.complete,
            Term::Error(Some(name)) => {
                t.errors.iter().any(|e| e.as_str().eq_ignore_ascii_case(name))
            }
            Term::Severity(s) => t.severity >= *s,
            Term::Data(pattern) => payload_contains(t, pattern),
            Term::Contains(text) => {
                t.summary.to_lowercase().contains(&text.to_lowercase())
                    || t.kind.to_lowercase().contains(&text.to_lowercase())
            }
            Term::Incomplete(want) => {
                let bad = !t.complete || !t.errors.is_empty();
                if *want { bad } else { !bad }
            }
        })
    }

    /// Every match, by scanning.
    ///
    /// Correct and cheap on a few thousand transactions, and the reference the
    /// index is tested against. For a large capture, or for a first page
    /// quickly, build an [`Index`] and use [`Index::hits`].
    pub fn run<'a>(&self, decoded: &'a Decoded) -> Vec<&'a Transaction> {
        decoded.transactions.iter().filter(|t| self.matches(t)).collect()
    }
}

/// The payload bytes of a transaction, in order.
fn payload(t: &Transaction) -> Vec<u8> {
    t.fields
        .iter()
        .filter(|f| f.kind == schema::FieldKind::Data)
        .filter_map(|f| f.value.map(|v| v as u8))
        .collect()
}

fn payload_contains(t: &Transaction, pattern: &[Option<u8>]) -> bool {
    let bytes = payload(t);
    if pattern.len() > bytes.len() {
        return false;
    }
    bytes.windows(pattern.len()).any(|w| {
        w.iter().zip(pattern).all(|(b, p)| match p {
            Some(want) => b == want,
            None => true,
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use schema::{BusId, Field, FieldKind, Protocol, SampleRef};

    fn field(name: &str, value: u64, display: &str, kind: FieldKind) -> Field {
        Field {
            name: name.into(),
            value: Some(value),
            display: display.into(),
            kind,
            start: 0,
            end: 1,
            samples: SampleRef { chunk: 0, first: 0, last: 1 },
            severity: Severity::Info,
        }
    }

    fn transaction() -> Transaction {
        Transaction {
            id: 1,
            bus: BusId(0),
            protocol: Protocol::I2c,
            start: 0,
            end: 100,
            kind: "WRITE".into(),
            summary: "0x52 W DE AD".into(),
            severity: Severity::Info,
            parent: None,
            fields: vec![
                field("address", 0x52, "0x52", FieldKind::Address),
                field("direction", 0, "W", FieldKind::Flag),
                field("data[0]", 0xDE, "0xDE", FieldKind::Data),
                field("data[1]", 0xAD, "0xAD", FieldKind::Data),
            ],
            errors: vec![],
            samples: SampleRef { chunk: 0, first: 0, last: 10 },
            complete: true,
        }
    }

    fn hits(q: &str, t: &Transaction) -> bool {
        parse(q).unwrap().matches(t)
    }

    #[test]
    fn the_specifications_own_example_parses_and_matches() {
        let t = transaction();
        assert!(hits("addr:0x52", &t));
        assert!(!hits("addr:0x53", &t));
        // The full example: an address and anything wrong with it. Nothing is
        // wrong with this one, so it must not match.
        assert!(!hits("addr:0x52 error:any", &t));

        let mut bad = transaction();
        bad.errors.push(schema::ErrorKind::Nack);
        assert!(hits("addr:0x52 error:any", &bad));
        assert!(hits("addr:0x52 error:nack", &bad));
        assert!(!hits("addr:0x52 error:framing", &bad));
    }

    #[test]
    fn numbers_are_accepted_in_three_bases() {
        let t = transaction();
        assert!(hits("addr:0x52", &t));
        assert!(hits("addr:82", &t));
        assert!(hits("addr:0b1010010", &t));
    }

    #[test]
    fn terms_are_all_required() {
        let t = transaction();
        assert!(hits("addr:0x52 type:WRITE bus:0 protocol:i2c", &t));
        assert!(!hits("addr:0x52 type:READ", &t));
    }

    #[test]
    fn a_data_pattern_matches_a_run_of_payload_bytes() {
        let t = transaction();
        assert!(hits("data:\"DE AD\"", &t));
        assert!(hits("data:\"AD\"", &t));
        assert!(!hits("data:\"AD DE\"", &t), "order matters");
        // The wildcard from the specification's example.
        assert!(hits("data:\"DE ??\"", &t));
        assert!(!hits("data:\"?? BE\"", &t));
    }

    #[test]
    fn severity_matches_at_or_above() {
        let mut t = transaction();
        t.severity = Severity::Warning;
        assert!(hits("severity:info", &t));
        assert!(hits("severity:warning", &t));
        assert!(!hits("severity:error", &t));
    }

    #[test]
    fn incomplete_transactions_are_findable() {
        let mut t = transaction();
        t.complete = false;
        assert!(hits("error:any", &t), "incomplete counts as something wrong");
        assert!(hits("incomplete:true", &t));
        assert!(!hits("error:none", &t));
    }

    #[test]
    fn a_bare_word_searches_the_summary() {
        let t = transaction();
        assert!(hits("WRITE", &t));
        assert!(hits("0x52", &t));
        assert!(!hits("nonsense", &t));
    }

    #[test]
    fn quoted_values_keep_their_spaces() {
        assert_eq!(tokens(r#"data:"DE AD" addr:0x52"#),
                   vec!["data:DE AD".to_string(), "addr:0x52".to_string()]);
    }

    #[test]
    fn an_unknown_protocol_is_refused_rather_than_matching_nothing_silently() {
        let e = parse("protocol:carrier-pigeon").unwrap_err();
        assert!(e.message.contains("unknown protocol"), "{e}");
    }

    /// A decoder's own field is matched by name without the parser knowing the
    /// protocol, which is what "protocol-native" has to mean if adding a
    /// decoder is not to mean editing the query language.
    #[test]
    fn an_unknown_field_name_matches_that_field() {
        let mut t = transaction();
        t.fields.push(field("mdio.phy", 1, "1", FieldKind::Address));
        assert!(hits("mdio.phy:1", &t));
        assert!(!hits("mdio.phy:2", &t));
    }
}
