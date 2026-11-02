//! The indexed transaction store.
//!
//! Section 6.2: "Queries run incrementally and return first results quickly on
//! large captures", and section 11 puts a number on it - the first page of
//! results must not require loading the entire capture. A scan cannot promise
//! either: it touches every transaction whatever the query, so the cost of
//! `addr:0x52` on a capture with two hundred thousand transactions is two
//! hundred thousand predicate evaluations before the first row appears.
//!
//! # What is indexed
//!
//! Postings lists: for each term a query can name, the rows that match it, in
//! ascending row order. Intersecting sorted lists smallest-first answers a
//! conjunction while touching only candidates that could possibly match, and
//! it produces them in order - so the first page really is the first page,
//! and stopping after twenty results costs twenty results' worth of work.
//!
//! Section 4.4 suggests SQLite or a columnar store. This is the columnar half
//! of that, in memory, built from a decode in one pass: no dependency, no
//! schema migration, and no query planner to be surprised by. What it gives up
//! is persistence across runs, which is what the capture file is for.
//!
//! # What is not indexed, and why
//!
//! **Data fields.** A four-byte payload contributes four fields named
//! `data[0]`..`data[3]`, so indexing them by value would add one posting list
//! per byte position per value - the largest part of the index, to answer a
//! question nobody asks by equality. `data:"DE AD"` is a byte pattern and is
//! evaluated as a residual predicate on candidates instead.
//!
//! **Text search.** `contains:"ERROR"` is a substring match over summaries, and
//! a substring index is a different structure (suffix array or trigrams) for a
//! different phase. Also a residual.
//!
//! A residual term never changes the answer - it is applied to every candidate
//! the postings produced - only how much work reaching the answer takes. The
//! tests hold the index and the scan to exactly the same results.

use std::collections::{HashMap, HashSet};

use schema::{Decoded, Severity, Transaction};

use crate::{Match, Query, Term};

/// Postings for one decode.
pub struct Index {
    rows: usize,
    kind: HashMap<String, Vec<u32>>,
    bus: HashMap<u16, Vec<u32>>,
    protocol: HashMap<schema::Protocol, Vec<u32>>,
    /// `(field name lowercased, value)` for fields that carry a number.
    field_num: HashMap<(String, u64), Vec<u32>>,
    /// `(field name lowercased, display lowercased)` for the rest.
    field_text: HashMap<(String, String), Vec<u32>>,
    /// Which field names were indexed at all. A name that was not - a data
    /// byte, or a field no transaction carried - must fall back to a scan
    /// rather than silently answering "no rows".
    indexed_fields: HashSet<String>,
    error: HashMap<String, Vec<u32>>,
    /// `error:any`: anything carrying an error or marked incomplete.
    problems: Vec<u32>,
    clean: Vec<u32>,
    /// At or above Info, Notice, Warning, Error.
    severity: [Vec<u32>; 4],
}

fn severity_slot(s: Severity) -> usize {
    match s {
        Severity::Info => 0,
        Severity::Notice => 1,
        Severity::Warning => 2,
        Severity::Error => 3,
    }
}

impl Index {
    /// Build the postings. One pass over the decode.
    pub fn build(decoded: &Decoded) -> Index {
        let mut index = Index {
            rows: decoded.transactions.len(),
            kind: HashMap::new(),
            bus: HashMap::new(),
            protocol: HashMap::new(),
            field_num: HashMap::new(),
            field_text: HashMap::new(),
            indexed_fields: HashSet::new(),
            error: HashMap::new(),
            problems: Vec::new(),
            clean: Vec::new(),
            severity: [Vec::new(), Vec::new(), Vec::new(), Vec::new()],
        };

        for (row, t) in decoded.transactions.iter().enumerate() {
            let row = row as u32;
            index.kind.entry(t.kind.to_ascii_uppercase()).or_default().push(row);
            index.bus.entry(t.bus.0).or_default().push(row);
            index.protocol.entry(t.protocol).or_default().push(row);

            let problem = !t.errors.is_empty() || !t.complete;
            if problem {
                index.problems.push(row);
            } else {
                index.clean.push(row);
            }
            for e in &t.errors {
                index.error.entry(e.as_str().to_ascii_lowercase())
                    .or_default().push(row);
            }

            // Severity is a threshold in the query language, so a row belongs
            // to every level at or below its own. Four lists, not a scan of
            // one, because "at or above warning" is then a posting list like
            // any other.
            for slot in 0..=severity_slot(t.severity) {
                index.severity[slot].push(row);
            }

            for f in &t.fields {
                if f.kind == schema::FieldKind::Data {
                    // Left to the byte-pattern predicate; see the module note.
                    continue;
                }
                let name = f.name.to_ascii_lowercase();
                index.indexed_fields.insert(name.clone());
                match f.value {
                    Some(v) => {
                        index.field_num.entry((name.clone(), v)).or_default()
                            .push(row);
                    }
                    None => {}
                }
                // Indexed by display as well as by number: `direction:W` and
                // `addr:0x52` are both things people type, and only the
                // decoder knows which rendering it meant.
                index.field_text
                    .entry((name, f.display.to_ascii_lowercase()))
                    .or_default().push(row);
            }
        }

        index
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Every field name a query can name and get a posting list for.
    ///
    /// Section 6.2 asks for autocomplete "based on active protocol decoders";
    /// this is the other half of that - what the decode actually produced,
    /// rather than what the decoder says it can produce.
    pub fn field_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.indexed_fields.iter()
            .map(|s| s.as_str()).collect();
        names.sort_unstable();
        names
    }

    /// The posting list for one term, or None when the term has to be checked
    /// against each candidate instead.
    fn postings(&self, term: &Term) -> Option<&[u32]> {
        static EMPTY: [u32; 0] = [];
        let list = match term {
            Term::Kind(k) => self.kind.get(&k.to_ascii_uppercase())
                .map(|v| v.as_slice()).unwrap_or(&EMPTY),
            Term::Bus(b) => self.bus.get(b)
                .map(|v| v.as_slice()).unwrap_or(&EMPTY),
            Term::Protocol(p) => self.protocol.get(p)
                .map(|v| v.as_slice()).unwrap_or(&EMPTY),
            Term::Error(None) => &self.problems,
            Term::Error(Some(name)) => self.error.get(&name.to_ascii_lowercase())
                .map(|v| v.as_slice()).unwrap_or(&EMPTY),
            Term::Severity(s) => &self.severity[severity_slot(*s)],
            Term::Incomplete(true) => &self.problems,
            Term::Incomplete(false) => &self.clean,
            Term::Field { name, value } => {
                let lower = name.to_ascii_lowercase();
                if !self.indexed_fields.contains(&lower) {
                    // Either a data byte or a field nothing carried. The first
                    // must be scanned; the second is genuinely empty, and
                    // scanning it costs one pass to reach the same answer.
                    return None;
                }
                match value {
                    Match::Number(n) => self.field_num.get(&(lower, *n))
                        .map(|v| v.as_slice()).unwrap_or(&EMPTY),
                    Match::Text(s) => self.field_text
                        .get(&(lower, s.to_ascii_lowercase()))
                        .map(|v| v.as_slice()).unwrap_or(&EMPTY),
                }
            }
            // Byte patterns and substrings: residuals, by design.
            Term::Data(_) | Term::Contains(_) => return None,
        };
        Some(list)
    }

    /// Matching rows, in capture order, produced lazily.
    pub fn hits<'a>(&'a self, query: &'a Query, decoded: &'a Decoded) -> Hits<'a> {
        let mut lists: Vec<&[u32]> = Vec::new();
        let mut residual: Vec<&Term> = Vec::new();

        for term in &query.terms {
            match self.postings(term) {
                Some(list) => lists.push(list),
                None => residual.push(term),
            }
        }
        // Smallest first: the driving list decides how many candidates are
        // ever considered, and the rarest term is the cheapest place to start.
        lists.sort_by_key(|l| l.len());

        // Nothing to intersect when every term was a residual, or when
        // there were no terms at all: then every row is a candidate.
        let all_rows = lists.is_empty();

        Hits {
            decoded,
            lists,
            residual,
            all_rows,
            next_row: 0,
            cursor: 0,
            examined: 0,
        }
    }

    /// One page of results: rows `from..from + count` of the matches.
    ///
    /// Stateless on purpose. Keeping an iterator alive across frames would
    /// borrow the decode for as long as the window is open, and re-walking to
    /// `from` costs the results already shown rather than the whole capture.
    pub fn page(&self, query: &Query, decoded: &Decoded, from: usize, count: usize)
        -> Vec<usize>
    {
        self.hits(query, decoded).skip(from).take(count).collect()
    }

    /// How many rows match. Walks the whole intersection, so it is the
    /// expensive question - ask it when the number is wanted, not to build a
    /// page.
    pub fn count(&self, query: &Query, decoded: &Decoded) -> usize {
        self.hits(query, decoded).count()
    }
}

/// Rows matching a query, in order.
pub struct Hits<'a> {
    decoded: &'a Decoded,
    /// Posting lists to intersect, shortest first.
    lists: Vec<&'a [u32]>,
    /// Terms that have to be checked against each candidate.
    residual: Vec<&'a Term>,
    /// True when there is nothing to intersect - every row is a candidate.
    all_rows: bool,
    next_row: usize,
    cursor: usize,
    examined: usize,
}

impl Hits<'_> {
    /// How many candidates were tested. The measure of whether the index is
    /// doing its job: for a selective query it should be close to the number
    /// of results, not to the size of the capture.
    pub fn examined(&self) -> usize {
        self.examined
    }

    fn passes_residual(&self, t: &Transaction) -> bool {
        self.residual.iter().all(|term| {
            let one = Query { terms: vec![(*term).clone()] };
            one.matches(t)
        })
    }
}

impl Iterator for Hits<'_> {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        loop {
            let candidate = if self.all_rows {
                if self.next_row >= self.decoded.transactions.len() {
                    return None;
                }
                let row = self.next_row;
                self.next_row += 1;
                row
            } else {
                let driver = self.lists[0];
                if self.cursor >= driver.len() {
                    return None;
                }
                let row = driver[self.cursor] as usize;
                self.cursor += 1;

                // Present in every other list, or not a match at all.
                if !self.lists[1..].iter()
                    .all(|list| list.binary_search(&(row as u32)).is_ok())
                {
                    self.examined += 1;
                    continue;
                }
                row
            };

            self.examined += 1;
            let Some(t) = self.decoded.transactions.get(candidate) else {
                continue;
            };
            if self.passes_residual(t) {
                return Some(candidate);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use schema::{BusId, Field, FieldKind, Protocol, SampleRef};

    fn field(name: &str, value: Option<u64>, display: &str, kind: FieldKind)
        -> Field
    {
        Field {
            name: name.into(),
            value,
            display: display.into(),
            kind,
            start: 0,
            end: 1,
            samples: SampleRef { chunk: 0, first: 0, last: 1 },
            severity: Severity::Info,
        }
    }

    /// A decode big enough that the difference between an index and a scan is
    /// a difference in kind rather than in milliseconds.
    fn big(rows: usize) -> Decoded {
        let mut out = Decoded::default();
        for i in 0..rows {
            let address = 0x50 + (i % 8) as u64;
            let bad = i % 1000 == 7;
            out.transactions.push(Transaction {
                id: i as u64 + 1,
                bus: BusId((i % 2) as u16),
                protocol: Protocol::I2c,
                start: i as u64 * 1_000,
                end: i as u64 * 1_000 + 500,
                kind: if i % 3 == 0 { "READ".into() } else { "WRITE".into() },
                summary: format!("0x{address:02X} payload {i}"),
                severity: if bad { Severity::Notice } else { Severity::Info },
                parent: None,
                fields: vec![
                    field("address", Some(address), &format!("0x{address:02X}"),
                          FieldKind::Address),
                    field("direction", Some(0), if i % 3 == 0 { "R" } else { "W" },
                          FieldKind::Flag),
                    field("data[0]", Some((i % 251) as u64),
                          &format!("0x{:02X}", i % 251), FieldKind::Data),
                ],
                errors: if bad { vec![schema::ErrorKind::Nack] } else { vec![] },
                samples: SampleRef { chunk: 0, first: i as u32, last: i as u32 + 1 },
                complete: true,
            });
        }
        out
    }

    fn scan(query: &Query, decoded: &Decoded) -> Vec<usize> {
        decoded.transactions.iter().enumerate()
            .filter(|(_, t)| query.matches(t))
            .map(|(i, _)| i)
            .collect()
    }

    /// The index exists to be faster, not to be different. Every query form
    /// the language has, checked against the scan it replaces.
    #[test]
    fn the_index_agrees_with_the_scan_on_every_query_form() {
        let decoded = big(5_000);
        let index = Index::build(&decoded);

        for text in [
            "",
            "addr:0x52",
            "addr:0x52 type:READ",
            "type:WRITE bus:1",
            "protocol:i2c",
            "error:any",
            "error:nack",
            "error:none",
            "severity:notice",
            "severity:warning",
            "incomplete:true",
            "direction:R",
            "addr:0x52 error:any",
            "addr:0x52 error:any type:WRITE bus:0",
            "contains:payload",
            "addr:0x52 contains:payload",
            "data:\"00\"",
            "addr:0x99",
            "type:NOTHING",
            "data[0]:0x01",
        ] {
            let query = crate::parse(text).unwrap();
            let want = scan(&query, &decoded);
            let got: Vec<usize> = index.hits(&query, &decoded).collect();
            assert_eq!(got, want, "the index disagreed with the scan on {text:?}");
        }
    }

    /// The point of the thing: a selective query must not touch the capture.
    #[test]
    fn the_first_page_costs_the_first_page_and_not_the_capture() {
        let decoded = big(200_000);
        let index = Index::build(&decoded);
        let query = crate::parse("addr:0x52 type:READ").unwrap();

        let mut hits = index.hits(&query, &decoded);
        let page: Vec<usize> = hits.by_ref().take(20).collect();
        assert_eq!(page.len(), 20);
        assert!(hits.examined() < 200,
                "reaching twenty results examined {} candidates out of 200000; \
                 that is a scan wearing an index's clothes", hits.examined());

        // And the rows are in capture order, which is what makes them a page.
        assert!(page.windows(2).all(|w| w[0] < w[1]));
    }

    /// A term the index cannot answer must not turn into a wrong answer - it
    /// costs a scan, and the results are identical.
    #[test]
    fn an_unindexed_term_still_returns_the_right_rows() {
        let decoded = big(2_000);
        let index = Index::build(&decoded);

        // A data byte, which is deliberately not indexed.
        let query = crate::parse("data[0]:0x05").unwrap();
        let got: Vec<usize> = index.hits(&query, &decoded).collect();
        assert_eq!(got, scan(&query, &decoded));
        assert!(!got.is_empty(), "the fixture has a data[0] of 5");
    }

    /// Paging must not repeat or skip a row at the seam.
    #[test]
    fn pages_join_up_without_gaps_or_repeats() {
        let decoded = big(3_000);
        let index = Index::build(&decoded);
        let query = crate::parse("type:WRITE").unwrap();

        let all: Vec<usize> = index.hits(&query, &decoded).collect();
        let mut paged = Vec::new();
        let mut from = 0;
        loop {
            let page = index.page(&query, &decoded, from, 97);
            if page.is_empty() {
                break;
            }
            from += page.len();
            paged.extend(page);
        }
        assert_eq!(paged, all);
        assert_eq!(index.count(&query, &decoded), all.len());
    }

    /// Severity is a threshold, so its lists nest. A row that is an error is
    /// also at or above notice, and a query for notice must find it.
    #[test]
    fn severity_lists_nest_the_way_the_threshold_reads() {
        let mut decoded = big(10);
        decoded.transactions[3].severity = Severity::Error;
        let index = Index::build(&decoded);

        for level in ["info", "notice", "warning", "error"] {
            let query = crate::parse(&format!("severity:{level}")).unwrap();
            let got: Vec<usize> = index.hits(&query, &decoded).collect();
            assert!(got.contains(&3),
                    "the error at row 3 is at or above {level}");
            assert_eq!(got, scan(&query, &decoded));
        }
    }

    #[test]
    fn an_empty_decode_indexes_and_answers_nothing() {
        let decoded = Decoded::default();
        let index = Index::build(&decoded);
        let query = crate::parse("addr:0x52").unwrap();
        assert_eq!(index.rows(), 0);
        assert_eq!(index.count(&query, &decoded), 0);
        assert!(index.field_names().is_empty());
    }

    #[test]
    fn the_index_reports_the_fields_the_decode_actually_carried() {
        let decoded = big(4);
        let index = Index::build(&decoded);
        let names = index.field_names();
        assert!(names.contains(&"address"));
        assert!(names.contains(&"direction"));
        assert!(!names.contains(&"data[0]"),
                "data bytes are searched by pattern, not by equality, so they \
                 are not offered as indexed fields");
    }
}
