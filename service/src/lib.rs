//! The local API: one session, and everything the GUI, the CLI and an agent
//! can ask of it.
//!
//! Section 9: "The GUI must not be the only client. Programmatic access should
//! use the same session and analysis services so automated tests and AI agents
//! see the same decoded truth as a human user." So this is not a wrapper around
//! the CLI's printing - it is the same crates the window calls, with results
//! that serialise.
//!
//! # The safety boundary
//!
//! Section 9.2: "MCP/API actions that change capture configuration or hardware
//! state must be explicit. Read-only analysis operations should be clearly
//! separable from control operations."
//!
//! Every method here is one or the other and says which in
//! [`Operation::kind`]. The MCP server refuses the control half unless it was
//! started with `--allow-control`, so an agent given a session cannot arm the
//! hardware unless somebody decided it may. That is a process-level decision,
//! not a per-call prompt, because a per-call prompt is a thing people click
//! through.
//!
//! # What "stable" means here
//!
//! The method names and their result shapes are section 9.1's list, verbatim
//! where the specification names them. Results are `serde` structs rather than
//! strings so a change to how something is printed is not a change to the API.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use schema::{Decoded, Picos, Protocol, Transaction};
use serde::{Deserialize, Serialize};

pub mod mcp;

/// Which half of the safety boundary an operation falls on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Reads and analyses. Cannot touch hardware or change configuration.
    Read,
    /// Changes capture configuration or hardware state.
    Control,
}

/// One thing the API can do, and which half it is on.
pub struct Operation {
    pub name: &'static str,
    pub kind: Kind,
    pub about: &'static str,
}

/// Section 9.1's surface, with the boundary marked.
pub const OPERATIONS: &[Operation] = &[
    Operation { name: "list_devices", kind: Kind::Read,
                about: "the boards attached" },
    Operation { name: "configure_capture", kind: Kind::Control,
                about: "channels, edge count and burst length for the next capture" },
    Operation { name: "start_capture", kind: Kind::Control,
                about: "arm the board and take a burst, optionally until a trigger matches" },
    Operation { name: "stop_capture", kind: Kind::Control,
                about: "stop a capture in progress" },
    Operation { name: "open_capture", kind: Kind::Read,
                about: "load a capture file into the session" },
    Operation { name: "add_decoder", kind: Kind::Read,
                about: "decode the session's capture as a protocol" },
    Operation { name: "query", kind: Kind::Read,
                about: "find transactions with the query language" },
    Operation { name: "get_transaction", kind: Kind::Read,
                about: "one transaction, its fields, and its neighbours" },
    Operation { name: "get_waveform", kind: Kind::Read,
                about: "raw transitions over a time range" },
    Operation { name: "export", kind: Kind::Read,
                about: "json, csv, or a reproducible evidence package" },
    Operation { name: "add_bookmark", kind: Kind::Read,
                about: "mark a time in the session's capture" },
    Operation { name: "capture_health", kind: Kind::Read,
                about: "gaps, truncation and what the session holds" },
    Operation { name: "compare_transactions", kind: Kind::Read,
                about: "two transactions, field by field" },
    Operation { name: "first_error_after", kind: Kind::Read,
                about: "the first problem after a named event" },
    Operation { name: "summarize_interval", kind: Kind::Read,
                about: "measurements over a time range" },
];

pub fn operation(name: &str) -> Option<&'static Operation> {
    OPERATIONS.iter().find(|o| o.name == name)
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Device {
    pub port: String,
}

/// What the next capture will do.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Named port, or None for the only board attached.
    #[serde(default)]
    pub port: Option<String>,
    /// The board's ring holds this many edges.
    #[serde(default = "default_edges")]
    pub max_edges: u32,
    /// How long to watch, in milliseconds.
    #[serde(default = "default_ms")]
    pub settle_ms: u64,
    /// Drive a known pattern on the board's own taps and capture it. The only
    /// way to get real edges with nothing wired.
    #[serde(default)]
    pub self_test: bool,
    /// Stop when this trigger matches, taking up to `rounds` bursts.
    #[serde(default)]
    pub until: Option<String>,
    #[serde(default = "default_rounds")]
    pub rounds: u32,
}

fn default_edges() -> u32 { 8192 }
fn default_ms() -> u64 { 200 }
fn default_rounds() -> u32 { 1 }

impl Default for CaptureConfig {
    fn default() -> Self {
        CaptureConfig {
            port: None,
            max_edges: default_edges(),
            settle_ms: default_ms(),
            self_test: false,
            until: None,
            rounds: default_rounds(),
        }
    }
}

/// What the session holds, and whether it can be trusted.
///
/// Section 9.1's `capture_health`, and the same facts `sniffer info` prints.
#[derive(Debug, Clone, Serialize)]
pub struct Health {
    pub loaded: bool,
    pub source: String,
    pub path: Option<String>,
    pub channels: Vec<String>,
    pub transitions: u64,
    pub span_ps: Picos,
    pub chunks: usize,
    pub gaps: usize,
    /// Time inside gaps: how much of the session nobody watched.
    pub unwatched_ps: Picos,
    pub truncated_at: Option<u64>,
    pub bookmarks: usize,
    pub protocol: Option<String>,
    pub decoder: Option<String>,
    pub transactions: usize,
    pub with_problems: usize,
    /// True when nothing about the capture is in doubt.
    pub sound: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct DecodeReport {
    pub protocol: String,
    pub decoder: String,
    pub guessed: bool,
    pub transactions: usize,
    pub with_problems: usize,
    pub settings: BTreeMap<String, String>,
}

/// A transaction, flattened to what a caller usually wants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub id: u64,
    pub start_ps: Picos,
    pub end_ps: Picos,
    pub bus: u16,
    pub protocol: String,
    pub kind: String,
    pub summary: String,
    pub severity: String,
    pub complete: bool,
    pub errors: Vec<String>,
}

impl Row {
    fn of(t: &Transaction) -> Row {
        Row {
            id: t.id,
            start_ps: t.start,
            end_ps: t.end,
            bus: t.bus.0,
            protocol: t.protocol.as_str().to_string(),
            kind: t.kind.clone(),
            summary: t.summary.clone(),
            severity: t.severity.as_str().to_string(),
            complete: t.complete,
            errors: t.errors.iter().map(|e| e.as_str().to_string()).collect(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QueryResult {
    pub query: String,
    pub matched: usize,
    /// True when more matched than were returned.
    pub more: bool,
    pub rows: Vec<Row>,
    /// How many candidates the index examined - the number that says whether
    /// the index earned its keep.
    pub examined: usize,
}

/// One transaction with its context, which is what section 9.2 asks for.
#[derive(Debug, Clone, Serialize)]
pub struct Detail {
    pub row: Row,
    pub fields: Vec<FieldOut>,
    pub explanation: Vec<String>,
    /// The transaction before and after it in capture order.
    pub before: Option<Row>,
    pub after: Option<Row>,
    pub parent: Option<Row>,
    pub parts: Vec<Row>,
    /// Where in the raw capture it came from - Appendix B's requirement.
    pub samples: SampleRefOut,
}

#[derive(Debug, Clone, Serialize)]
pub struct FieldOut {
    pub name: String,
    pub display: String,
    pub value: Option<u64>,
    pub kind: String,
    pub start_ps: Picos,
    pub end_ps: Picos,
    pub samples: SampleRefOut,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct SampleRefOut {
    pub chunk: u32,
    pub first: u32,
    pub last: u32,
}

impl From<schema::SampleRef> for SampleRefOut {
    fn from(r: schema::SampleRef) -> Self {
        SampleRefOut { chunk: r.chunk, first: r.first, last: r.last }
    }
}

/// Raw transitions, per channel.
#[derive(Debug, Clone, Serialize)]
pub struct Waveform {
    pub start_ps: Picos,
    pub end_ps: Picos,
    pub channels: Vec<ChannelTrace>,
    /// True when the range held more transitions than were returned.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChannelTrace {
    pub channel: u8,
    pub name: String,
    /// The level the range opened at.
    pub initial: bool,
    /// `(time, level)` for each transition of this channel.
    pub transitions: Vec<(Picos, bool)>,
}

/// What an evidence package contains.
///
/// Section 9.2: "Export a reproducible evidence package containing query,
/// transaction IDs, and waveform range." Reproducible is the operative word:
/// the query, the decoder and its settings, and the clipped samples all travel
/// together, so somebody else can run the same query over the same samples and
/// get the same answer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub tool: String,
    pub captured_from: String,
    pub query: String,
    pub transaction_ids: Vec<u64>,
    pub waveform_start_ps: Picos,
    pub waveform_end_ps: Picos,
    pub protocol: String,
    pub decoder: String,
    pub decoder_settings: BTreeMap<String, String>,
    /// The capture file written beside this manifest, holding exactly the
    /// samples the range covers.
    pub capture_file: String,
    pub rows: Vec<Row>,
}

// ---------------------------------------------------------------------------
// The session
// ---------------------------------------------------------------------------

/// One capture, decoded, with everything the API needs to answer questions
/// about it.
#[derive(Default)]
pub struct Session {
    capture: Option<file::Capture>,
    path: Option<PathBuf>,
    decoded: Decoded,
    index: Option<search::Index>,
    protocol: Option<Protocol>,
    decoder: Option<schema::DecoderInfo>,
    guessed: bool,
    config: CaptureConfig,
}

impl Session {
    pub fn new() -> Session {
        Session::default()
    }

    // ---- control ----------------------------------------------------------

    /// Section 9.1's `list_devices`.
    ///
    /// Read-only despite touching the USB bus: enumerating is not changing
    /// anything, and refusing to say what is attached would make the control
    /// boundary useless to explain.
    pub fn list_devices() -> Vec<Device> {
        capture::list().into_iter().map(|port| Device { port }).collect()
    }

    /// Section 9.1's `configure_capture`.
    ///
    /// Thresholds and sample modes are in the specification's signature and
    /// not in this hardware: the board's taps are digital inputs at a fixed
    /// threshold and it timestamps edges rather than sampling. Rather than
    /// accept parameters it would ignore, this takes what the board actually
    /// has - and says so.
    pub fn configure_capture(&mut self, config: CaptureConfig) -> Result<CaptureConfig, String> {
        if config.max_edges == 0 {
            return Err("max_edges has to be at least one".into());
        }
        if let Some(text) = &config.until {
            // Refused now rather than at capture time, when a board is armed
            // and the mistake costs a bench setup.
            trigger::parse(text)?;
        }
        self.config = config;
        Ok(self.config.clone())
    }

    pub fn configuration(&self) -> &CaptureConfig {
        &self.config
    }

    /// Section 9.1's `start_capture`.
    ///
    /// Blocking, because a burst is: the board is armed, the bus is watched
    /// for the configured milliseconds, and the ring is drained. With a
    /// trigger it repeats up to `rounds` bursts and stops at the first match.
    pub fn start_capture(&mut self) -> Result<Health, String> {
        let condition = match &self.config.until {
            Some(text) => Some(trigger::parse(text)?),
            None => None,
        };
        let board = capture::Board::open(self.config.port.as_deref())
            .map_err(|e| e.0)?;

        let mut whole: Option<file::Capture> = None;
        for _ in 0..self.config.rounds.max(1) {
            let started = std::time::Instant::now();
            let burst = capture::burst(&board, self.config.max_edges,
                                       self.config.settle_ms,
                                       self.config.self_test)
                .map_err(|e| e.0)?;

            let mut gaps = burst.gaps;
            if burst.full {
                gaps.push(file::Gap {
                    start: burst.chunk.end,
                    end: burst.chunk.end,
                    reason: "the board's ring filled; capture stopped there".into(),
                    lost: None,
                });
            }
            let index = file::rebuild_index(std::slice::from_ref(&burst.chunk),
                                            &gaps, &Decoded::default());
            let one = file::Capture {
                session: burst.session,
                chunks: vec![burst.chunk],
                gaps,
                decoders: vec![],
                decoded: Decoded::default(),
                annotations: vec![],
                index,
                truncated_at: None,
            };

            let hit = match &condition {
                None => false,
                Some(c) => {
                    let protocol = registry::guess(&one);
                    let decoded = registry::decoder(protocol, &one).decode(&one);
                    trigger::first(&one, &decoded, c).is_some()
                }
            };

            // The time between two bursts is time nobody watched, and that is
            // loss however normal it is.
            let round_trip = started.elapsed().as_nanos() as u64 * 1_000;
            let unwatched = round_trip.saturating_sub(one.span().1).max(1);
            whole = Some(match whole {
                None => one,
                Some(before) => before.join(&one, unwatched,
                    "between bursts: nothing was watched"),
            });

            if hit {
                break;
            }
        }

        let capture = whole.ok_or("no bursts were captured")?;
        self.adopt(capture, None);
        self.decode_now(None, &BTreeMap::new())?;
        Ok(self.capture_health())
    }

    /// Section 9.1's `stop_capture`.
    ///
    /// There is nothing to stop, and saying so is better than pretending.
    /// This hardware captures in bursts: `start_capture` returns when the
    /// burst it asked for is over, so a session is never left running. The
    /// method exists because the API's shape should not change the day the
    /// firmware grows continuous capture.
    pub fn stop_capture(&self) -> String {
        "nothing to stop: this board captures in bursts, and start_capture \
         returns when the burst it asked for has been drained".into()
    }

    // ---- reading ----------------------------------------------------------

    /// Section 9.1's `open_capture`.
    pub fn open_capture(&mut self, path: &Path) -> Result<Health, String> {
        let capture = file::Capture::open(path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        self.adopt(capture, Some(path.to_path_buf()));
        // Decoded straight away: every other question needs it, and an API
        // that answers "no transactions" until you ask it to decode is a trap.
        self.decode_now(None, &BTreeMap::new())?;
        Ok(self.capture_health())
    }

    /// Load a capture that is already in memory - the simulator's, or one
    /// built by a test.
    pub fn adopt(&mut self, capture: file::Capture, path: Option<PathBuf>) {
        self.capture = Some(capture);
        self.path = path;
        self.decoded = Decoded::default();
        self.index = None;
        self.protocol = None;
        self.decoder = None;
    }

    /// Section 9.1's `add_decoder`.
    ///
    /// Named `add_decoder` in the specification; one at a time in this
    /// release, because a capture has two wires and one protocol on them.
    pub fn add_decoder(
        &mut self,
        protocol: Option<&str>,
        settings: &BTreeMap<String, String>,
    ) -> Result<DecodeReport, String> {
        let protocol = match protocol {
            None => None,
            Some(name) => Some(Protocol::parse(name).ok_or_else(|| {
                let known: Vec<&str> = registry::PROTOCOLS.iter()
                    .map(|(p, _)| p.as_str()).collect();
                format!("unknown protocol {name:?}; try one of: {}",
                        known.join(", "))
            })?),
        };
        self.decode_now(protocol, settings)
    }

    fn decode_now(
        &mut self,
        protocol: Option<Protocol>,
        settings: &BTreeMap<String, String>,
    ) -> Result<DecodeReport, String> {
        let capture = self.capture.as_ref().ok_or("no capture is open")?;
        let pairs: Vec<(&str, &str)> = settings.iter()
            .map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let options = registry::Options::from_pairs(&pairs);

        self.guessed = protocol.is_none();
        let protocol = protocol.unwrap_or_else(|| registry::guess(capture));
        let decoder = registry::decoder_with(protocol, capture, &options);
        let info = decoder.info();
        self.decoded = decoder.decode(capture);
        self.index = Some(search::Index::build(&self.decoded));
        self.protocol = Some(protocol);
        self.decoder = Some(info.clone());

        Ok(DecodeReport {
            protocol: protocol.as_str().to_string(),
            decoder: format!("{} {}", info.name, info.version),
            guessed: self.guessed,
            transactions: self.decoded.transactions.len(),
            with_problems: self.decoded.with_errors().count(),
            settings: info.settings.into_iter().collect(),
        })
    }

    /// Section 9.1's `query`.
    pub fn query(
        &self,
        expression: &str,
        range: Option<(Picos, Picos)>,
        limit: Option<usize>,
    ) -> Result<QueryResult, String> {
        let _ = self.capture.as_ref().ok_or("no capture is open")?;
        let query = search::parse(expression).map_err(|e| e.to_string())?;
        let index = self.index.as_ref().ok_or("nothing has been decoded yet")?;

        let limit = limit.unwrap_or(200);
        let mut hits = index.hits(&query, &self.decoded);
        let mut rows = Vec::new();
        let mut matched = 0usize;
        let mut more = false;

        for row in hits.by_ref() {
            let t = &self.decoded.transactions[row];
            if let Some((from, to)) = range {
                if t.end < from || t.start > to {
                    continue;
                }
            }
            matched += 1;
            if rows.len() < limit {
                rows.push(Row::of(t));
            } else {
                more = true;
                break;
            }
        }

        Ok(QueryResult {
            query: expression.to_string(),
            matched,
            more,
            rows,
            examined: hits.examined(),
        })
    }

    /// Section 9.1's `get_transaction`, with section 9.2's "neighboring
    /// context" - the transactions either side, its parent, and its parts.
    pub fn get_transaction(&self, id: u64) -> Result<Detail, String> {
        let position = self.decoded.transactions.iter()
            .position(|t| t.id == id)
            .ok_or_else(|| format!("no transaction #{id}; the session has {}",
                                   self.decoded.transactions.len()))?;
        let t = &self.decoded.transactions[position];

        Ok(Detail {
            row: Row::of(t),
            fields: t.fields.iter().map(|f| FieldOut {
                name: f.name.clone(),
                display: f.display.clone(),
                value: f.value,
                kind: format!("{:?}", f.kind).to_lowercase(),
                start_ps: f.start,
                end_ps: f.end,
                samples: f.samples.into(),
            }).collect(),
            explanation: measure::explain(t).into_iter()
                .map(|l| format!("{}: {}", l.kind, l.text)).collect(),
            before: position.checked_sub(1)
                .and_then(|i| self.decoded.transactions.get(i)).map(Row::of),
            after: self.decoded.transactions.get(position + 1).map(Row::of),
            parent: t.parent
                .and_then(|p| self.decoded.transactions.iter()
                    .find(|c| c.id == p))
                .map(Row::of),
            parts: self.decoded.transactions.iter()
                .filter(|c| c.parent == Some(id))
                .map(Row::of).collect(),
            samples: t.samples.into(),
        })
    }

    /// Section 9.1's `get_waveform`.
    ///
    /// The raw transitions, per channel, with the level each channel held when
    /// the range opened - without that the caller cannot draw the first hold,
    /// which is the same trap the timeline fell into once.
    pub fn get_waveform(
        &self,
        start: Picos,
        end: Picos,
        channels: Option<&[u8]>,
        limit: Option<usize>,
    ) -> Result<Waveform, String> {
        let capture = self.capture.as_ref().ok_or("no capture is open")?;
        let (start, end) = if start <= end { (start, end) } else { (end, start) };
        let limit = limit.unwrap_or(4_000);

        let wanted: Vec<u8> = match channels {
            Some(list) => list.to_vec(),
            None => (0..capture.session.channels.len() as u8).collect(),
        };

        let mut truncated = false;
        let mut traces = Vec::new();
        for channel in wanted {
            let name = capture.session.channels.get(channel as usize)
                .cloned().unwrap_or_else(|| format!("ch{channel}"));
            let mut initial = false;
            let mut transitions = Vec::new();
            let mut seen_initial = false;

            for chunk in &capture.chunks {
                if chunk.is_empty() || chunk.end < start || chunk.start > end {
                    continue;
                }
                let first = match chunk.times.binary_search(&start) {
                    Ok(i) => i,
                    Err(0) => 0,
                    Err(i) => i - 1,
                };
                if !seen_initial {
                    initial = chunk.channel(first, channel);
                    seen_initial = true;
                }
                let mut previous = chunk.channel(first, channel);
                for i in (first + 1)..chunk.len() {
                    let at = chunk.times[i];
                    if at > end {
                        break;
                    }
                    let level = chunk.channel(i, channel);
                    if level != previous && at >= start {
                        if transitions.len() >= limit {
                            truncated = true;
                            break;
                        }
                        transitions.push((at, level));
                    }
                    previous = level;
                }
            }
            traces.push(ChannelTrace { channel, name, initial, transitions });
        }

        Ok(Waveform { start_ps: start, end_ps: end, channels: traces, truncated })
    }

    /// Section 9.1's `add_bookmark`.
    ///
    /// Read-side, not control: it changes the session's capture in memory, not
    /// the hardware or the capture configuration. It reaches the file only when
    /// the session is saved.
    pub fn add_bookmark(&mut self, at: Picos, label: &str, note: &str)
        -> Result<usize, String>
    {
        let capture = self.capture.as_mut().ok_or("no capture is open")?;
        capture.annotations.push(file::Annotation {
            start: at,
            end: at,
            label: label.to_string(),
            note: note.to_string(),
        });
        capture.annotations.sort_by_key(|a| a.start);
        Ok(capture.annotations.len())
    }

    /// Section 9.1's `capture_health`.
    pub fn capture_health(&self) -> Health {
        let Some(capture) = self.capture.as_ref() else {
            return Health {
                loaded: false,
                source: "nothing open".into(),
                path: None,
                channels: Vec::new(),
                transitions: 0,
                span_ps: 0,
                chunks: 0,
                gaps: 0,
                unwatched_ps: 0,
                truncated_at: None,
                bookmarks: 0,
                protocol: None,
                decoder: None,
                transactions: 0,
                with_problems: 0,
                sound: true,
            };
        };
        let (first, last) = capture.span();
        let unwatched: Picos = capture.gaps.iter()
            .map(|g| g.end.saturating_sub(g.start)).sum();

        Health {
            loaded: true,
            source: capture.session.source.clone(),
            path: self.path.as_ref().map(|p| p.display().to_string()),
            channels: capture.session.channels.clone(),
            transitions: capture.chunks.iter()
                .map(|c| c.transitions() as u64).sum(),
            span_ps: last.saturating_sub(first),
            chunks: capture.chunks.len(),
            gaps: capture.gaps.len(),
            unwatched_ps: unwatched,
            truncated_at: capture.truncated_at,
            bookmarks: capture.annotations.len(),
            protocol: self.protocol.map(|p| p.as_str().to_string()),
            decoder: self.decoder.as_ref()
                .map(|d| format!("{} {}", d.name, d.version)),
            transactions: self.decoded.transactions.len(),
            with_problems: self.decoded.with_errors().count(),
            sound: capture.gaps.is_empty() && capture.truncated_at.is_none(),
        }
    }

    /// Section 9.2's "compare two transactions".
    pub fn compare_transactions(&self, a: u64, b: u64)
        -> Result<serde_json::Value, String>
    {
        let find = |id: u64| self.decoded.transactions.iter()
            .find(|t| t.id == id)
            .ok_or_else(|| format!("no transaction #{id}"));
        let (first, second) = (find(a)?, find(b)?);
        let comparison = measure::compare(first, second);

        Ok(serde_json::json!({
            "a": Row::of(first),
            "b": Row::of(second),
            "comparable": comparison.comparable,
            "why_not": comparison.why_not,
            "identical_content": comparison.identical_content(),
            "fields": comparison.fields.iter().map(|f| serde_json::json!({
                "name": f.name,
                "a": f.a,
                "b": f.b,
                "differs": f.differs(),
            })).collect::<Vec<_>>(),
            "duration_ps": [comparison.duration.0, comparison.duration.1],
        }))
    }

    /// Section 9.2's "find first error after a named event".
    ///
    /// The event is a trigger condition, so "the first NACK after the CCC that
    /// assigns an address" is one call rather than two searches and some
    /// arithmetic.
    pub fn first_error_after(&self, event: &str)
        -> Result<serde_json::Value, String>
    {
        let capture = self.capture.as_ref().ok_or("no capture is open")?;
        let condition = trigger::parse(event)?;
        let Some(hit) = trigger::first(capture, &self.decoded, &condition) else {
            return Ok(serde_json::json!({
                "event": event,
                "found": false,
                "why": "the event never happened in this capture",
            }));
        };

        let problem = self.decoded.transactions.iter()
            .filter(|t| !t.errors.is_empty() || !t.complete)
            .find(|t| t.start >= hit.at);

        Ok(serde_json::json!({
            "event": event,
            "found": true,
            "event_at_ps": hit.at,
            "event_what": hit.what,
            "error": problem.map(Row::of),
            "delay_ps": problem.map(|t| t.start.saturating_sub(hit.at)),
        }))
    }

    /// Section 9.2's "summarize bus activity over a selected interval".
    pub fn summarize_interval(&self, start: Picos, end: Picos)
        -> Result<serde_json::Value, String>
    {
        let capture = self.capture.as_ref().ok_or("no capture is open")?;
        let m = measure::measure(capture, &self.decoded, start, end);
        Ok(serde_json::json!({
            "start_ps": m.start,
            "end_ps": m.end,
            "duration": measure::human_time(m.duration),
            "duration_ps": m.duration,
            "channels": m.channels.iter().map(|c| serde_json::json!({
                "name": c.name,
                "edges": c.edges,
                "rising": c.rising,
                "duty": c.duty,
                "clock": c.frequency_hz.map(measure::human_rate),
                "shortest": c.shortest.map(measure::human_time),
            })).collect::<Vec<_>>(),
            "transactions": m.transactions,
            "with_problems": m.errors,
            "incomplete": m.incomplete,
            "payload_bytes": m.payload_bytes,
            "throughput": measure::human_bytes_per_second(m.payload_bytes_per_second),
            "utilisation": m.utilisation,
            "gap_overlap": m.gap_overlap,
        }))
    }

    /// Section 9.1's `export`, including section 9.2's evidence package.
    ///
    /// `json` and `csv` return text. `evidence` writes a directory holding the
    /// manifest and a capture clipped to the waveform range, and returns where
    /// it put it.
    pub fn export(
        &self,
        format: &str,
        query: Option<&str>,
        out: Option<&Path>,
    ) -> Result<String, String> {
        let capture = self.capture.as_ref().ok_or("no capture is open")?;
        let selected: Vec<&Transaction> = match query {
            None => self.decoded.transactions.iter().collect(),
            Some(expression) => {
                let q = search::parse(expression).map_err(|e| e.to_string())?;
                q.run(&self.decoded)
            }
        };

        match format.to_ascii_lowercase().as_str() {
            "json" => {
                let rows: Vec<Row> = selected.iter().map(|t| Row::of(t)).collect();
                serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())
            }
            "csv" => {
                let mut out = String::from(
                    "id,start_ps,end_ps,bus,protocol,kind,severity,complete,\
                     summary,errors\n");
                for t in &selected {
                    out.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{},{}\n",
                        t.id, t.start, t.end, t.bus.0, t.protocol.as_str(),
                        csv_quote(&t.kind), t.severity.as_str(), t.complete,
                        csv_quote(&t.summary),
                        csv_quote(&t.errors.iter().map(|e| e.as_str())
                            .collect::<Vec<_>>().join(" "))));
                }
                Ok(out)
            }
            "evidence" => {
                let dir = out.ok_or("an evidence package needs a directory \
                                     to write into")?;
                self.write_evidence(capture, &selected, query.unwrap_or(""), dir)
            }
            other => Err(format!(
                "unknown format {other:?}; try json, csv or evidence")),
        }
    }

    fn write_evidence(
        &self,
        capture: &file::Capture,
        selected: &[&Transaction],
        query: &str,
        dir: &Path,
    ) -> Result<String, String> {
        if selected.is_empty() {
            return Err("nothing matched, so there is nothing to evidence".into());
        }
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot make {}: {e}", dir.display()))?;

        // The waveform range is the selection's own span, with a little room
        // either side so the framing before and after it is visible.
        let first = selected.iter().map(|t| t.start).min().unwrap_or(0);
        let last = selected.iter().map(|t| t.end).max().unwrap_or(0);
        let pad = (last.saturating_sub(first) / 10).max(1_000_000);
        let (from, to) = (first.saturating_sub(pad), last + pad);

        let clip = capture.clip(from, to);
        let capture_file = dir.join("evidence.cap");
        let handle = std::fs::File::create(&capture_file)
            .map_err(|e| format!("cannot write {}: {e}", capture_file.display()))?;
        let mut writer = file::Writer::new(handle, &clip.session)
            .map_err(|e| e.to_string())?;
        for chunk in &clip.chunks {
            writer.chunk(chunk).map_err(|e| e.to_string())?;
        }
        for gap in &clip.gaps {
            writer.gap(gap).map_err(|e| e.to_string())?;
        }
        for a in &clip.annotations {
            writer.annotation(a).map_err(|e| e.to_string())?;
        }
        writer.finish().map_err(|e| e.to_string())?;

        let info = self.decoder.clone();
        let evidence = Evidence {
            tool: format!("sniffer {}", env!("CARGO_PKG_VERSION")),
            captured_from: capture.session.source.clone(),
            query: query.to_string(),
            transaction_ids: selected.iter().map(|t| t.id).collect(),
            waveform_start_ps: from,
            waveform_end_ps: to,
            protocol: self.protocol.map(|p| p.as_str().to_string())
                .unwrap_or_default(),
            decoder: info.as_ref()
                .map(|d| format!("{} {}", d.name, d.version))
                .unwrap_or_default(),
            decoder_settings: info.map(|d| d.settings.into_iter().collect())
                .unwrap_or_default(),
            capture_file: "evidence.cap".into(),
            rows: selected.iter().map(|t| Row::of(t)).collect(),
        };

        let manifest = dir.join("evidence.json");
        std::fs::write(&manifest,
                       serde_json::to_string_pretty(&evidence)
                           .map_err(|e| e.to_string())?)
            .map_err(|e| format!("cannot write {}: {e}", manifest.display()))?;

        Ok(dir.display().to_string())
    }

    /// Save the session's capture, bookmarks and decode to a file.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let capture = self.capture.as_ref().ok_or("no capture is open")?;
        let handle = std::fs::File::create(path)
            .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
        let mut writer = file::Writer::new(handle, &capture.session)
            .map_err(|e| e.to_string())?;
        for chunk in &capture.chunks {
            writer.chunk(chunk).map_err(|e| e.to_string())?;
        }
        for gap in &capture.gaps {
            writer.gap(gap).map_err(|e| e.to_string())?;
        }
        if let Some(info) = &self.decoder {
            writer.decoder(info).map_err(|e| e.to_string())?;
            writer.decoded(&self.decoded).map_err(|e| e.to_string())?;
        }
        for a in &capture.annotations {
            writer.annotation(a).map_err(|e| e.to_string())?;
        }
        writer.finish().map_err(|e| e.to_string())
    }

    pub fn decoded(&self) -> &Decoded {
        &self.decoded
    }

    pub fn capture(&self) -> Option<&file::Capture> {
        self.capture.as_ref()
    }
}

fn csv_quote(text: &str) -> String {
    if text.contains(',') || text.contains('"') || text.contains('\n') {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> Session {
        let mut s = Session::new();
        let cap = simulator::build("demo", 1_000_000).unwrap();
        s.adopt(cap, None);
        s.add_decoder(None, &BTreeMap::new()).unwrap();
        s
    }

    /// The boundary section 9.2 asks for, stated once and machine-readable.
    #[test]
    fn every_operation_is_on_one_side_of_the_boundary() {
        let control: Vec<&str> = OPERATIONS.iter()
            .filter(|o| o.kind == Kind::Control).map(|o| o.name).collect();
        assert_eq!(control, vec!["configure_capture", "start_capture",
                                 "stop_capture"],
                   "the control half is what touches hardware or capture \
                    configuration, and nothing else");
        for o in OPERATIONS {
            assert!(!o.about.is_empty(), "{} does not say what it does", o.name);
        }
        // Section 9.1's list, all present.
        for name in ["list_devices", "configure_capture", "start_capture",
                     "stop_capture", "open_capture", "add_decoder", "query",
                     "get_transaction", "get_waveform", "export",
                     "add_bookmark", "capture_health"] {
            assert!(operation(name).is_some(), "{name} is missing");
        }
    }

    #[test]
    fn an_empty_session_answers_rather_than_panicking() {
        let s = Session::new();
        let health = s.capture_health();
        assert!(!health.loaded);
        assert_eq!(health.transactions, 0);
        assert!(s.query("addr:0x52", None, None).is_err());
        assert!(s.get_transaction(1).is_err());
        assert!(s.get_waveform(0, 1_000, None, None).is_err());
        assert!(s.export("json", None, None).is_err());
    }

    #[test]
    fn a_session_decodes_what_it_opens() {
        let s = session();
        let health = s.capture_health();
        assert!(health.loaded);
        assert_eq!(health.protocol.as_deref(), Some("i2c"));
        assert_eq!(health.transactions, 6);
        assert_eq!(health.with_problems, 1);
        assert!(health.sound, "the demo traffic has no gaps");
    }

    #[test]
    fn health_reports_gaps_as_unsound_and_says_how_much_was_missed() {
        let mut s = Session::new();
        s.adopt(simulator::build_with_gap("demo", 1_000_000).unwrap(), None);
        s.add_decoder(None, &BTreeMap::new()).unwrap();
        let health = s.capture_health();
        assert!(health.gaps > 0);
        assert!(health.unwatched_ps > 0);
        assert!(!health.sound, "a capture with holes is not sound");
    }

    #[test]
    fn query_runs_the_same_language_as_everything_else() {
        let s = session();
        let result = s.query("addr:0x52", None, None).unwrap();
        assert_eq!(result.matched, 4);
        assert_eq!(result.rows.len(), 4);
        assert!(!result.more);
        assert!(result.examined >= result.matched);

        // A limit is a page, and says there is more.
        let page = s.query("addr:0x52", None, Some(2)).unwrap();
        assert_eq!(page.rows.len(), 2);
        assert!(page.more);
    }

    #[test]
    fn query_can_be_confined_to_a_time_range() {
        let s = session();
        let all = s.query("type:WRITE", None, None).unwrap();
        let early = s.query("type:WRITE", Some((0, 40_000_000)), None).unwrap();
        assert!(early.matched < all.matched);
        assert!(early.rows.iter().all(|r| r.start_ps < 40_000_000));
    }

    #[test]
    fn a_transaction_comes_with_its_neighbours_and_its_evidence() {
        let s = session();
        let detail = s.get_transaction(2).unwrap();
        assert_eq!(detail.row.id, 2);
        assert!(detail.before.is_some());
        assert!(detail.after.is_some());
        assert!(!detail.fields.is_empty());
        assert!(!detail.explanation.is_empty());
        // Appendix B: every field traces to samples.
        for f in &detail.fields {
            assert!(f.samples.last >= f.samples.first);
        }
    }

    /// A waveform without the level each channel opened at cannot be drawn:
    /// the first hold would be missing. The same trap the timeline fell into.
    #[test]
    fn a_waveform_says_what_level_each_channel_opened_at() {
        let s = session();
        let wave = s.get_waveform(20_000_000, 30_000_000, None, None).unwrap();
        assert_eq!(wave.channels.len(), 2);
        for trace in &wave.channels {
            assert!(!trace.name.is_empty());
            // Every transition is inside the range and is a real change.
            assert!(trace.transitions.iter()
                .all(|(t, _)| *t >= wave.start_ps && *t <= wave.end_ps));
            let mut level = trace.initial;
            for (_, next) in &trace.transitions {
                assert_ne!(*next, level, "a transition that changes nothing");
                level = *next;
            }
        }
    }

    #[test]
    fn a_waveform_can_be_confined_to_one_channel_and_capped() {
        let s = session();
        let wave = s.get_waveform(0, 200_000_000, Some(&[1]), Some(5)).unwrap();
        assert_eq!(wave.channels.len(), 1);
        assert_eq!(wave.channels[0].channel, 1);
        assert!(wave.channels[0].transitions.len() <= 5);
        assert!(wave.truncated, "a capped waveform has to admit it");
    }

    #[test]
    fn exports_are_the_same_rows_in_two_formats() {
        let s = session();
        let json = s.export("json", Some("addr:0x52"), None).unwrap();
        let rows: Vec<serde_json::Value> = serde_json::from_str(&json).unwrap();
        assert_eq!(rows.len(), 4);

        let csv = s.export("csv", Some("addr:0x52"), None).unwrap();
        assert_eq!(csv.lines().count(), 5, "a header and four rows");
        assert!(csv.lines().next().unwrap().starts_with("id,start_ps"));

        assert!(s.export("yaml", None, None).is_err());
    }

    /// Section 9.2's evidence package: reproducible means the query, the
    /// decoder and the samples travel together.
    #[test]
    fn an_evidence_package_carries_enough_to_reproduce_the_finding() {
        let s = session();
        let dir = std::env::temp_dir().join("sniffer-evidence-test");
        let _ = std::fs::remove_dir_all(&dir);
        let where_ = s.export("evidence", Some("error:any"), Some(&dir)).unwrap();
        assert!(where_.contains("sniffer-evidence-test"));

        let manifest: Evidence = serde_json::from_str(
            &std::fs::read_to_string(dir.join("evidence.json")).unwrap()).unwrap();
        assert_eq!(manifest.query, "error:any");
        assert_eq!(manifest.transaction_ids.len(), 1);
        assert!(!manifest.decoder.is_empty());
        assert!(manifest.waveform_end_ps > manifest.waveform_start_ps);

        // The capture beside it holds those samples and decodes to the same
        // finding, which is what makes the package evidence rather than a
        // screenshot.
        let clip = file::Capture::open(dir.join(&manifest.capture_file)).unwrap();
        let protocol = registry::guess(&clip);
        let again = registry::decoder(protocol, &clip).decode(&clip);
        assert!(again.with_errors().count() >= 1,
                "the clipped samples no longer show the problem they are \
                 evidence of");
    }

    #[test]
    fn an_evidence_package_of_nothing_is_refused() {
        let s = session();
        let dir = std::env::temp_dir().join("sniffer-evidence-empty");
        assert!(s.export("evidence", Some("addr:0x11"), Some(&dir)).is_err());
    }

    #[test]
    fn comparing_two_transactions_marks_what_differs() {
        let s = session();
        let out = s.compare_transactions(1, 4).unwrap();
        assert_eq!(out["comparable"], serde_json::json!(true));
        let fields = out["fields"].as_array().unwrap();
        let address = fields.iter()
            .find(|f| f["name"] == "address").unwrap();
        assert_eq!(address["differs"], serde_json::json!(true));
        assert!(s.compare_transactions(1, 999).is_err());
    }

    #[test]
    fn the_first_error_after_an_event_is_one_call() {
        let s = session();
        let out = s.first_error_after("addr:0x3C").unwrap();
        assert_eq!(out["found"], serde_json::json!(true));
        assert!(out["error"]["errors"].as_array().unwrap()
            .iter().any(|e| e == "nack"));
        assert!(out["delay_ps"].as_u64().unwrap() > 0);

        // An event that never happens says so rather than guessing.
        let out = s.first_error_after("addr:0x11").unwrap();
        assert_eq!(out["found"], serde_json::json!(false));
    }

    #[test]
    fn summarising_an_interval_gives_the_same_numbers_as_measure() {
        let s = session();
        let (first, last) = s.capture().unwrap().span();
        let out = s.summarize_interval(first, last).unwrap();
        assert_eq!(out["transactions"], serde_json::json!(6));
        assert_eq!(out["with_problems"], serde_json::json!(1));
        assert!(out["utilisation"].as_f64().unwrap() > 0.0);
        assert!(out["channels"].as_array().unwrap().len() == 2);
    }

    #[test]
    fn a_bookmark_lands_in_the_session_and_survives_a_save() {
        let mut s = session();
        assert_eq!(s.add_bookmark(1_000, "here", "why").unwrap(), 1);

        let path = std::env::temp_dir().join("sniffer-service-save.cap");
        let _ = std::fs::remove_file(&path);
        s.save(&path).unwrap();

        let mut reopened = Session::new();
        reopened.open_capture(&path).unwrap();
        let health = reopened.capture_health();
        assert_eq!(health.bookmarks, 1);
        assert_eq!(health.transactions, 6, "and the decode came back with it");
    }

    #[test]
    fn a_bad_protocol_or_trigger_is_refused_before_anything_is_armed() {
        let mut s = session();
        let err = s.add_decoder(Some("smoke-signals"), &BTreeMap::new())
            .unwrap_err();
        assert!(err.contains("unknown protocol"), "{err}");

        let mut config = CaptureConfig::default();
        config.until = Some("wibble".into());
        let err = s.configure_capture(config).unwrap_err();
        assert!(err.contains("edge:rising:0"),
                "a bad trigger has to be refused before a board is armed: {err}");

        let mut config = CaptureConfig::default();
        config.max_edges = 0;
        assert!(s.configure_capture(config).is_err());
    }

    #[test]
    fn stop_capture_says_plainly_that_there_is_nothing_to_stop() {
        let s = Session::new();
        assert!(s.stop_capture().contains("bursts"));
    }
}
