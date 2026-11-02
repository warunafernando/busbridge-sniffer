//! Triggers: what to look for, and where it can be looked for.
//!
//! Section 10 asks for one trigger model covering both hardware and
//! software/post-capture triggers, with the builder saying which conditions
//! can run in hardware. Its classes are edge/level, bus activity, protocol
//! field, error, and sequence.
//!
//! # Where a condition can run, and where it does run
//!
//! These are two different questions and conflating them would be a lie in a
//! tooltip:
//!
//! - [`Condition::class`] says which of section 10's classes it is, and
//!   [`Condition::hardware_class`] whether that class is one a capture engine
//!   could implement. An edge on a channel is; "the third NACK after a CCC" is
//!   not.
//! - [`hardware_available`] says whether the hardware in front of us
//!   implements any trigger at all. On the BUSBRIDGE board today it does not:
//!   `SNIFF:RAW:*` captures every edge into a ring and hands it over, with no
//!   condition to arm. So every trigger here runs in software, over samples
//!   that have already been captured.
//!
//! That is not a workaround. Section 10 says sequence triggers are "primarily
//! post-capture/search in first release", and the same reasoning applies to
//! the rest while the capture engine has no comparator: a post-capture trigger
//! finds the same moment, and the pre-trigger window comes free because the
//! samples before the match were captured too.
//!
//! # Pre-trigger is a clip
//!
//! A hardware trigger needs a ring buffer to keep the samples before the
//! event. A burst capture already has them, so "500 us before the trigger and
//! 2 ms after" is [`file::Capture::clip`] around the match - which is why that
//! lives in the file crate and keeps the format's invariants rather than being
//! done by hand here.

#![forbid(unsafe_code)]

use schema::{Decoded, Picos, Transaction};

/// Which of section 10's classes a condition belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    EdgeLevel,
    BusActivity,
    ProtocolField,
    Error,
    Sequence,
    /// A combination of the above.
    Composite,
}

impl Class {
    pub fn as_str(self) -> &'static str {
        match self {
            Class::EdgeLevel => "edge/level",
            Class::BusActivity => "bus activity",
            Class::ProtocolField => "protocol field",
            Class::Error => "error",
            Class::Sequence => "sequence",
            Class::Composite => "composite",
        }
    }

    /// Could a capture engine implement this class in hardware?
    ///
    /// Section 10's own answer: edge and level yes; bus activity yes for the
    /// framing a comparator can see; protocol field "depends on the capture
    /// engine"; error "may be software-only initially"; sequence
    /// "primarily post-capture".
    pub fn could_run_in_hardware(self) -> bool {
        matches!(self, Class::EdgeLevel | Class::BusActivity)
    }
}

/// Which way an edge goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Rising,
    Falling,
    Either,
}

impl Direction {
    fn matches(self, was: bool, now: bool) -> bool {
        match self {
            Direction::Rising => !was && now,
            Direction::Falling => was && !now,
            Direction::Either => was != now,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Rising => "rising",
            Direction::Falling => "falling",
            Direction::Either => "either",
        }
    }
}

/// What to trigger on.
#[derive(Debug, Clone, PartialEq)]
pub enum Condition {
    /// An edge on a channel.
    Edge { channel: u8, direction: Direction },
    /// A level held for at least this long. `None` means "at all".
    Level { channel: u8, high: bool, for_at_least: Option<Picos> },
    /// A pulse narrower or wider than a bound - a glitch, or a stretched
    /// clock.
    Pulse { channel: u8, high: bool, shorter_than: Option<Picos>,
            longer_than: Option<Picos> },
    /// The framing a protocol starts with: a START, a CS assert, a UART start
    /// bit, a CAN SOF. All of them are "a transaction began", which is what
    /// the decoder reports, so that is what this matches.
    TransactionStart { protocol: Option<schema::Protocol> },
    /// A decoded field equal to a value: an I2C address, a CAN id, an MDIO
    /// register.
    Field { name: String, value: search::Match },
    /// A kind of transaction: WRITE, IBI, CCC.
    Kind(String),
    /// Any error, or one by name.
    Error(Option<String>),
    /// A followed by B within a window.
    Sequence { first: Box<Condition>, then: Box<Condition>, within: Picos },
    /// Every one of these, at the same transaction or sample.
    All(Vec<Condition>),
    /// Any one of these.
    Any(Vec<Condition>),
}

impl Condition {
    pub fn class(&self) -> Class {
        match self {
            Condition::Edge { .. } | Condition::Level { .. }
                | Condition::Pulse { .. } => Class::EdgeLevel,
            Condition::TransactionStart { .. } => Class::BusActivity,
            Condition::Field { .. } | Condition::Kind(_) => Class::ProtocolField,
            Condition::Error(_) => Class::Error,
            Condition::Sequence { .. } => Class::Sequence,
            Condition::All(_) | Condition::Any(_) => Class::Composite,
        }
    }

    /// Could this run in hardware, on a capture engine that supported its
    /// class? A composite is only as hardware-able as its least able part.
    pub fn hardware_class(&self) -> bool {
        match self {
            Condition::All(parts) | Condition::Any(parts) =>
                !parts.is_empty() && parts.iter().all(|p| p.hardware_class()),
            other => other.class().could_run_in_hardware(),
        }
    }

    /// What this condition needs to be evaluated: samples, or a decode.
    pub fn needs_decode(&self) -> bool {
        match self {
            Condition::Edge { .. } | Condition::Level { .. }
                | Condition::Pulse { .. } => false,
            Condition::All(parts) | Condition::Any(parts) =>
                parts.iter().any(|p| p.needs_decode()),
            Condition::Sequence { first, then, .. } =>
                first.needs_decode() || then.needs_decode(),
            _ => true,
        }
    }

    /// One line saying what it is, for a builder that has to explain itself.
    pub fn describe(&self) -> String {
        match self {
            Condition::Edge { channel, direction } =>
                format!("a {} edge on channel {channel}", direction.as_str()),
            Condition::Level { channel, high, for_at_least } => {
                let level = if *high { "high" } else { "low" };
                match for_at_least {
                    Some(t) => format!("channel {channel} {level} for at least \
                                        {t} ps"),
                    None => format!("channel {channel} {level}"),
                }
            }
            Condition::Pulse { channel, high, shorter_than, longer_than } => {
                let level = if *high { "high" } else { "low" };
                let mut what = format!("a {level} pulse on channel {channel}");
                if let Some(t) = shorter_than {
                    what.push_str(&format!(" shorter than {}",
                                           measure::human_time(*t)));
                }
                if let Some(t) = longer_than {
                    what.push_str(&format!(" longer than {}",
                                           measure::human_time(*t)));
                }
                what
            }
            Condition::TransactionStart { protocol } => match protocol {
                Some(p) => format!("the start of any {} transaction", p.as_str()),
                None => "the start of any transaction".to_string(),
            },
            Condition::Field { name, value } => match value {
                search::Match::Number(n) => format!("{name} equal to {n:#x}"),
                search::Match::Text(t) => format!("{name} equal to {t:?}"),
            },
            Condition::Kind(k) => format!("a {k} transaction"),
            Condition::Error(None) => "anything with an error".to_string(),
            Condition::Error(Some(name)) => format!("a {name} error"),
            Condition::Sequence { first, then, within } =>
                format!("{}, then {} within {}",
                        first.describe(), then.describe(),
                        measure::human_time(*within)),
            Condition::All(parts) => parts.iter().map(|p| p.describe())
                .collect::<Vec<_>>().join(" and "),
            Condition::Any(parts) => parts.iter().map(|p| p.describe())
                .collect::<Vec<_>>().join(" or "),
        }
    }
}

/// Whether the connected hardware can arm a trigger of its own.
///
/// It cannot, today: the board's `SNIFF:RAW:*` mode captures every edge into a
/// ring and hands the ring over, with no condition to arm and no comparator to
/// arm it with. Stated as a function rather than left implicit so the window
/// can say so plainly, and so the day the firmware grows a trigger there is
/// one place to change.
pub fn hardware_available() -> bool {
    false
}

/// Why not, for the tooltip that has to explain it.
pub const NO_HARDWARE_TRIGGER: &str =
    "this board captures every edge into a ring and hands it over, with no \
     condition to arm, so triggers are evaluated over the samples afterwards. \
     The samples before the match are already there, which is what a hardware \
     trigger needs a ring buffer for.";

/// Where a match happened.
#[derive(Debug, Clone, PartialEq)]
pub struct Match {
    pub at: Picos,
    /// What matched, in words.
    pub what: String,
    /// The transaction it was found in, when it was found in one.
    pub transaction: Option<u64>,
}

/// Every match, in time order.
pub fn find(
    capture: &file::Capture,
    decoded: &Decoded,
    condition: &Condition,
) -> Vec<Match> {
    let mut found = match condition {
        Condition::Edge { channel, direction } =>
            edges(capture, *channel, *direction),
        Condition::Level { channel, high, for_at_least } =>
            levels(capture, *channel, *high, *for_at_least),
        Condition::Pulse { channel, high, shorter_than, longer_than } =>
            pulses(capture, *channel, *high, *shorter_than, *longer_than),
        Condition::TransactionStart { protocol } => decoded.transactions.iter()
            .filter(|t| protocol.map(|p| t.protocol == p).unwrap_or(true))
            .map(|t| Match {
                at: t.start,
                what: format!("{} {} begins", t.protocol.as_str(), t.kind),
                transaction: Some(t.id),
            })
            .collect(),
        Condition::Field { .. } | Condition::Kind(_) | Condition::Error(_) =>
            transactions(decoded, condition),
        Condition::Sequence { first, then, within } => {
            let a = find(capture, decoded, first);
            let b = find(capture, decoded, then);
            let mut out = Vec::new();
            for start in &a {
                // The first B strictly after this A and inside the window. A
                // sequence match is reported at the *second* event, because
                // that is the moment the sequence completed - and the moment
                // somebody wants to look at.
                if let Some(second) = b.iter()
                    .find(|m| m.at > start.at && m.at - start.at <= *within)
                {
                    out.push(Match {
                        at: second.at,
                        what: format!("{} then {} after {}",
                                      start.what, second.what,
                                      measure::human_time(second.at - start.at)),
                        transaction: second.transaction,
                    });
                }
            }
            out
        }
        Condition::Any(parts) => {
            let mut out = Vec::new();
            for p in parts {
                out.extend(find(capture, decoded, p));
            }
            out
        }
        Condition::All(parts) => {
            // Everything the first part matched that every other part also
            // matched, by transaction where there is one and by time where
            // there is not.
            let Some((head, rest)) = parts.split_first() else { return Vec::new() };
            let mut out = find(capture, decoded, head);
            for p in rest {
                let theirs = find(capture, decoded, p);
                out.retain(|mine| theirs.iter().any(|other| {
                    match (mine.transaction, other.transaction) {
                        (Some(a), Some(b)) => a == b,
                        _ => a_close(mine.at, other.at),
                    }
                }));
            }
            out
        }
    };
    found.sort_by_key(|m| m.at);
    found.dedup_by(|a, b| a.at == b.at && a.what == b.what);
    found
}

/// Two sample-level matches at the same moment. Exact equality, because both
/// come from the same capture's timestamps rather than from arithmetic.
fn a_close(a: Picos, b: Picos) -> bool {
    a == b
}

/// The first match, which is what a trigger is usually asked for.
pub fn first(
    capture: &file::Capture,
    decoded: &Decoded,
    condition: &Condition,
) -> Option<Match> {
    find(capture, decoded, condition).into_iter().next()
}

/// The window a pre-trigger capture would have kept.
///
/// `before` and `after` are picoseconds either side of the match, clamped to
/// the capture.
pub fn window(
    capture: &file::Capture,
    at: Picos,
    before: Picos,
    after: Picos,
) -> (Picos, Picos) {
    let (first, last) = capture.span();
    (at.saturating_sub(before).max(first), (at + after).min(last))
}

fn edges(capture: &file::Capture, channel: u8, direction: Direction)
    -> Vec<Match>
{
    let mut out = Vec::new();
    for chunk in &capture.chunks {
        // From the second entry: the first is the initial state, not a
        // transition, so treating it as one would report an edge that never
        // happened at the moment capture was armed.
        for i in 1..chunk.len() {
            let was = chunk.channel(i - 1, channel);
            let now = chunk.channel(i, channel);
            if direction.matches(was, now) {
                out.push(Match {
                    at: chunk.times[i],
                    what: format!("{} edge on channel {channel}",
                                  if now { "rising" } else { "falling" }),
                    transaction: None,
                });
            }
        }
    }
    out
}

/// Where a level began, and how long it held.
fn holds(capture: &file::Capture, channel: u8, high: bool)
    -> Vec<(Picos, Picos)>
{
    let mut out = Vec::new();
    for chunk in &capture.chunks {
        let mut i = 0;
        while i < chunk.len() {
            let level = chunk.channel(i, channel);
            let from = chunk.times[i];
            // Run on while this channel does not change: an entry where some
            // other channel moved does not end this level.
            let mut j = i + 1;
            while j < chunk.len() && chunk.channel(j, channel) == level {
                j += 1;
            }
            let to = if j < chunk.len() { chunk.times[j] } else { chunk.end };
            if level == high && to > from {
                out.push((from, to - from));
            }
            i = j;
        }
    }
    out
}

fn levels(
    capture: &file::Capture,
    channel: u8,
    high: bool,
    for_at_least: Option<Picos>,
) -> Vec<Match> {
    holds(capture, channel, high).into_iter()
        .filter(|(_, held)| for_at_least.map(|t| *held >= t).unwrap_or(true))
        .map(|(at, held)| Match {
            at,
            what: format!("channel {channel} {} for {}",
                          if high { "high" } else { "low" },
                          measure::human_time(held)),
            transaction: None,
        })
        .collect()
}

fn pulses(
    capture: &file::Capture,
    channel: u8,
    high: bool,
    shorter_than: Option<Picos>,
    longer_than: Option<Picos>,
) -> Vec<Match> {
    holds(capture, channel, high).into_iter()
        .filter(|(_, held)| {
            shorter_than.map(|t| *held < t).unwrap_or(true)
                && longer_than.map(|t| *held > t).unwrap_or(true)
        })
        .map(|(at, held)| Match {
            at,
            what: format!("{} pulse of {} on channel {channel}",
                          if high { "high" } else { "low" },
                          measure::human_time(held)),
            transaction: None,
        })
        .collect()
}

/// Transaction-level conditions, evaluated through the query language so the
/// trigger and the filter box cannot disagree about what `addr:0x52` means.
fn transactions(decoded: &Decoded, condition: &Condition) -> Vec<Match> {
    let term = match condition {
        Condition::Field { name, value } => search::Term::Field {
            name: name.clone(),
            value: value.clone(),
        },
        Condition::Kind(k) => search::Term::Kind(k.clone()),
        Condition::Error(name) => search::Term::Error(name.clone()),
        _ => return Vec::new(),
    };
    let query = search::Query { terms: vec![term] };
    decoded.transactions.iter()
        .filter(|t| query.matches(t))
        .map(|t| Match {
            at: t.start,
            what: describe_hit(t, condition),
            transaction: Some(t.id),
        })
        .collect()
}

fn describe_hit(t: &Transaction, condition: &Condition) -> String {
    match condition {
        Condition::Error(_) => {
            let errors: Vec<&str> = t.errors.iter().map(|e| e.as_str()).collect();
            let what = if errors.is_empty() {
                "incomplete".to_string()
            } else {
                errors.join(", ")
            };
            format!("{} {} - {what}", t.kind, t.summary)
        }
        _ => format!("{} {}", t.kind, t.summary),
    }
}

// ---------------------------------------------------------------------------
// A compact way to write one down
// ---------------------------------------------------------------------------

/// Parse a trigger expression.
///
/// The same shape as a search query, because it is the same vocabulary and
/// people should not have to learn two:
///
/// ```text
/// edge:rising:0            a rising edge on channel 0
/// edge:0                   either direction
/// low:1:for=2us            channel 1 low for at least 2 us
/// glitch:0:shorter=100ns   a high pulse under 100 ns
/// start                    any transaction's framing start
/// start:i2c                any I2C transaction's
/// addr:0x52                a decoded field, as in a search
/// type:IBI
/// error:nack
/// error:any
/// A then B within=5ms      a sequence, where A and B are any of the above
/// ```
///
/// Commas mean "or", spaces mean "and", which matches the search language's
/// implicit conjunction.
pub fn parse(input: &str) -> Result<Condition, String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("a trigger needs something to look for".into());
    }

    // A sequence is the outermost thing, so it is split first.
    if let Some((before, after)) = split_once_word(input, "then") {
        let (then_part, within) = take_within(&after)?;
        return Ok(Condition::Sequence {
            first: Box::new(parse(&before)?),
            then: Box::new(parse(&then_part)?),
            within,
        });
    }

    let mut all: Vec<Condition> = Vec::new();
    for word in input.split_whitespace() {
        let mut any: Vec<Condition> = Vec::new();
        for alternative in word.split(',') {
            any.push(one(alternative)?);
        }
        all.push(if any.len() == 1 { any.remove(0) } else { Condition::Any(any) });
    }
    Ok(if all.len() == 1 { all.remove(0) } else { Condition::All(all) })
}

/// Pull the window off the end of a sequence's second half.
///
/// Written either way round - `within=5ms` or `within 5ms` - because both are
/// what people type, and a parser that accepts one of them is a parser people
/// get wrong.
fn take_within(input: &str) -> Result<(String, Picos), String> {
    let tokens: Vec<&str> = input.split_whitespace().collect();
    let mut kept: Vec<&str> = Vec::new();
    let mut within: Option<Picos> = None;
    let mut i = 0;
    while i < tokens.len() {
        let token = tokens[i];
        if let Some(value) = token.strip_prefix("within=") {
            within = Some(duration(value)?);
        } else if token.eq_ignore_ascii_case("within") {
            let value = tokens.get(i + 1)
                .ok_or("within what? try within=5ms")?;
            within = Some(duration(value)?);
            i += 1;
        } else {
            kept.push(token);
        }
        i += 1;
    }
    if kept.is_empty() {
        return Err("a sequence needs something after `then`".into());
    }
    // A default rather than a refusal: a sequence with no window is nearly
    // always meant as "soon after", and a millisecond is soon on every bus
    // here.
    Ok((kept.join(" "), within.unwrap_or(1_000_000_000)))
}

/// Split on a bare word, so `within` inside a field value is not mistaken for
/// the keyword.
fn split_once_word(input: &str, word: &str) -> Option<(String, String)> {
    let mut before: Vec<&str> = Vec::new();
    let mut after: Vec<&str> = Vec::new();
    let mut seen = false;
    for token in input.split_whitespace() {
        if !seen && token == word {
            seen = true;
            continue;
        }
        if seen { after.push(token) } else { before.push(token) }
    }
    if !seen || before.is_empty() || after.is_empty() {
        return None;
    }
    Some((before.join(" "), after.join(" ")))
}

fn one(word: &str) -> Result<Condition, String> {
    let lower = word.to_ascii_lowercase();
    let parts: Vec<&str> = word.split(':').collect();

    match parts[0].to_ascii_lowercase().as_str() {
        "edge" | "rising" | "falling" => {
            let (direction, rest) = match parts[0].to_ascii_lowercase().as_str() {
                "rising" => (Direction::Rising, &parts[1..]),
                "falling" => (Direction::Falling, &parts[1..]),
                _ => match parts.get(1).map(|p| p.to_ascii_lowercase()) {
                    Some(ref d) if d == "rising" => (Direction::Rising, &parts[2..]),
                    Some(ref d) if d == "falling" => (Direction::Falling, &parts[2..]),
                    _ => (Direction::Either, &parts[1..]),
                },
            };
            let channel = rest.first()
                .and_then(|c| c.parse().ok())
                .ok_or_else(|| format!("{word}: which channel?"))?;
            Ok(Condition::Edge { channel, direction })
        }
        "high" | "low" => {
            let high = parts[0].eq_ignore_ascii_case("high");
            let channel = parts.get(1).and_then(|c| c.parse().ok())
                .ok_or_else(|| format!("{word}: which channel?"))?;
            let mut for_at_least = None;
            for extra in &parts[2..] {
                if let Some(value) = extra.strip_prefix("for=") {
                    for_at_least = Some(duration(value)?);
                } else {
                    return Err(format!("{word}: what is {extra:?}?"));
                }
            }
            Ok(Condition::Level { channel, high, for_at_least })
        }
        "glitch" | "pulse" => {
            let high = !lower.contains("low=");
            let channel = parts.get(1).and_then(|c| c.parse().ok())
                .ok_or_else(|| format!("{word}: which channel?"))?;
            let mut shorter_than = None;
            let mut longer_than = None;
            for extra in &parts[2..] {
                if let Some(value) = extra.strip_prefix("shorter=") {
                    shorter_than = Some(duration(value)?);
                } else if let Some(value) = extra.strip_prefix("longer=") {
                    longer_than = Some(duration(value)?);
                } else {
                    return Err(format!("{word}: what is {extra:?}?"));
                }
            }
            if shorter_than.is_none() && longer_than.is_none() {
                return Err(format!("{word}: shorter= or longer= than what?"));
            }
            Ok(Condition::Pulse { channel, high, shorter_than, longer_than })
        }
        "start" => {
            let protocol = match parts.get(1) {
                None => None,
                Some(name) => Some(schema::Protocol::parse(name)
                    .ok_or_else(|| format!("{word}: unknown protocol"))?),
            };
            Ok(Condition::TransactionStart { protocol })
        }
        "error" | "err" => {
            let name = parts.get(1).map(|s| s.to_ascii_lowercase());
            Ok(match name.as_deref() {
                None | Some("any") => Condition::Error(None),
                Some(other) => Condition::Error(Some(other.to_string())),
            })
        }
        "type" | "kind" => parts.get(1)
            .map(|k| Condition::Kind(k.to_ascii_uppercase()))
            .ok_or_else(|| format!("{word}: which kind?")),
        // Anything else is a field, exactly as the search language reads it,
        // so `addr:0x52` and `can.id:0x123` need no separate grammar here.
        _ => {
            let query = search::parse(word).map_err(|e| e.to_string())?;
            match query.terms.into_iter().next() {
                Some(search::Term::Field { name, value }) =>
                    Ok(Condition::Field { name, value }),
                Some(search::Term::Kind(k)) => Ok(Condition::Kind(k)),
                Some(search::Term::Error(e)) => Ok(Condition::Error(e)),
                _ => Err(format!(
                    "{word}: not something to trigger on. Try edge:rising:0, \
                     low:1:for=2us, glitch:0:shorter=100ns, start, addr:0x52, \
                     type:WRITE or error:nack.")),
            }
        }
    }
}

/// A duration with a unit: `2us`, `100ns`, `5ms`, `1s`, or bare picoseconds.
pub fn duration(text: &str) -> Result<Picos, String> {
    let text = text.trim();
    let (number, scale) = if let Some(n) = text.strip_suffix("ps") {
        (n, 1u64)
    } else if let Some(n) = text.strip_suffix("ns") {
        (n, 1_000)
    } else if let Some(n) = text.strip_suffix("us") {
        (n, 1_000_000)
    } else if let Some(n) = text.strip_suffix("ms") {
        (n, 1_000_000_000)
    } else if let Some(n) = text.strip_suffix('s') {
        (n, 1_000_000_000_000)
    } else {
        (text, 1)
    };
    let value: f64 = number.trim().parse()
        .map_err(|_| format!("{text:?} is not a time. Try 100ns, 2us, 5ms."))?;
    if value < 0.0 {
        return Err(format!("{text:?} is negative"));
    }
    Ok((value * scale as f64) as Picos)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn i2c() -> (file::Capture, Decoded) {
        let cap = simulator::build("demo", 1_000_000).unwrap();
        let protocol = registry::guess(&cap);
        let decoded = registry::decoder(protocol, &cap).decode(&cap);
        (cap, decoded)
    }

    #[test]
    fn the_classes_say_where_they_could_run() {
        let edge = parse("edge:rising:0").unwrap();
        assert_eq!(edge.class(), Class::EdgeLevel);
        assert!(edge.hardware_class());
        assert!(!edge.needs_decode());

        let field = parse("addr:0x52").unwrap();
        assert_eq!(field.class(), Class::ProtocolField);
        assert!(!field.hardware_class(),
                "section 10 says protocol-field support depends on the engine, \
                 and this one has none");
        assert!(field.needs_decode());

        let error = parse("error:nack").unwrap();
        assert_eq!(error.class(), Class::Error);
        assert!(!error.hardware_class());

        let sequence = parse("edge:rising:0 then error:nack within=1ms").unwrap();
        assert_eq!(sequence.class(), Class::Sequence);
        assert!(!sequence.hardware_class());
        assert!(sequence.needs_decode(), "its second half does");
    }

    /// A composite is only as hardware-able as its least able part, or a
    /// builder would promise hardware for a trigger that cannot have it.
    #[test]
    fn a_composite_is_as_hardware_able_as_its_weakest_part() {
        let both = parse("edge:rising:0 low:1").unwrap();
        assert!(both.hardware_class());

        let mixed = parse("edge:rising:0 addr:0x52").unwrap();
        assert_eq!(mixed.class(), Class::Composite);
        assert!(!mixed.hardware_class());
    }

    /// And the honest part: this board has no trigger to arm.
    #[test]
    fn the_hardware_says_plainly_that_it_has_no_trigger() {
        assert!(!hardware_available());
        assert!(NO_HARDWARE_TRIGGER.contains("ring"));
    }

    #[test]
    fn an_edge_trigger_finds_edges_and_not_the_initial_state() {
        let (cap, decoded) = i2c();
        let rising = find(&cap, &decoded,
                          &parse("edge:rising:0").unwrap());
        let falling = find(&cap, &decoded,
                           &parse("edge:falling:0").unwrap());
        let either = find(&cap, &decoded, &parse("edge:0").unwrap());

        assert!(!rising.is_empty());
        assert_eq!(either.len(), rising.len() + falling.len());

        // The first entry of a chunk is the initial state, not a transition.
        let first_time = cap.chunks[0].times[0];
        assert!(either.iter().all(|m| m.at > first_time),
                "an edge was reported at the moment capture was armed");

        // And the count is the number of transitions of that channel, not the
        // number of capture entries.
        assert!(either.len() < cap.chunks[0].len());
    }

    #[test]
    fn a_level_trigger_can_want_a_minimum_duration() {
        let (cap, decoded) = i2c();
        let all = find(&cap, &decoded, &parse("high:0").unwrap());
        let long = find(&cap, &decoded, &parse("high:0:for=2us").unwrap());
        assert!(!all.is_empty());
        assert!(long.len() < all.len(),
                "a 2 us minimum should exclude the clock's own high phases");
        // The idle stretches between transactions are the long ones.
        assert!(!long.is_empty());
    }

    /// The glitch case, which is what a pulse-width trigger is for.
    #[test]
    fn a_pulse_trigger_finds_the_narrow_ones() {
        let (cap, decoded) = i2c();
        // The demo's clock runs at 750 ns a cycle, so nothing is under 100 ns.
        assert!(find(&cap, &decoded,
                     &parse("glitch:0:shorter=100ns").unwrap()).is_empty());
        // And everything is under 100 us.
        assert!(!find(&cap, &decoded,
                      &parse("glitch:0:shorter=100us").unwrap()).is_empty());
    }

    #[test]
    fn a_field_trigger_finds_the_transaction_and_says_which() {
        let (cap, decoded) = i2c();
        let found = find(&cap, &decoded, &parse("addr:0x77").unwrap());
        assert_eq!(found.len(), 1, "one transfer to 0x77 in the demo traffic");
        let hit = &found[0];
        assert!(hit.transaction.is_some());
        let t = decoded.transactions.iter()
            .find(|t| Some(t.id) == hit.transaction).unwrap();
        assert_eq!(hit.at, t.start);
    }

    /// The trigger and the filter box have to agree about what a field means,
    /// so the trigger runs the query language rather than its own comparison.
    #[test]
    fn a_field_trigger_agrees_with_the_same_search() {
        let (cap, decoded) = i2c();
        let triggered = find(&cap, &decoded, &parse("addr:0x52").unwrap());
        let searched = search::parse("addr:0x52").unwrap().run(&decoded);
        assert_eq!(triggered.len(), searched.len());
        for (hit, t) in triggered.iter().zip(searched) {
            assert_eq!(hit.transaction, Some(t.id));
        }
    }

    /// A sequence match is reported at the second event: that is the moment
    /// the sequence completed, and the moment somebody wants to look at.
    #[test]
    fn a_sequence_matches_at_the_second_event() {
        let (cap, decoded) = i2c();
        let condition = parse("addr:0x3C then error:nack within=100us").unwrap();
        let found = find(&cap, &decoded, &condition);
        assert_eq!(found.len(), 1, "0x3C is followed by the NACK at 0x77");

        let nack = decoded.with_errors().next().unwrap();
        assert_eq!(found[0].at, nack.start);
        assert!(found[0].what.contains("then"));
    }

    #[test]
    fn a_sequence_window_that_is_too_short_matches_nothing() {
        let (cap, decoded) = i2c();
        let found = find(&cap, &decoded,
                         &parse("addr:0x3C then error:nack within=1ns").unwrap());
        assert!(found.is_empty());
    }

    #[test]
    fn an_and_needs_both_on_the_same_transaction() {
        let (cap, decoded) = i2c();
        // The NACK is at 0x77, so this matches.
        let both = find(&cap, &decoded, &parse("addr:0x77 error:nack").unwrap());
        assert_eq!(both.len(), 1);
        // And this cannot: 0x52 never NACKed.
        let neither = find(&cap, &decoded,
                           &parse("addr:0x52 error:nack").unwrap());
        assert!(neither.is_empty());
    }

    #[test]
    fn an_or_matches_either() {
        let (cap, decoded) = i2c();
        let either = find(&cap, &decoded, &parse("addr:0x77,addr:0x3C").unwrap());
        assert_eq!(either.len(), 2);
        assert!(either[0].at < either[1].at, "matches come in time order");
    }

    #[test]
    fn matches_come_in_time_order_however_they_were_found() {
        let (cap, decoded) = i2c();
        let found = find(&cap, &decoded,
                         &parse("error:any,start:i2c").unwrap());
        assert!(found.windows(2).all(|w| w[0].at <= w[1].at));
    }

    /// The pre-trigger window: a hardware trigger needs a ring buffer for the
    /// samples before the event, and a burst capture already has them.
    #[test]
    fn the_window_around_a_match_is_a_clip_with_the_level_kept() {
        let (cap, decoded) = i2c();
        let hit = first(&cap, &decoded, &parse("error:nack").unwrap()).unwrap();
        let (from, to) = window(&cap, hit.at, 20_000_000, 20_000_000);
        assert!(from < hit.at && to > hit.at);

        let clipped = cap.clip(from, to);
        assert_eq!(clipped.chunks[0].times[0], from,
                   "the clip has to start with the level in force");
        // And it decodes on its own, which is the point of taking it.
        let protocol = registry::guess(&clipped);
        let again = registry::decoder(protocol, &clipped).decode(&clipped);
        assert!(!again.transactions.is_empty());
    }

    #[test]
    fn the_window_is_clamped_to_the_capture() {
        let (cap, decoded) = i2c();
        let hit = first(&cap, &decoded, &parse("start").unwrap()).unwrap();
        let (from, to) = window(&cap, hit.at, u64::MAX / 4, u64::MAX / 4);
        let (first_time, last) = cap.span();
        assert_eq!((from, to), (first_time, last));
    }

    #[test]
    fn durations_take_a_unit() {
        assert_eq!(duration("100ns").unwrap(), 100_000);
        assert_eq!(duration("2us").unwrap(), 2_000_000);
        assert_eq!(duration("1.5ms").unwrap(), 1_500_000_000);
        assert_eq!(duration("1s").unwrap(), 1_000_000_000_000);
        assert_eq!(duration("500").unwrap(), 500, "bare is picoseconds");
        assert!(duration("soon").is_err());
        assert!(duration("-1us").is_err());
    }

    #[test]
    fn a_trigger_nobody_could_mean_is_refused_with_help() {
        let err = parse("wibble").unwrap_err();
        assert!(err.contains("edge:rising:0"), "unhelpful: {err}");
        assert!(parse("").is_err());
        assert!(parse("edge:rising").is_err(), "which channel?");
        assert!(parse("glitch:0").is_err(), "shorter or longer than what?");
    }

    #[test]
    fn every_condition_can_describe_itself() {
        for text in ["edge:rising:0", "low:1:for=2us", "glitch:0:shorter=100ns",
                     "start", "start:i2c", "addr:0x52", "type:WRITE",
                     "error:nack", "error:any", "addr:0x52,addr:0x3C",
                     "edge:rising:0 addr:0x52",
                     "addr:0x3C then error:nack within=1ms"] {
            let condition = parse(text).unwrap_or_else(
                |e| panic!("{text}: {e}"));
            let described = condition.describe();
            assert!(!described.is_empty(), "{text} describes as nothing");
            assert!(!described.contains("  "), "{text} -> {described:?}");
        }
    }
}
