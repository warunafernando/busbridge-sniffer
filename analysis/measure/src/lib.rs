//! Measurements over an interval, and two ways of explaining a transaction.
//!
//! Section 7 of the specification: timing cursors that show delta time,
//! frequency and edge counts; a range measurement giving duration, duty cycle,
//! effective clock, transaction rate, payload throughput, bus utilisation and
//! error counts; a field-by-field comparison of two transactions; and a
//! deterministic explanation of a selection.
//!
//! # Cursors and ranges are the same measurement
//!
//! A pair of cursors is an interval, and a dragged region is an interval, so
//! both are [`measure`] over `[start, end]`. Two implementations would drift,
//! and the first symptom would be a cursor readout that disagrees with the
//! range panel about the same two edges.
//!
//! # What the numbers mean, exactly
//!
//! Every one of these has an obvious-looking wrong definition, so each is
//! stated here and pinned by a test:
//!
//! - **Edges** are transitions *of that channel*. A capture entry is a moment
//!   when some channel moved; counting entries would count SCL's edges as
//!   SDA's, which is the same mistake the timeline made once and the reason
//!   this is spelled out.
//! - **High time** is the time the channel was high *inside the interval*,
//!   integrated from the holds - so a level that was already high when the
//!   interval opened counts from the interval's start, not from its last edge.
//! - **Duty cycle** is high time over the interval's duration, so it is only
//!   meaningful for something that toggles; it is reported for every channel
//!   and interpreted by whoever asked.
//! - **Effective clock** is from the *median* period between rising edges, not
//!   the mean. On a stretched I2C bus the mean is dragged by the stretch and
//!   reports a clock nobody ran at; the median says what most cycles did.
//! - **Bus utilisation** is the union of transaction spans clipped to the
//!   interval, over its duration. A union, because a transaction and its own
//!   parts overlap - summing durations would happily report 300% busy.
//! - **Payload throughput** counts data-field bytes of transactions that
//!   overlap the interval, so a transaction straddling the edge contributes
//!   all of its bytes. Clipping bytes to time would mean inventing a rate at
//!   which they arrived.

#![forbid(unsafe_code)]

use schema::{Decoded, Picos, Transaction};

/// Where the A and B cursors are.
///
/// Either may be unplaced; a measurement needs both.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Cursors {
    pub a: Option<Picos>,
    pub b: Option<Picos>,
}

impl Cursors {
    /// The interval between them, lowest first. None until both are placed.
    pub fn interval(&self) -> Option<(Picos, Picos)> {
        match (self.a, self.b) {
            (Some(a), Some(b)) if a <= b => Some((a, b)),
            // Dropped in whichever order, so B before A is an interval too.
            (Some(a), Some(b)) => Some((b, a)),
            _ => None,
        }
    }

    pub fn delta(&self) -> Option<Picos> {
        self.interval().map(|(a, b)| b - a)
    }

    /// Place the next cursor: A first, then B, then A again.
    ///
    /// One click that always means something, rather than a modifier to
    /// remember. Section 7 wants A and B placed; it does not say how.
    pub fn place(&mut self, at: Picos) {
        match (self.a, self.b) {
            (None, _) => self.a = Some(at),
            (Some(_), None) => self.b = Some(at),
            (Some(_), Some(_)) => {
                self.a = Some(at);
                self.b = None;
            }
        }
    }

    pub fn clear(&mut self) {
        self.a = None;
        self.b = None;
    }
}

/// What one channel did over the interval.
#[derive(Debug, Clone, PartialEq)]
pub struct ChannelStats {
    pub channel: u8,
    pub name: String,
    /// Transitions of this channel inside the interval.
    pub edges: usize,
    pub rising: usize,
    pub falling: usize,
    /// Time spent high, inside the interval.
    pub high: Picos,
    /// High time over duration, 0.0 to 1.0.
    pub duty: f64,
    /// The typical period between rising edges: the median, not the mean.
    pub period: Option<Picos>,
    /// From the median period. None with fewer than two rising edges - one
    /// edge is not a frequency, however tempting the division looks.
    pub frequency_hz: Option<f64>,
    /// The narrowest level held, either polarity. What a glitch shows up as.
    pub shortest: Option<Picos>,
}

/// Everything measured over an interval.
#[derive(Debug, Clone, PartialEq)]
pub struct Measurement {
    pub start: Picos,
    pub end: Picos,
    pub duration: Picos,
    pub channels: Vec<ChannelStats>,
    /// Transactions overlapping the interval.
    pub transactions: usize,
    pub errors: usize,
    pub incomplete: usize,
    pub payload_bytes: usize,
    /// Union of transaction spans, clipped to the interval.
    pub busy: Picos,
    pub utilisation: f64,
    pub transaction_rate_hz: f64,
    pub payload_bytes_per_second: f64,
    /// True when a hole in the capture touches the interval, which makes every
    /// count above a lower bound rather than a fact.
    pub gap_overlap: bool,
    /// True when the capture's times were constructed rather than measured.
    ///
    /// Everything on this struct derived from time is then a restatement of the
    /// bit period the reconstruction chose: `duration`, `transaction_rate_hz`,
    /// `payload_bytes_per_second`, `utilisation`, and every `ChannelStats`
    /// field except `edges`. They are computed rather than withheld, because a
    /// reconstruction is still the right place to count edges and compare
    /// payloads - but anything reporting them has to say this, the way it says
    /// `gap_overlap`.
    pub timing_synthetic: bool,
}

/// Measure an interval of a capture.
pub fn measure(
    capture: &file::Capture,
    decoded: &Decoded,
    start: Picos,
    end: Picos,
) -> Measurement {
    let (start, end) = if start <= end { (start, end) } else { (end, start) };
    let duration = end.saturating_sub(start);
    let seconds = duration as f64 / 1e12;

    let channels = (0..capture.session.channels.len())
        .map(|i| channel_stats(capture, i as u8, start, end))
        .collect();

    // Transactions that overlap the interval at all: a transaction half inside
    // it is still something that happened here.
    let touching: Vec<&Transaction> = decoded.transactions.iter()
        .filter(|t| t.start <= end && t.end >= start)
        .collect();

    let errors = touching.iter()
        .filter(|t| !t.errors.is_empty() || !t.complete).count();
    let incomplete = touching.iter().filter(|t| !t.complete).count();
    let payload_bytes: usize = touching.iter().map(|t| payload_len(t)).sum();

    // The union, not the sum: a transaction overlaps its own parts.
    let mut spans: Vec<(Picos, Picos)> = touching.iter()
        .map(|t| (t.start.max(start), t.end.min(end)))
        .filter(|(a, b)| b > a)
        .collect();
    spans.sort_unstable();
    let mut busy: Picos = 0;
    let mut open: Option<(Picos, Picos)> = None;
    for (a, b) in spans {
        match open {
            None => open = Some((a, b)),
            Some((oa, ob)) if a <= ob => open = Some((oa, ob.max(b))),
            Some((oa, ob)) => {
                busy += ob - oa;
                open = Some((a, b));
            }
        }
    }
    if let Some((oa, ob)) = open {
        busy += ob - oa;
    }

    Measurement {
        start,
        end,
        duration,
        channels,
        transactions: touching.len(),
        errors,
        incomplete,
        payload_bytes,
        busy,
        utilisation: if duration == 0 { 0.0 } else { busy as f64 / duration as f64 },
        transaction_rate_hz: if seconds > 0.0 {
            touching.len() as f64 / seconds
        } else {
            0.0
        },
        payload_bytes_per_second: if seconds > 0.0 {
            payload_bytes as f64 / seconds
        } else {
            0.0
        },
        gap_overlap: capture.gap_overlaps(start, end),
        timing_synthetic: capture.session.timing.is_synthetic(),
    }
}

/// Payload bytes of a transaction: its data fields, in order.
fn payload_len(t: &Transaction) -> usize {
    t.fields.iter()
        .filter(|f| f.kind == schema::FieldKind::Data)
        .count()
}

fn channel_stats(
    capture: &file::Capture,
    channel: u8,
    start: Picos,
    end: Picos,
) -> ChannelStats {
    let name = capture.session.channels.get(channel as usize)
        .cloned().unwrap_or_else(|| format!("ch{channel}"));
    let duration = end.saturating_sub(start);

    let mut edges = 0usize;
    let mut rising = 0usize;
    let mut falling = 0usize;
    let mut high: Picos = 0;
    let mut shortest: Option<Picos> = None;
    let mut rising_times: Vec<Picos> = Vec::new();

    for chunk in &capture.chunks {
        if chunk.times.is_empty() {
            continue;
        }
        // The entry at or before the interval's start holds the level the
        // interval opens at.
        let first = match chunk.times.binary_search(&start) {
            Ok(i) => i,
            Err(0) => 0,
            Err(i) => i - 1,
        };

        let mut previous: Option<bool> = None;
        let mut i = first;
        while i < chunk.len() {
            let at = chunk.times[i];
            if at > end {
                break;
            }
            let level = chunk.channel(i, channel);
            let next = chunk.times.get(i + 1).copied()
                .unwrap_or_else(|| chunk.end.max(end));

            // A transition of *this* channel, inside the interval.
            if let Some(was) = previous {
                if was != level && at >= start && at <= end {
                    edges += 1;
                    if level {
                        rising += 1;
                        rising_times.push(at);
                    } else {
                        falling += 1;
                    }
                }
            } else if at >= start && level {
                // The level was already high when the interval opened; not an
                // edge, but the high time counts from the interval's start.
            }

            // The hold, clipped to the interval.
            let from = at.max(start);
            let to = next.min(end);
            if to > from {
                if level {
                    high += to - from;
                }
                // Only holds that are wholly inside count as pulse widths -
                // one clipped by the interval's edge is not a measurement of
                // anything.
                if at >= start && next <= end {
                    let width = next - at;
                    shortest = Some(match shortest {
                        Some(s) => s.min(width),
                        None => width,
                    });
                }
            }

            previous = Some(level);
            i += 1;
        }
    }

    // The median gap between rising edges: what most cycles did, rather than
    // what the mean says after one stretched cycle.
    let mut periods: Vec<Picos> = rising_times.windows(2)
        .map(|w| w[1] - w[0]).collect();
    periods.sort_unstable();
    let period = if periods.is_empty() {
        None
    } else {
        Some(periods[periods.len() / 2])
    };

    ChannelStats {
        channel,
        name,
        edges,
        rising,
        falling,
        high,
        duty: if duration == 0 { 0.0 } else { high as f64 / duration as f64 },
        period,
        frequency_hz: period.filter(|p| *p > 0).map(|p| 1e12 / p as f64),
        shortest,
    }
}

// ---------------------------------------------------------------------------
// Comparing two transactions
// ---------------------------------------------------------------------------

/// One field, as it stands in each transaction.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDiff {
    pub name: String,
    /// None when this transaction has no such field.
    pub a: Option<String>,
    pub b: Option<String>,
}

impl FieldDiff {
    pub fn differs(&self) -> bool {
        self.a != self.b
    }
}

/// A field-by-field comparison.
#[derive(Debug, Clone, PartialEq)]
pub struct Comparison {
    /// Same protocol and same kind: the case where a field-by-field diff means
    /// what it looks like it means.
    pub comparable: bool,
    pub why_not: Option<String>,
    /// Every field of either, in the order the first one carries them.
    pub fields: Vec<FieldDiff>,
    /// Differences in what is not a field.
    pub kind: Option<(String, String)>,
    pub severity: Option<(String, String)>,
    pub errors: Option<(Vec<String>, Vec<String>)>,
    pub duration: (Picos, Picos),
}

impl Comparison {
    pub fn differing_fields(&self) -> impl Iterator<Item = &FieldDiff> {
        self.fields.iter().filter(|f| f.differs())
    }

    /// True when nothing but the timing differs.
    pub fn identical_content(&self) -> bool {
        self.kind.is_none()
            && self.severity.is_none()
            && self.errors.is_none()
            && self.differing_fields().count() == 0
    }
}

/// Compare two transactions, field by field.
///
/// Section 7 says "compatible" transactions; incompatible ones are compared
/// anyway and the reason they do not line up is reported. Refusing would be
/// less useful - a READ where a WRITE was expected is exactly the sort of
/// thing someone is comparing to find out.
pub fn compare(a: &Transaction, b: &Transaction) -> Comparison {
    let comparable = a.protocol == b.protocol && a.kind == b.kind;
    let why_not = if a.protocol != b.protocol {
        Some(format!("different protocols: {} and {}",
                     a.protocol.as_str(), b.protocol.as_str()))
    } else if a.kind != b.kind {
        Some(format!("different kinds: {} and {}", a.kind, b.kind))
    } else {
        None
    };

    // Every field name of either, in A's order then B's extras, so the diff
    // reads down the transaction rather than in whatever order a set gives.
    let mut names: Vec<String> = Vec::new();
    for f in a.fields.iter().chain(b.fields.iter()) {
        if !names.iter().any(|n| n == &f.name) {
            names.push(f.name.clone());
        }
    }

    let look = |t: &Transaction, name: &str| -> Option<String> {
        t.fields.iter().find(|f| f.name == name).map(|f| f.display.clone())
    };
    let fields = names.into_iter()
        .map(|name| FieldDiff {
            a: look(a, &name),
            b: look(b, &name),
            name,
        })
        .collect();

    let errors_a: Vec<String> = a.errors.iter().map(|e| e.as_str().to_string())
        .collect();
    let errors_b: Vec<String> = b.errors.iter().map(|e| e.as_str().to_string())
        .collect();

    Comparison {
        comparable,
        why_not,
        fields,
        kind: (a.kind != b.kind).then(|| (a.kind.clone(), b.kind.clone())),
        severity: (a.severity != b.severity).then(|| (
            a.severity.as_str().to_string(), b.severity.as_str().to_string())),
        errors: (errors_a != errors_b).then_some((errors_a, errors_b)),
        duration: (a.end.saturating_sub(a.start), b.end.saturating_sub(b.start)),
    }
}

// ---------------------------------------------------------------------------
// Explaining a transaction
// ---------------------------------------------------------------------------

/// One line of an explanation, and what sort of line it is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// "what", "field", "problem", "timing", "evidence".
    pub kind: &'static str,
    pub text: String,
}

/// Explain a transaction from its own fields.
///
/// Deterministic and derived: every line comes from the decode, nothing is
/// inferred, and the same transaction always explains the same way. Section 7
/// allows an AI explanation "on top" - this is the part underneath, which is
/// the part that can be trusted and tested.
pub fn explain(t: &Transaction) -> Vec<Line> {
    let mut out = Vec::new();
    let line = |kind: &'static str, text: String| Line { kind, text };

    out.push(line("what", format!(
        "{} on {} bus {}, {} long",
        t.kind, t.protocol.as_str(), t.bus.0,
        crate::human_time(t.end.saturating_sub(t.start)))));
    out.push(line("what", t.summary.clone()));

    for f in &t.fields {
        // Data bytes are already in the summary; repeating each one as its own
        // line buries the fields that carry meaning.
        if f.kind == schema::FieldKind::Data {
            continue;
        }
        out.push(line("field", format!("{} is {}", f.name, f.display)));
    }
    let bytes = payload_len(t);
    if bytes > 0 {
        out.push(line("field", format!("{bytes} payload byte(s)")));
    }

    if !t.complete {
        out.push(line("problem",
            "incomplete: it ran into a gap or the end of the capture, so what \
             is decoded is only what was seen".into()));
    }
    for e in &t.errors {
        out.push(line("problem", format!("error: {}", e.as_str())));
    }
    if t.errors.is_empty() && t.complete {
        out.push(line("problem", "nothing wrong was found with it".into()));
    }

    out.push(line("timing", format!("from {} to {}",
        crate::human_time(t.start), crate::human_time(t.end))));
    out.push(line("evidence", format!(
        "decoded from chunk {}, sample edges {} to {}",
        t.samples.chunk, t.samples.first, t.samples.last)));

    out
}

/// A time in the unit that reads best at that magnitude.
///
/// Here rather than in the UI because the CLI, the API and the explanation all
/// have to agree about what "12.5 us" means.
pub fn human_time(t: Picos) -> String {
    if t == 0 {
        "0".into()
    } else if t < 1_000 {
        format!("{t} ps")
    } else if t < 1_000_000 {
        format!("{:.3} ns", t as f64 / 1e3)
    } else if t < 1_000_000_000 {
        format!("{:.3} us", t as f64 / 1e6)
    } else if t < 1_000_000_000_000 {
        format!("{:.4} ms", t as f64 / 1e9)
    } else {
        format!("{:.4} s", t as f64 / 1e12)
    }
}

/// A rate, in the unit that reads best.
pub fn human_rate(hz: f64) -> String {
    if hz <= 0.0 {
        "0".into()
    } else if hz < 1_000.0 {
        format!("{hz:.1} Hz")
    } else if hz < 1_000_000.0 {
        format!("{:.2} kHz", hz / 1e3)
    } else {
        format!("{:.3} MHz", hz / 1e6)
    }
}

/// A byte rate, in the unit that reads best.
pub fn human_bytes_per_second(bps: f64) -> String {
    if bps <= 0.0 {
        "0".into()
    } else if bps < 1_000.0 {
        format!("{bps:.0} B/s")
    } else if bps < 1_000_000.0 {
        format!("{:.1} kB/s", bps / 1e3)
    } else {
        format!("{:.2} MB/s", bps / 1e6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-microsecond square wave on channel 0 while channel 1 holds high,
    /// so every definition above has an answer known in advance.
    fn square_wave(cycles: u64) -> file::Capture {
        let period = 1_000_000u64;            // 1 us, so 1 MHz
        let mut times = vec![0u64];
        let mut lines = vec![0b10u8];         // ch0 low, ch1 high
        for n in 0..cycles {
            times.push(n * period + period / 2);
            lines.push(0b11);                  // ch0 rises halfway through
            times.push((n + 1) * period);
            lines.push(0b10);                  // and falls at the end
        }
        let chunk = file::SampleChunk {
            id: 0,
            start: 0,
            end: cycles * period,
            times,
            lines,
        };
        let index = file::rebuild_index(std::slice::from_ref(&chunk), &[],
                                        &Decoded::default());
        file::Capture {
            session: file::Session {
                format_version: 1,
                schema_version: 1,
                source: "test".into(),
                device_id: String::new(),
                firmware_version: String::new(),
                host_software: "test".into(),
                started_utc: String::new(),
                channels: vec!["CLK".into(), "STILL".into()],
                tick_hz: 1_000_000_000_000,
                timing: file::Timing::Measured,
            },
            chunks: vec![chunk],
            gaps: vec![],
            decoders: vec![],
            decoded: Decoded::default(),
            annotations: vec![],
            index,
            truncated_at: None,
        }
    }

    #[test]
    fn cursors_make_an_interval_whichever_order_they_are_placed_in() {
        let mut c = Cursors::default();
        assert_eq!(c.interval(), None);
        c.place(2_000);
        assert_eq!(c.interval(), None, "one cursor is not an interval");
        c.place(1_000);
        assert_eq!(c.interval(), Some((1_000, 2_000)));
        assert_eq!(c.delta(), Some(1_000));

        // A third click starts again, so the pair never goes stale.
        c.place(5_000);
        assert_eq!(c.a, Some(5_000));
        assert_eq!(c.b, None);
    }

    #[test]
    fn a_square_wave_measures_as_one() {
        let cap = square_wave(10);
        let m = measure(&cap, &Decoded::default(), 0, 10_000_000);

        let clk = &m.channels[0];
        assert_eq!(clk.name, "CLK");
        assert_eq!(clk.rising, 10, "ten cycles, ten rising edges");
        assert_eq!(clk.falling, 10);
        assert_eq!(clk.edges, 20);
        assert_eq!(clk.period, Some(1_000_000), "one microsecond");
        let hz = clk.frequency_hz.unwrap();
        assert!((hz - 1e6).abs() < 1.0, "1 MHz, got {hz}");
        assert!((clk.duty - 0.5).abs() < 0.01, "square, got {}", clk.duty);
    }

    /// The mistake the timeline made: counting capture entries as this
    /// channel's edges. Channel 1 never moves, and every entry belongs to
    /// channel 0.
    #[test]
    fn a_channel_that_never_moves_has_no_edges_and_full_duty() {
        let cap = square_wave(10);
        let m = measure(&cap, &Decoded::default(), 0, 10_000_000);
        let still = &m.channels[1];
        assert_eq!(still.edges, 0, "channel 1 never moved");
        assert_eq!(still.rising, 0);
        assert_eq!(still.frequency_hz, None, "no edges is not a frequency");
        assert!((still.duty - 1.0).abs() < 0.001,
                "it was high throughout, got {}", still.duty);
    }

    /// A level already high when the interval opens counts from the interval's
    /// start - not from its last edge, which was before the window.
    #[test]
    fn high_time_starts_at_the_interval_not_at_the_last_edge() {
        let cap = square_wave(10);
        // Opens mid-high: channel 0 rose at 500 ns and falls at 1 us.
        let m = measure(&cap, &Decoded::default(), 750_000, 1_000_000);
        let clk = &m.channels[0];
        assert_eq!(clk.high, 250_000,
                   "a quarter microsecond of high inside a quarter-microsecond \
                    window");
        assert!((clk.duty - 1.0).abs() < 0.001);
    }

    /// The median, not the mean: one stretched cycle must not move the
    /// reported clock.
    #[test]
    fn a_stretched_cycle_does_not_move_the_effective_clock() {
        let mut cap = square_wave(10);
        // Push everything after the fifth rising edge out by 100 us, as a
        // target holding the clock would.
        let stretch = 100_000_000u64;
        let chunk = &mut cap.chunks[0];
        for (i, t) in chunk.times.iter_mut().enumerate() {
            if i > 10 {
                *t += stretch;
            }
        }
        chunk.end += stretch;
        cap.index = file::rebuild_index(&cap.chunks, &[], &Decoded::default());

        let m = measure(&cap, &Decoded::default(), 0, 200_000_000);
        let clk = &m.channels[0];
        assert_eq!(clk.rising, 10, "the same ten cycles");
        assert_eq!(clk.period, Some(1_000_000),
                   "the median cycle is still a microsecond");
        let hz = clk.frequency_hz.unwrap();
        assert!((hz - 1e6).abs() < 1.0,
                "the stretch dragged the reported clock to {hz}");

        // And the mean would have been wrong, which is why the median is used.
        let mean = clk.rising as f64 / (m.duration as f64 / 1e12);
        assert!(mean < 1e5, "the mean rate over the window is {mean}, which is \
                             the number this deliberately does not report");
    }

    fn i2c_decode() -> (file::Capture, Decoded) {
        let cap = simulator::build("demo", 1_000_000).unwrap();
        let protocol = registry::guess(&cap);
        let decoded = registry::decoder(protocol, &cap).decode(&cap);
        (cap, decoded)
    }

    #[test]
    fn transaction_counts_and_rates_come_from_what_overlaps_the_interval() {
        let (cap, decoded) = i2c_decode();
        let (first, last) = cap.span();
        let whole = measure(&cap, &decoded, first, last);
        assert_eq!(whole.transactions, decoded.transactions.len());
        assert_eq!(whole.errors, 1, "the demo traffic has one NACK");
        assert!(whole.transaction_rate_hz > 0.0);
        assert!(whole.payload_bytes > 0);

        // A window over the first transaction alone sees only it.
        let t = &decoded.transactions[0];
        let one = measure(&cap, &decoded, t.start, t.end);
        assert_eq!(one.transactions, 1);
        assert_eq!(one.payload_bytes, 3, "0x52 W 10 DE AD");
    }

    /// Utilisation is a union. A transaction overlaps its own parts, so
    /// summing durations can exceed the interval - and a bus reported as 300%
    /// busy is worse than no number at all.
    #[test]
    fn utilisation_never_exceeds_one_even_with_nested_transactions() {
        let (cap, mut decoded) = i2c_decode();
        // A parent covering everything, as a device analyser would add.
        let (first, last) = cap.span();
        let mut parent = decoded.transactions[0].clone();
        parent.id = 9_999;
        parent.start = first;
        parent.end = last;
        parent.kind = "SESSION".into();
        let children: Vec<u64> = decoded.transactions.iter().map(|t| t.id).collect();
        for id in children {
            if let Some(t) = decoded.transactions.iter_mut().find(|t| t.id == id) {
                t.parent = Some(9_999);
            }
        }
        decoded.transactions.push(parent);

        let m = measure(&cap, &decoded, first, last);
        assert!(m.utilisation <= 1.0 + 1e-9,
                "utilisation came out at {}", m.utilisation);
        assert!(m.busy <= m.duration);
    }

    #[test]
    fn a_gap_touching_the_interval_is_reported() {
        let cap = simulator::build_with_gap("demo", 1_000_000).unwrap();
        let decoded = registry::decoder(registry::guess(&cap), &cap).decode(&cap);
        let (first, last) = cap.span();
        assert!(measure(&cap, &decoded, first, last).gap_overlap,
                "a measurement over a hole has to say so");
    }

    /// A measurement over a reconstruction says so.
    ///
    /// This is where invented timing does its damage: `effective_clock_hz` and
    /// `duty` on a synthetic capture are restatements of the bit period the
    /// reconstruction chose, and they arrive looking exactly like measurements
    /// of a bus. The numbers are still computed - counting edges and comparing
    /// payloads over a reconstruction is reasonable - so the flag is what
    /// stands between them and being read as fact.
    #[test]
    fn a_measurement_over_synthetic_timing_is_flagged_as_such() {
        let (cap, decoded) = i2c_decode();
        assert!(!measure(&cap, &decoded, 0, 100_000).timing_synthetic,
                "a recorded capture was flagged as reconstructed");

        let mut synthetic = cap.clone();
        synthetic.session.timing = file::Timing::Synthetic(file::Synthetic {
            why: "too fast to oversample".into(),
            from: "pin-clocked decode".into(),
            bit_ps: 80_000,
        });
        let m = measure(&synthetic, &decoded, 0, 100_000);
        assert!(m.timing_synthetic,
                "a reconstruction was measured without saying so");
        // Flagged, not withheld - the counts are still worth having.
        assert_eq!(m.transactions, measure(&cap, &decoded, 0, 100_000).transactions);
    }

    #[test]
    fn an_empty_interval_measures_zero_rather_than_dividing_by_it() {
        let (cap, decoded) = i2c_decode();
        let m = measure(&cap, &decoded, 1_000, 1_000);
        assert_eq!(m.duration, 0);
        assert_eq!(m.utilisation, 0.0);
        assert_eq!(m.transaction_rate_hz, 0.0);
        assert_eq!(m.payload_bytes_per_second, 0.0);
        for c in &m.channels {
            assert_eq!(c.duty, 0.0);
        }
    }

    #[test]
    fn an_interval_given_backwards_is_the_same_interval() {
        let (cap, decoded) = i2c_decode();
        let a = measure(&cap, &decoded, 10_000, 90_000);
        let b = measure(&cap, &decoded, 90_000, 10_000);
        assert_eq!(a, b);
    }

    // ---- comparing ---------------------------------------------------------

    #[test]
    fn comparing_two_writes_shows_which_fields_differ() {
        let (_, decoded) = i2c_decode();
        let a = &decoded.transactions[0];          // 0x52 W 10 DE AD
        let b = &decoded.transactions[3];          // 0x3C W 01
        let c = compare(a, b);

        assert!(c.comparable, "both are I2C writes");
        assert!(c.why_not.is_none());
        assert!(!c.identical_content());
        let differing: Vec<&str> = c.differing_fields()
            .map(|f| f.name.as_str()).collect();
        assert!(differing.contains(&"address"),
                "0x52 and 0x3C differ; got {differing:?}");
    }

    #[test]
    fn comparing_a_transaction_with_itself_finds_nothing() {
        let (_, decoded) = i2c_decode();
        let t = &decoded.transactions[0];
        let c = compare(t, t);
        assert!(c.identical_content());
        assert_eq!(c.differing_fields().count(), 0);
        assert_eq!(c.duration.0, c.duration.1);
    }

    /// Different kinds are compared anyway, with the reason stated: a READ
    /// where a WRITE was expected is exactly what someone is looking for.
    #[test]
    fn incomparable_transactions_are_compared_with_the_reason_given() {
        let (_, decoded) = i2c_decode();
        let write = decoded.transactions.iter()
            .find(|t| t.kind == "WRITE").unwrap();
        let read = decoded.transactions.iter()
            .find(|t| t.kind.starts_with("READ")).unwrap();
        let c = compare(write, read);
        assert!(!c.comparable);
        assert!(c.why_not.unwrap().contains("kinds"));
        assert!(c.kind.is_some());
        assert!(!c.fields.is_empty(), "the fields are still lined up");
    }

    /// A field only one of them carries has to show as present-and-absent,
    /// not be quietly dropped.
    #[test]
    fn a_field_missing_from_one_side_still_appears() {
        let (_, decoded) = i2c_decode();
        let mut a = decoded.transactions[0].clone();
        let b = a.clone();
        a.fields.retain(|f| f.name != "address");

        let c = compare(&a, &b);
        let address = c.fields.iter().find(|f| f.name == "address").unwrap();
        assert_eq!(address.a, None);
        assert!(address.b.is_some());
        assert!(address.differs());
    }

    // ---- explaining --------------------------------------------------------

    #[test]
    fn an_explanation_is_derived_and_deterministic() {
        let (_, decoded) = i2c_decode();
        let t = &decoded.transactions[0];
        let once = explain(t);
        assert_eq!(once, explain(t), "the same transaction must explain the same");

        let text: String = once.iter().map(|l| l.text.clone())
            .collect::<Vec<_>>().join("\n");
        assert!(text.contains("WRITE"));
        assert!(text.contains("i2c"));
        assert!(text.contains("0x52"), "the address it carries");
        assert!(text.contains("chunk 0"), "and where the evidence is");
        assert!(once.iter().any(|l| l.kind == "evidence"));
    }

    #[test]
    fn an_explanation_says_what_is_wrong_when_something_is() {
        let (_, decoded) = i2c_decode();
        let nack = decoded.with_errors().next().unwrap();
        let text: String = explain(nack).iter()
            .filter(|l| l.kind == "problem")
            .map(|l| l.text.clone()).collect::<Vec<_>>().join("\n");
        assert!(text.contains("nack"), "got {text:?}");
    }

    #[test]
    fn an_explanation_of_a_clean_transaction_says_so() {
        let (_, decoded) = i2c_decode();
        let clean = decoded.transactions.iter()
            .find(|t| t.errors.is_empty() && t.complete).unwrap();
        assert!(explain(clean).iter()
            .any(|l| l.kind == "problem" && l.text.contains("nothing wrong")));
    }

    #[test]
    fn times_and_rates_read_in_a_sensible_unit() {
        assert_eq!(human_time(0), "0");
        assert!(human_time(500).ends_with("ps"));
        assert!(human_time(1_500).ends_with("ns"));
        assert!(human_time(1_500_000).ends_with("us"));
        assert!(human_rate(400_000.0).ends_with("kHz"));
        assert!(human_rate(2_000_000.0).ends_with("MHz"));
        assert!(human_bytes_per_second(2_500.0).ends_with("kB/s"));
        assert_eq!(human_rate(0.0), "0");
    }
}
