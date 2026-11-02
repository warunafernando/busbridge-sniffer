//! The capture container: version 1.
//!
//! # Shape
//!
//! A magic, then a stream of length-prefixed records, then an index. Every
//! record carries its own type, length and CRC, which is what makes the format
//! recoverable: a file truncated by a crash is read until the first record that
//! does not check out, and everything before it is good. The index at the end
//! is an optimisation and never the source of truth - `rebuild_index` derives it
//! from the records, which is the specification's requirement that indexes can
//! be rebuilt from raw chunks.
//!
//! # What is in it
//!
//! Section 4.2 of the specification lists the record types, and these are they:
//! session header, sample chunk, gap, decoder config, decoded cache,
//! annotation, index.
//!
//! # Why samples are edges
//!
//! A digital capture of a two-wire bus is mostly nothing happening. Storing a
//! sample per tick at 250 MHz would be 31 MB a second per channel to say the
//! line did not move. So a chunk holds transitions: a timestamp and the state
//! of every channel after the edge. The specification allows either -
//! "compressed transitions or samples" - and transitions are what the hardware
//! produces.
//!
//! # Why not serde for the container
//!
//! The records inside are serde-encoded, but the framing is written by hand.
//! The framing is the part that has to survive a truncated file and a version
//! it does not know, and hand-written framing is the part that can be read
//! back by a tool that does not share this code.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{Read, Seek, Write};
use std::path::Path;

use schema::{Decoded, DecoderInfo, Picos};
use serde::{Deserialize, Serialize};

/// "SNIFCAP1" - eight bytes, so a hex dump names the format.
pub const MAGIC: &[u8; 8] = b"SNIFCAP1";

/// Bumped when the framing changes. The records inside carry their own
/// versioning through the schema crate.
pub const FORMAT_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordType {
    Session = 1,
    Samples = 2,
    Gap = 3,
    DecoderConfig = 4,
    Decoded = 5,
    Annotation = 6,
    Index = 7,
}

impl RecordType {
    fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => RecordType::Session,
            2 => RecordType::Samples,
            3 => RecordType::Gap,
            4 => RecordType::DecoderConfig,
            5 => RecordType::Decoded,
            6 => RecordType::Annotation,
            7 => RecordType::Index,
            _ => return None,
        })
    }
}

/// How the times in a capture were arrived at.
///
/// A capture file carries values and times together and nothing in its shape
/// distinguishes a time that was measured from one that was constructed. That
/// is fine while every writer measures, and stops being fine the moment one
/// does not: a reconstructed waveform looks exactly like a recorded one, and
/// every tool downstream - the waveform view, the cursors, the effective-clock
/// and duty-cycle measurements - will answer questions about its timing as
/// confidently as about a real recording, and be wrong.
///
/// So it is in the file, not in a comment or a filename, and it defaults to
/// `Measured` so an older capture reads as what it is.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum Timing {
    /// Counted by the capture hardware against its own clock.
    #[default]
    Measured,
    /// Reconstructed. The values and their order are real; the times are not.
    Synthetic(Synthetic),
}

/// What a reconstruction was built from, and what it had to invent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Synthetic {
    /// Why the times could not be measured.
    pub why: String,
    /// What the values came from - the part that *is* real.
    pub from: String,
    /// The bit period every edge was placed on. Nothing in the file varied from
    /// it, so any jitter, stretch or setup time read off this capture is an
    /// artifact of this number and not a property of the bus.
    pub bit_ps: Picos,
}

impl Timing {
    pub fn is_synthetic(&self) -> bool {
        matches!(self, Timing::Synthetic(_))
    }

    /// One line for a human, when there is something they must not assume.
    pub fn warning(&self) -> Option<String> {
        match self {
            Timing::Measured => None,
            Timing::Synthetic(s) => Some(format!(
                "SYNTHETIC TIMING - times in this capture were constructed, \
                 not measured. {} Values come from {}. Every edge sits on a \
                 {} ps bit period, so durations, clock rates, duty cycles and \
                 any jitter read from it describe that number and not the bus.",
                s.why, s.from, s.bit_ps)),
        }
    }
}

/// What the capture was and where it came from.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Session {
    pub format_version: u16,
    pub schema_version: u16,
    /// What produced it: a board's identity, or the simulator's name and seed.
    pub source: String,
    pub device_id: String,
    pub firmware_version: String,
    pub host_software: String,
    /// Wall clock at the start, for a human. Nothing computes with it.
    pub started_utc: String,
    /// Channel index to name, e.g. 0 -> "SCL". The bit position in a sample's
    /// line mask is the channel index.
    pub channels: Vec<String>,
    /// The tick rate the hardware counted at, recorded for provenance. Times in
    /// the file are picoseconds; this says what they were derived from.
    pub tick_hz: u64,
    /// Whether those times were measured or constructed. Defaulted rather than
    /// required, so captures written before this existed read back as
    /// `Measured`, which is what they are.
    #[serde(default)]
    pub timing: Timing,
}

/// A run of transitions.
///
/// **The first entry is the initial state, not a transition.** A stream of
/// transitions alone cannot say what the lines were doing before the first one:
/// an entry recording SDA low tells you SDA is now low, and leaves you to guess
/// whether it fell or whether SCL moved. Every decoder needs that first level
/// to compare against, so the chunk carries it and the writer is responsible
/// for putting it there.
///
/// It is a real sample at a real time - the moment capture was armed - so
/// nothing has to special-case it except a reader asking "how many edges", and
/// `transitions()` answers that.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SampleChunk {
    pub id: u32,
    pub start: Picos,
    /// When the capture stopped, which is **at or after** the last transition.
    ///
    /// Not the same thing, and the difference matters: a line that goes idle
    /// and stays there produces no further edges, so a UART frame ending in an
    /// idle stop bit has no edge at its end. Taking the last transition as the
    /// end of the capture makes every such frame look truncated. What is known
    /// is that the levels held from the last transition until here.
    pub end: Picos,
    /// The time of each entry, and the state of all channels at it. Parallel
    /// vectors rather than a vector of pairs - they compress better and the
    /// times are read alone far more often than the states.
    pub times: Vec<Picos>,
    pub lines: Vec<u8>,
}

impl SampleChunk {
    pub fn len(&self) -> usize {
        self.times.len()
    }

    pub fn is_empty(&self) -> bool {
        self.times.is_empty()
    }

    /// Entries that are actual transitions - everything but the initial state.
    pub fn transitions(&self) -> usize {
        self.times.len().saturating_sub(1)
    }

    /// The state of one channel after edge `i`.
    pub fn channel(&self, i: usize, channel: u8) -> bool {
        self.lines[i] & (1 << channel) != 0
    }
}

/// A hole in the capture.
///
/// The specification's first acceptance criterion is that no silent drop path
/// exists, so this record is the only correct way to represent one - and the
/// reason it carries `lost` as an `Option` is that "we know we lost data and do
/// not know how much" is a different statement from "we lost nine packets".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Gap {
    pub start: Picos,
    pub end: Picos,
    pub reason: String,
    pub lost: Option<u64>,
}

/// A bookmark, note or marker.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Annotation {
    pub start: Picos,
    pub end: Picos,
    pub label: String,
    pub note: String,
}

/// Where everything is, so a reader need not walk the whole file.
///
/// Rebuildable by definition: `rebuild_index` produces this from the records,
/// and a file whose index disagrees with its records is wrong about the index.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Index {
    /// Chunk id to its byte offset in the file.
    pub chunk_offsets: BTreeMap<u32, u64>,
    /// Chunk id to the time it starts, for a time-to-chunk lookup.
    pub chunk_times: BTreeMap<u32, Picos>,
    pub first_time: Picos,
    pub last_time: Picos,
    pub edge_count: u64,
    pub gap_count: u32,
    pub transaction_count: u64,
}

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Not one of these files at all.
    NotACapture,
    /// Written by a newer format than this build understands.
    Version(u16),
    /// The file ends inside a record, or a record's checksum disagrees with its
    /// bytes. Carries how much was readable, because that part is still good.
    Truncated { good_records: usize, at: u64 },
    Decode(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::NotACapture => write!(f, "not a capture file (bad magic)"),
            Error::Version(v) => write!(
                f, "capture format version {v}, this build reads {FORMAT_VERSION}"),
            Error::Truncated { good_records, at } => write!(
                f, "file is truncated at byte {at}; {good_records} record(s) before \
                    it are intact and were kept"),
            Error::Decode(m) => write!(f, "record does not decode: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

type Result<T> = std::result::Result<T, Error>;

/// CRC-32, the reflected one, same as zlib and the firmware's image header.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Writes a capture as it is produced, so a long capture never has to be held
/// in memory - the specification's requirement that raw chunks are written
/// before decoding and that RAM stays bounded.
pub struct Writer<W: Write + Seek> {
    out: W,
    index: Index,
    records: usize,
}

impl<W: Write + Seek> Writer<W> {
    pub fn new(mut out: W, session: &Session) -> Result<Self> {
        out.write_all(MAGIC)?;
        out.write_all(&FORMAT_VERSION.to_le_bytes())?;
        let mut w = Writer { out, index: Index::default(), records: 0 };
        w.write_record(RecordType::Session, session)?;
        Ok(w)
    }

    fn write_record<T: Serialize>(&mut self, kind: RecordType, value: &T) -> Result<u64> {
        let body = serde_json::to_vec(value)
            .map_err(|e| Error::Decode(e.to_string()))?;
        let offset = self.out.stream_position()?;

        // type, length, crc, body. The crc covers the body only: a corrupt
        // length is caught by the next record failing to parse, and a crc over
        // the header as well would not tell them apart any better.
        self.out.write_all(&[kind as u8])?;
        self.out.write_all(&(body.len() as u32).to_le_bytes())?;
        self.out.write_all(&crc32(&body).to_le_bytes())?;
        self.out.write_all(&body)?;
        self.records += 1;
        Ok(offset)
    }

    pub fn chunk(&mut self, chunk: &SampleChunk) -> Result<()> {
        let offset = self.write_record(RecordType::Samples, chunk)?;
        self.index.chunk_offsets.insert(chunk.id, offset);
        self.index.chunk_times.insert(chunk.id, chunk.start);
        if self.index.edge_count == 0 {
            self.index.first_time = chunk.start;
        }
        self.index.edge_count += chunk.len() as u64;
        self.index.last_time = self.index.last_time.max(chunk.end);
        Ok(())
    }

    pub fn gap(&mut self, gap: &Gap) -> Result<()> {
        self.write_record(RecordType::Gap, gap)?;
        self.index.gap_count += 1;
        self.index.last_time = self.index.last_time.max(gap.end);
        Ok(())
    }

    pub fn decoder(&mut self, info: &DecoderInfo) -> Result<()> {
        self.write_record(RecordType::DecoderConfig, info)?;
        Ok(())
    }

    pub fn decoded(&mut self, decoded: &Decoded) -> Result<()> {
        self.write_record(RecordType::Decoded, decoded)?;
        self.index.transaction_count += decoded.transactions.len() as u64;
        Ok(())
    }

    pub fn annotation(&mut self, a: &Annotation) -> Result<()> {
        self.write_record(RecordType::Annotation, a)?;
        Ok(())
    }

    /// Write the index and finish. A file that was never finished is still
    /// readable - `Capture::open` rebuilds the index when it finds none.
    pub fn finish(mut self) -> Result<()> {
        let index = self.index.clone();
        self.write_record(RecordType::Index, &index)?;
        self.out.flush()?;
        Ok(())
    }
}

/// A capture read into memory.
///
/// Whole-file for now, which is honest about what this is: the specification
/// requires captures larger than RAM to be navigable, and that is a chunked
/// reader over the same format. The format is built for it - records are
/// independent and the index maps chunk ids to byte offsets - so that reader is
/// a later addition and not a redesign.
#[derive(Debug, Clone)]
pub struct Capture {
    pub session: Session,
    pub chunks: Vec<SampleChunk>,
    pub gaps: Vec<Gap>,
    pub decoders: Vec<DecoderInfo>,
    pub decoded: Decoded,
    pub annotations: Vec<Annotation>,
    pub index: Index,
    /// Set when the file ended inside a record. Everything before it is intact
    /// and present; this says so out loud rather than pretending the capture
    /// simply ended there.
    pub truncated_at: Option<u64>,
}

impl Capture {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)?;
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 10 || &bytes[..8] != MAGIC {
            return Err(Error::NotACapture);
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != FORMAT_VERSION {
            return Err(Error::Version(version));
        }

        let mut session = None;
        let mut chunks = Vec::new();
        let mut gaps = Vec::new();
        let mut decoders = Vec::new();
        let mut decoded = Decoded::default();
        let mut annotations = Vec::new();
        let mut stored_index: Option<Index> = None;
        let mut truncated_at = None;
        let mut good = 0usize;

        let mut at = 10usize;
        while at < bytes.len() {
            // A record needs its nine-byte header before anything else.
            if at + 9 > bytes.len() {
                truncated_at = Some(at as u64);
                break;
            }
            let kind = bytes[at];
            let len = u32::from_le_bytes(bytes[at + 1..at + 5].try_into().unwrap()) as usize;
            let want = u32::from_le_bytes(bytes[at + 5..at + 9].try_into().unwrap());
            let body_at = at + 9;
            if body_at + len > bytes.len() {
                truncated_at = Some(at as u64);
                break;
            }
            let body = &bytes[body_at..body_at + len];
            if crc32(body) != want {
                // A record whose bytes do not match its checksum is where the
                // trustworthy part of the file ends. Reading past it would be
                // reading whatever the corruption happens to parse as.
                truncated_at = Some(at as u64);
                break;
            }

            match RecordType::from_u8(kind) {
                Some(RecordType::Session) => session = Some(from_json(body)?),
                Some(RecordType::Samples) => chunks.push(from_json(body)?),
                Some(RecordType::Gap) => gaps.push(from_json(body)?),
                Some(RecordType::DecoderConfig) => decoders.push(from_json(body)?),
                Some(RecordType::Decoded) => {
                    let d: Decoded = from_json(body)?;
                    decoded.transactions.extend(d.transactions);
                    decoded.events.extend(d.events);
                }
                Some(RecordType::Annotation) => annotations.push(from_json(body)?),
                Some(RecordType::Index) => stored_index = Some(from_json(body)?),
                // An unknown record type from a newer writer is skipped, not
                // refused: the length is there precisely so a reader can step
                // over what it does not understand.
                None => {}
            }
            good += 1;
            at = body_at + len;
        }

        let session = session.ok_or(Error::Decode("no session record".into()))?;
        let index = match stored_index {
            Some(i) => i,
            None => rebuild_index(&chunks, &gaps, &decoded),
        };

        if truncated_at.is_some() && good == 0 {
            return Err(Error::Truncated {
                good_records: good,
                at: truncated_at.unwrap(),
            });
        }

        Ok(Capture {
            session, chunks, gaps, decoders, decoded, annotations, index,
            truncated_at,
        })
    }

    /// Total capture span.
    pub fn span(&self) -> (Picos, Picos) {
        (self.index.first_time, self.index.last_time)
    }

    /// Does a gap overlap this interval? Decoders ask, so a transaction that
    /// straddles a hole can be marked incomplete rather than reported as fact.
    pub fn gap_overlaps(&self, start: Picos, end: Picos) -> bool {
        self.gaps.iter().any(|g| g.start <= end && g.end >= start)
    }

    /// The part of this capture between two times, as a capture of its own.
    ///
    /// This is what a pre-trigger window is: a trigger picks a moment, and
    /// what is wanted is some microseconds either side of it. Doing it here
    /// rather than in the caller is not tidiness - the format says the first
    /// entry of a chunk is the initial state, so a clip that simply drops the
    /// entries outside the window loses the levels the window opened at, and
    /// every decoder downstream starts in mid air.
    ///
    /// The clip says so in its session source. An excerpt that cannot be told
    /// from a whole capture is a way to mislead somebody later.
    pub fn clip(&self, start: Picos, end: Picos) -> Capture {
        let (start, end) = if start <= end { (start, end) } else { (end, start) };

        let mut chunks = Vec::new();
        for chunk in &self.chunks {
            if chunk.is_empty() || chunk.end < start || chunk.start > end {
                continue;
            }
            // The entry at or before the window start becomes the new initial
            // state, moved to the window's start: the levels it recorded are
            // what held when the window opened.
            let first = match chunk.times.binary_search(&start) {
                Ok(i) => i,
                Err(0) => 0,
                Err(i) => i - 1,
            };

            let mut times = Vec::new();
            let mut lines = Vec::new();
            for i in first..chunk.len() {
                let at = chunk.times[i];
                if at > end {
                    break;
                }
                times.push(at.max(start));
                lines.push(chunk.lines[i]);
            }
            if times.is_empty() {
                continue;
            }
            chunks.push(SampleChunk {
                id: chunk.id,
                start: times[0],
                end: chunk.end.min(end),
                times,
                lines,
            });
        }

        let gaps: Vec<Gap> = self.gaps.iter()
            .filter(|g| g.start <= end && g.end >= start)
            .map(|g| Gap {
                start: g.start.max(start),
                end: g.end.min(end),
                reason: g.reason.clone(),
                lost: g.lost,
            })
            .collect();

        let annotations: Vec<Annotation> = self.annotations.iter()
            .filter(|a| a.start <= end && a.end.max(a.start) >= start)
            .cloned()
            .collect();

        // Transactions wholly inside the window. One that straddles the edge
        // is not in this capture any more, and keeping it would be a decode
        // that the samples here cannot support.
        let decoded = Decoded {
            transactions: self.decoded.transactions.iter()
                .filter(|t| t.start >= start && t.end <= end)
                .cloned()
                .collect(),
            events: self.decoded.events.iter()
                .filter(|e| e.start >= start && e.end <= end)
                .cloned()
                .collect(),
        };

        let mut session = self.session.clone();
        session.source = format!("{} (clipped {} to {} ps)",
                                 session.source, start, end);

        let index = rebuild_index(&chunks, &gaps, &decoded);
        Capture {
            session,
            chunks,
            gaps,
            decoders: self.decoders.clone(),
            decoded,
            annotations,
            index,
            truncated_at: None,
        }
    }

    /// Put another capture after this one, with the hole between them recorded.
    ///
    /// Burst capture means a session is several captures, and the time between
    /// two bursts is time nobody watched. That is loss, so it becomes a gap
    /// record - the first acceptance criterion is that no loss is silent, and
    /// "we stopped looking for 40 ms" is loss even though nothing broke.
    ///
    /// `quiet_ps` is how long the bus went unwatched between them.
    pub fn join(&self, next: &Capture, quiet_ps: Picos, reason: &str) -> Capture {
        let (_, my_end) = self.span();
        let offset = my_end + quiet_ps;

        let mut chunks = self.chunks.clone();
        let next_id = chunks.iter().map(|c| c.id).max().map(|m| m + 1).unwrap_or(0);
        for (n, chunk) in next.chunks.iter().enumerate() {
            chunks.push(SampleChunk {
                id: next_id + n as u32,
                start: chunk.start + offset,
                end: chunk.end + offset,
                times: chunk.times.iter().map(|t| t + offset).collect(),
                lines: chunk.lines.clone(),
            });
        }

        let mut gaps = self.gaps.clone();
        if quiet_ps > 0 {
            gaps.push(Gap {
                start: my_end,
                end: offset,
                reason: reason.to_string(),
                lost: None,
            });
        }
        for gap in &next.gaps {
            gaps.push(Gap {
                start: gap.start + offset,
                end: gap.end + offset,
                reason: gap.reason.clone(),
                lost: gap.lost,
            });
        }

        let mut annotations = self.annotations.clone();
        for a in &next.annotations {
            annotations.push(Annotation {
                start: a.start + offset,
                end: a.end + offset,
                label: a.label.clone(),
                note: a.note.clone(),
            });
        }

        // Decodes are not merged: transaction ids are unique within a decode,
        // not across two, and renumbering them here would break every
        // reference anybody has already written down. The joined capture is
        // decoded again.
        let decoded = Decoded::default();
        let index = rebuild_index(&chunks, &gaps, &decoded);

        Capture {
            session: self.session.clone(),
            chunks,
            gaps,
            decoders: Vec::new(),
            decoded,
            annotations,
            index,
            truncated_at: self.truncated_at,
        }
    }
}

fn from_json<T: for<'de> Deserialize<'de>>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|e| Error::Decode(e.to_string()))
}

/// Derive the index from the records, which is what makes the stored one an
/// optimisation rather than a second source of truth.
pub fn rebuild_index(chunks: &[SampleChunk], gaps: &[Gap], decoded: &Decoded) -> Index {
    let mut index = Index::default();
    for (n, chunk) in chunks.iter().enumerate() {
        index.chunk_times.insert(chunk.id, chunk.start);
        index.edge_count += chunk.len() as u64;
        if n == 0 {
            index.first_time = chunk.start;
        }
        index.last_time = index.last_time.max(chunk.end);
    }
    for gap in gaps {
        index.last_time = index.last_time.max(gap.end);
    }
    index.gap_count = gaps.len() as u32;
    index.transaction_count = decoded.transactions.len() as u64;
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A capture with a known square wave, for the clip and join tests.
    fn wave(cycles: u64, period: Picos) -> Capture {
        let mut times = vec![0u64];
        let mut lines = vec![0u8];
        for n in 0..cycles {
            times.push(n * period + period / 2);
            lines.push(1);
            times.push((n + 1) * period);
            lines.push(0);
        }
        let chunk = SampleChunk {
            id: 0, start: 0, end: cycles * period, times, lines,
        };
        let index = rebuild_index(std::slice::from_ref(&chunk), &[],
                                 &Decoded::default());
        Capture {
            session: a_session(),
            chunks: vec![chunk],
            gaps: vec![],
            decoders: vec![],
            decoded: Decoded::default(),
            annotations: vec![],
            index,
            truncated_at: None,
        }
    }

    /// The invariant a hand-written clip forgets: the first entry of a chunk
    /// is the initial state, so a window that opens mid-pulse has to carry
    /// the level that was in force.
    #[test]
    fn a_clip_keeps_the_level_the_window_opened_at() {
        let cap = wave(10, 1_000_000);
        // Opens at 600 ns, which is inside a high phase (rises at 500 ns).
        let clipped = cap.clip(600_000, 2_600_000);

        let chunk = &clipped.chunks[0];
        assert_eq!(chunk.times[0], 600_000, "the initial state is at the window");
        assert_eq!(chunk.lines[0], 1, "and it records the level that held");
        assert!(chunk.times.iter().all(|t| *t >= 600_000 && *t <= 2_600_000));
        assert_eq!(chunk.end, 2_600_000);
    }

    #[test]
    fn a_clip_says_that_it_is_one() {
        let cap = wave(4, 1_000_000);
        let clipped = cap.clip(0, 2_000_000);
        assert!(clipped.session.source.contains("clipped"),
                "an excerpt that reads as a whole capture is a way to mislead \
                 somebody: {}", clipped.session.source);
    }

    #[test]
    fn a_clip_outside_the_capture_is_empty_rather_than_wrong() {
        let cap = wave(4, 1_000_000);
        let clipped = cap.clip(50_000_000, 60_000_000);
        assert!(clipped.chunks.is_empty());
        assert_eq!(clipped.index.edge_count, 0);
    }

    #[test]
    fn a_clip_keeps_the_gaps_and_bookmarks_it_covers_and_no_others() {
        let mut cap = wave(10, 1_000_000);
        cap.gaps.push(Gap { start: 1_000_000, end: 1_500_000,
                            reason: "inside".into(), lost: None });
        cap.gaps.push(Gap { start: 8_000_000, end: 8_500_000,
                            reason: "outside".into(), lost: None });
        cap.annotations.push(Annotation { start: 1_200_000, end: 1_200_000,
                                          label: "inside".into(),
                                          note: String::new() });
        cap.annotations.push(Annotation { start: 9_000_000, end: 9_000_000,
                                          label: "outside".into(),
                                          note: String::new() });
        cap.index = rebuild_index(&cap.chunks, &cap.gaps, &cap.decoded);

        let clipped = cap.clip(0, 3_000_000);
        assert_eq!(clipped.gaps.len(), 1);
        assert_eq!(clipped.gaps[0].reason, "inside");
        assert_eq!(clipped.annotations.len(), 1);
        assert_eq!(clipped.annotations[0].label, "inside");
    }

    /// Burst capture means the time between bursts is time nobody watched,
    /// and that is loss however normal it is.
    #[test]
    fn joining_two_bursts_records_the_unwatched_time_as_a_gap() {
        let a = wave(3, 1_000_000);
        let b = wave(2, 1_000_000);
        let quiet = 40_000_000;
        let joined = a.join(&b, quiet, "between bursts");

        assert_eq!(joined.chunks.len(), 2);
        assert_eq!(joined.gaps.len(), 1);
        assert_eq!(joined.gaps[0].start, a.span().1);
        assert_eq!(joined.gaps[0].end, a.span().1 + quiet);
        assert!(joined.gaps[0].reason.contains("between bursts"));

        // The second burst's times moved, and nothing overlaps the first.
        let second = &joined.chunks[1];
        assert!(second.start >= joined.gaps[0].end);
        assert_ne!(second.id, joined.chunks[0].id, "chunk ids stay unique");
        assert_eq!(joined.span().1, a.span().1 + quiet + b.span().1);
    }

    /// Transaction ids are unique within one decode, not across two. A joined
    /// capture is decoded again rather than carrying two sets of ids that
    /// collide.
    #[test]
    fn joining_drops_the_decodes_rather_than_colliding_their_ids() {
        let mut a = wave(3, 1_000_000);
        a.decoded.transactions.push(schema::Transaction {
            id: 1, bus: schema::BusId(0), protocol: schema::Protocol::I2c,
            start: 0, end: 1_000, kind: "WRITE".into(), summary: "x".into(),
            severity: schema::Severity::Info, parent: None, fields: vec![],
            errors: vec![],
            samples: schema::SampleRef { chunk: 0, first: 0, last: 1 },
            complete: true,
        });
        let b = a.clone();
        let joined = a.join(&b, 1_000, "between bursts");
        assert!(joined.decoded.transactions.is_empty());
        assert!(joined.decoders.is_empty());
    }

    fn a_session() -> Session {
        Session {
            format_version: FORMAT_VERSION,
            schema_version: schema::SCHEMA_VERSION,
            source: "test".into(),
            device_id: "none".into(),
            firmware_version: "0".into(),
            host_software: "test".into(),
            started_utc: "1970-01-01T00:00:00Z".into(),
            channels: vec!["SCL".into(), "SDA".into()],
            tick_hz: 250_000_000,
            timing: Timing::Measured,
        }
    }

    /// A session written before `timing` existed must read back as measured.
    ///
    /// Defaulting the other way would relabel every capture ever taken as
    /// suspect, which is both wrong and the kind of wrong that gets the warning
    /// ignored.
    #[test]
    fn a_session_without_a_timing_field_is_measured() {
        let json = r#"{
            "format_version": 1, "schema_version": 1,
            "source": "busbridge:USB", "device_id": "d",
            "firmware_version": "f", "host_software": "h",
            "started_utc": "1970-01-01T00:00:00Z",
            "channels": ["SCL", "SDA"], "tick_hz": 250000000
        }"#;
        let s: Session = serde_json::from_str(json).expect("old session reads");
        assert_eq!(s.timing, Timing::Measured);
        assert!(s.timing.warning().is_none());
    }

    /// And a reconstruction says so, through a round trip of the file format.
    #[test]
    fn synthetic_timing_survives_the_file_and_says_what_it_invented() {
        let mut session = a_session();
        session.timing = Timing::Synthetic(Synthetic {
            why: "the bus was too fast to oversample".into(),
            from: "pin-clocked decode".into(),
            bit_ps: 80_000,
        });
        let text = serde_json::to_string(&session).expect("serialises");
        let back: Session = serde_json::from_str(&text).expect("reads back");
        assert_eq!(back.timing, session.timing);

        let warning = back.timing.warning().expect("a warning");
        assert!(warning.contains("SYNTHETIC"), "{warning}");
        // The bit period has to be in it: it is the number every duration read
        // off the capture is really reporting.
        assert!(warning.contains("80000"), "{warning}");
    }

    fn a_chunk(id: u32) -> SampleChunk {
        SampleChunk {
            id,
            start: 0,
            end: 8_000,
            times: vec![0, 4_000, 8_000],
            lines: vec![3, 1, 3],
        }
    }

    fn write_one() -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut w = Writer::new(&mut buf, &a_session()).unwrap();
        w.chunk(&a_chunk(0)).unwrap();
        w.gap(&Gap {
            start: 8_000, end: 9_000,
            reason: "buffer full".into(), lost: None,
        }).unwrap();
        w.finish().unwrap();
        buf.into_inner()
    }

    #[test]
    fn a_capture_round_trips() {
        let bytes = write_one();
        let cap = Capture::from_bytes(&bytes).unwrap();
        assert_eq!(cap.session.channels, vec!["SCL", "SDA"]);
        assert_eq!(cap.chunks.len(), 1);
        assert_eq!(cap.chunks[0].times, vec![0, 4_000, 8_000]);
        assert_eq!(cap.gaps.len(), 1);
        assert_eq!(cap.index.edge_count, 3);
        assert_eq!(cap.index.gap_count, 1);
        assert!(cap.truncated_at.is_none());
    }

    #[test]
    fn a_file_that_is_not_one_of_ours_is_refused() {
        assert!(matches!(Capture::from_bytes(b"not a capture at all"),
                         Err(Error::NotACapture)));
    }

    #[test]
    fn a_newer_format_is_refused_by_version_rather_than_misread() {
        let mut bytes = write_one();
        bytes[8] = 99;
        assert!(matches!(Capture::from_bytes(&bytes), Err(Error::Version(99))));
    }

    /// The recovery requirement: a file cut short by a crash keeps everything
    /// before the cut, and says where it was cut.
    #[test]
    fn a_truncated_file_keeps_what_was_intact() {
        let bytes = write_one();
        for cut in [bytes.len() - 1, bytes.len() / 2, bytes.len() - 20] {
            let cap = Capture::from_bytes(&bytes[..cut]).unwrap();
            assert!(cap.truncated_at.is_some(), "cut at {cut} was not noticed");
            // The session survived, which is what makes the rest interpretable.
            assert_eq!(cap.session.tick_hz, 250_000_000);
        }
    }

    /// Corruption in the middle must stop the read, not be parsed past.
    #[test]
    fn a_bad_checksum_ends_the_trustworthy_part() {
        let mut bytes = write_one();
        // Flip a byte inside the first chunk's body: past the magic, the
        // version and the session record.
        let at = bytes.len() / 2;
        bytes[at] ^= 0xFF;
        let cap = Capture::from_bytes(&bytes).unwrap();
        assert!(cap.truncated_at.is_some());
    }

    #[test]
    fn an_unfinished_file_rebuilds_its_index() {
        let mut buf = Cursor::new(Vec::new());
        let mut w = Writer::new(&mut buf, &a_session()).unwrap();
        w.chunk(&a_chunk(0)).unwrap();
        w.chunk(&a_chunk(1)).unwrap();
        // Deliberately no finish(): the process died.
        drop(w);
        let cap = Capture::from_bytes(&buf.into_inner()).unwrap();
        assert_eq!(cap.chunks.len(), 2);
        assert_eq!(cap.index.edge_count, 6);
    }

    #[test]
    fn an_unknown_record_type_is_stepped_over() {
        let mut bytes = write_one();
        // Re-tag the gap record as a type from a future version. Finding it
        // takes a scan, which is what a reader does anyway.
        let mut at = 10usize;
        while at + 9 <= bytes.len() {
            let len = u32::from_le_bytes(bytes[at + 1..at + 5].try_into().unwrap()) as usize;
            if bytes[at] == RecordType::Gap as u8 {
                bytes[at] = 200;
                break;
            }
            at += 9 + len;
        }
        let cap = Capture::from_bytes(&bytes).unwrap();
        assert!(cap.truncated_at.is_none(), "an unknown type must not stop the read");
        assert_eq!(cap.chunks.len(), 1);
        assert_eq!(cap.gaps.len(), 0);
    }

    #[test]
    fn gap_overlap_is_inclusive_at_the_edges() {
        let bytes = write_one();
        let cap = Capture::from_bytes(&bytes).unwrap();
        assert!(cap.gap_overlaps(7_000, 8_000), "touching the start counts");
        assert!(cap.gap_overlaps(9_000, 10_000), "touching the end counts");
        assert!(!cap.gap_overlaps(0, 7_999));
        assert!(!cap.gap_overlaps(9_001, 20_000));
    }
}
