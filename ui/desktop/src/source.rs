//! Where a capture comes from: a file, the simulator, or a board.
//!
//! All three end at the same place - a `file::Capture` - because the file
//! format is the contract every other part of the product is written against.
//! A board capture that took a private path into the UI would be a second
//! implementation of the thing the acceptance criteria say there must be only
//! one of.
//!
//! # Why the board runs on its own thread
//!
//! A burst arms the hardware, waits however long the user asked for, and then
//! drains eight thousand edges over USB. Doing that between two frames freezes
//! the window for a second or more, and a frozen window during acquisition is
//! exactly when someone wants to see that anything is happening at all.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, TryRecvError};

use schema::Decoded;

/// A capture and where it came from.
pub struct Loaded {
    /// Shown in the title bar and the session pane: a file name, a script
    /// name, or a board's port.
    pub name: String,
    pub origin: Origin,
    pub capture: file::Capture,
    pub decoded: Decoded,
    pub info: schema::DecoderInfo,
    pub protocol: schema::Protocol,
    /// True when the protocol was guessed rather than chosen. Worth saying, as
    /// a decode that found nothing is usually the wrong protocol.
    pub guessed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Origin {
    File(PathBuf),
    Script(String),
    Board(String),
}

impl Origin {
    pub fn describe(&self) -> String {
        match self {
            Origin::File(p) => format!("file {}", p.display()),
            Origin::Script(s) => format!("simulated script {s}"),
            Origin::Board(p) => format!("board on {p}"),
        }
    }
}

/// Decoder choices the user can change without reloading the capture.
#[derive(Debug, Clone, Default)]
pub struct Settings {
    /// None means "work it out from the channel names".
    pub protocol: Option<schema::Protocol>,
    pub spi_mode: String,
    pub spi_bits: String,
    pub uart_baud: String,
    pub uart_parity: String,
    pub mdio_preamble: String,
    pub can_bitrate: String,
}

impl Settings {
    /// The registry's options, ignoring anything that will not parse.
    ///
    /// Ignoring rather than refusing because these are live text boxes: a
    /// half-typed "1152" must not blank the window with an error, and the
    /// number that eventually lands takes effect on the next decode.
    pub fn options(&self) -> registry::Options {
        registry::Options {
            spi_mode: self.spi_mode.trim().parse().ok(),
            spi_bits: self.spi_bits.trim().parse().ok(),
            uart_baud: self.uart_baud.trim().parse().ok(),
            uart_parity: match self.uart_parity.trim() {
                "" => None,
                other => Some(other.to_ascii_lowercase()),
            },
            mdio_preamble: self.mdio_preamble.trim().parse().ok(),
            can_bitrate: self.can_bitrate.trim().parse().ok(),
        }
    }

    /// Fill in what a script says its traffic needs, so simulating "uart" and
    /// then decoding it does not silently use the wrong parity.
    pub fn adopt(&mut self, pairs: &[(&str, &str)]) {
        for (key, value) in pairs {
            match *key {
                "spi_mode" => self.spi_mode = value.to_string(),
                "spi_bits" => self.spi_bits = value.to_string(),
                "uart_baud" => self.uart_baud = value.to_string(),
                "uart_parity" => self.uart_parity = value.to_string(),
                "mdio_preamble" => self.mdio_preamble = value.to_string(),
                "can_bitrate" => self.can_bitrate = value.to_string(),
                _ => {}
            }
        }
    }
}

/// Decode a capture, and say whether the protocol was guessed.
pub fn decode(
    capture: &file::Capture,
    settings: &Settings,
) -> (schema::Protocol, schema::DecoderInfo, Decoded, bool) {
    let guessed = settings.protocol.is_none();
    let protocol = settings.protocol.unwrap_or_else(|| registry::guess(capture));
    let decoder = registry::decoder_with(protocol, capture, &settings.options());
    let decoded = decoder.decode(capture);
    (protocol, decoder.info(), decoded, guessed)
}

/// Load a capture file and decode it.
pub fn open_file(path: &Path, settings: &Settings) -> Result<Loaded, String> {
    let capture = file::Capture::open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(finish(
        path.file_name().map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.display().to_string()),
        Origin::File(path.to_path_buf()),
        capture,
        settings,
    ))
}

/// Generate a script's traffic.
pub fn simulate(name: &str, hz: u64, settings: &mut Settings) -> Result<Loaded, String> {
    let script = simulator::script_named(name)
        .ok_or_else(|| format!("no script named {name:?}"))?;
    settings.adopt(script.settings);
    let capture = simulator::build(name, hz)
        .ok_or_else(|| format!("script {name:?} produced nothing"))?;
    Ok(finish(name.to_string(), Origin::Script(name.to_string()), capture, settings))
}

fn finish(
    name: String,
    origin: Origin,
    capture: file::Capture,
    settings: &Settings,
) -> Loaded {
    let (protocol, info, decoded, guessed) = decode(&capture, settings);
    Loaded { name, origin, capture, decoded, info, protocol, guessed }
}

/// The bytes of a capture, for saving it.
///
/// Round-tripped through the writer rather than copied from whatever was read,
/// so a capture that came off a board saves as a file the CLI can open - and
/// so this path is the same one the CLI's own writer takes.
pub fn to_bytes(capture: &file::Capture) -> Result<Vec<u8>, String> {
    let mut out = Cursor::new(Vec::new());
    let mut writer = file::Writer::new(&mut out, &capture.session)
        .map_err(|e| e.to_string())?;
    for chunk in &capture.chunks {
        writer.chunk(chunk).map_err(|e| e.to_string())?;
    }
    for gap in &capture.gaps {
        writer.gap(gap).map_err(|e| e.to_string())?;
    }
    for info in &capture.decoders {
        writer.decoder(info).map_err(|e| e.to_string())?;
    }
    if !capture.decoded.is_empty() {
        writer.decoded(&capture.decoded).map_err(|e| e.to_string())?;
    }
    // Bookmarks. Section 7 wants them carried into exports, and a save that
    // dropped them would lose work that only exists here.
    for a in &capture.annotations {
        writer.annotation(a).map_err(|e| e.to_string())?;
    }
    writer.finish().map_err(|e| e.to_string())?;
    Ok(out.into_inner())
}

// ---------------------------------------------------------------------------
// Extensions, off the UI thread
// ---------------------------------------------------------------------------

/// What an extension produced: the enriched decode, and what it did.
pub type Analysed = (Decoded, extend::Report);

/// An extension running as a subprocess.
///
/// Same shape as the board job below, for the same reason: an extension is
/// allowed to take its manifest's full timeout, and a window frozen for ten
/// seconds looks broken however good the reason.
pub struct AnalyseJob {
    pub what: String,
    rx: Receiver<Result<Analysed, String>>,
    done: bool,
}

impl AnalyseJob {
    pub fn start(
        manifest: extend::Manifest,
        protocol: schema::Protocol,
        decoded: Decoded,
        overrides: std::collections::BTreeMap<String, String>,
    ) -> AnalyseJob {
        let (tx, rx) = std::sync::mpsc::channel();
        let what = format!("running {}", manifest.name);

        std::thread::spawn(move || {
            // The thread works on its own copy and hands it back whole: an
            // extension that fails halfway must not leave the window looking
            // at a half-enriched decode.
            let mut working = decoded;
            let result = extend::run(&manifest, protocol, &mut working, &overrides)
                .map(|report| (working, report));
            let _ = tx.send(result);
        });

        AnalyseJob { what, rx, done: false }
    }

    pub fn poll(&mut self) -> Option<Result<Analysed, String>> {
        if self.done {
            return None;
        }
        match self.rx.try_recv() {
            Ok(result) => {
                self.done = true;
                Some(result)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.done = true;
                Some(Err("the extension thread stopped without answering".into()))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Board capture, off the UI thread
// ---------------------------------------------------------------------------

/// What the user asked the hardware for.
#[derive(Debug, Clone, Copy)]
pub struct BurstRequest {
    pub max_edges: u32,
    pub settle_ms: u64,
    pub self_test: bool,
}

impl Default for BurstRequest {
    fn default() -> Self {
        BurstRequest { max_edges: 8192, settle_ms: 200, self_test: false }
    }
}

/// A capture running on the hardware.
pub struct Job {
    pub what: String,
    rx: Receiver<Result<(String, file::Capture), String>>,
    done: bool,
}

impl Job {
    /// Take bursts one after another until the condition matches.
    ///
    /// Section 7 of the plan asks for live decoded results and event markers
    /// during acquisition. With burst hardware that is this: capture, decode,
    /// check, repeat - and the unwatched time between bursts recorded as a
    /// gap, because it is loss even though nothing broke.
    pub fn monitor(
        port: Option<String>,
        request: BurstRequest,
        rounds: u32,
        until: Option<trigger::Condition>,
        settings: Settings,
    ) -> Job {
        let (tx, rx) = std::sync::mpsc::channel();
        let what = match &until {
            Some(c) => format!("monitoring until {}", c.describe()),
            None => format!("monitoring for {rounds} burst(s)"),
        };

        std::thread::spawn(move || {
            let _ = tx.send(run_monitor(port.as_deref(), request,
                                        rounds.max(1), until, &settings));
        });

        Job { what, rx, done: false }
    }

    /// Start a burst. Returns immediately; the window keeps drawing.
    pub fn burst(port: Option<String>, request: BurstRequest) -> Job {
        let (tx, rx) = std::sync::mpsc::channel();
        let what = if request.self_test {
            "running the board's self test".to_string()
        } else {
            format!("capturing {} ms from the board", request.settle_ms)
        };

        std::thread::spawn(move || {
            let result = run_burst(port.as_deref(), request);
            // The receiver is gone if the window closed mid-capture, which is
            // not an error - there is simply nobody left to tell.
            let _ = tx.send(result);
        });

        Job { what, rx, done: false }
    }

    /// Has it finished? `None` while it is still running.
    pub fn poll(&mut self) -> Option<Result<(String, file::Capture), String>> {
        if self.done {
            return None;
        }
        match self.rx.try_recv() {
            Ok(result) => {
                self.done = true;
                Some(result)
            }
            Err(TryRecvError::Empty) => None,
            Err(TryRecvError::Disconnected) => {
                self.done = true;
                Some(Err("the capture thread stopped without answering".into()))
            }
        }
    }
}

fn run_burst(
    port: Option<&str>,
    request: BurstRequest,
) -> Result<(String, file::Capture), String> {
    let board = capture::Board::open(port).map_err(|e| e.0)?;
    let name = board.port.clone();
    let burst = capture::burst(&board, request.max_edges, request.settle_ms,
                               request.self_test)
        .map_err(|e| e.0)?;

    let mut gaps = burst.gaps;
    if burst.full {
        // The ring filled, so the capture stops where the hardware ran out of
        // room rather than where the bus went quiet. That is loss, and the
        // first acceptance criterion is that loss is never silent.
        gaps.push(file::Gap {
            start: burst.chunk.end,
            end: burst.chunk.end,
            reason: "the board's ring filled; capture stopped there".into(),
            lost: None,
        });
    }

    let index = file::rebuild_index(std::slice::from_ref(&burst.chunk), &gaps,
                                    &Decoded::default());
    Ok((name, file::Capture {
        session: burst.session,
        chunks: vec![burst.chunk],
        gaps,
        decoders: vec![],
        decoded: Decoded::default(),
        annotations: vec![],
        index,
        truncated_at: None,
    }))
}

/// Bursts one after another, joined into one capture.
fn run_monitor(
    port: Option<&str>,
    request: BurstRequest,
    rounds: u32,
    until: Option<trigger::Condition>,
    settings: &Settings,
) -> Result<(String, file::Capture), String> {
    let board = capture::Board::open(port).map_err(|e| e.0)?;
    let name = board.port.clone();
    let mut whole: Option<file::Capture> = None;

    for _ in 0..rounds {
        let started = std::time::Instant::now();
        let burst = capture::burst(&board, request.max_edges, request.settle_ms,
                                   request.self_test)
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

        // The condition is checked against this burst as it lands, which is
        // the whole point of monitoring rather than capturing.
        let hit = match &until {
            None => false,
            Some(condition) => {
                let (_, _, decoded, _) = decode(&one, settings);
                trigger::first(&one, &decoded, condition).is_some()
            }
        };

        // How long the bus went unwatched: the round trip, minus the part of
        // it that was actually being captured.
        let round_trip = started.elapsed().as_nanos() as u64 * 1_000;
        let watched = one.span().1;
        let unwatched = round_trip.saturating_sub(watched).max(1);

        whole = Some(match whole {
            None => one,
            Some(before) => before.join(
                &one, unwatched, "between bursts: nothing was watched"),
        });

        if hit {
            break;
        }
    }

    whole.map(|c| (name, c))
        .ok_or_else(|| "no bursts were captured".to_string())
}

// ---------------------------------------------------------------------------
// Finding files without a native dialog
// ---------------------------------------------------------------------------

/// Captures in a directory, newest first.
///
/// A built-in browser rather than the system dialog: it is one dependency
/// fewer, it works the same on every platform this is tested on, and listing
/// only captures is more useful here than listing everything.
pub fn captures_in(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<(std::time::SystemTime, PathBuf)> = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e.eq_ignore_ascii_case("cap")) != Some(true) {
            continue;
        }
        let when = entry.metadata().and_then(|m| m.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        found.push((when, path));
    }
    found.sort_by(|a, b| b.0.cmp(&a.0));
    found.into_iter().map(|(_, p)| p).collect()
}

/// Directories worth offering on startup.
pub fn likely_directories() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(cwd) = std::env::current_dir() {
        let golden = cwd.join("tests").join("golden");
        if golden.is_dir() {
            dirs.push(golden);
        }
        dirs.push(cwd);
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_ignore_half_typed_numbers_instead_of_refusing() {
        let mut s = Settings::default();
        s.uart_baud = "11".into();
        assert_eq!(s.options().uart_baud, Some(11));
        s.uart_baud = "not a number".into();
        assert_eq!(s.options().uart_baud, None,
                   "a live text box must not become an error dialog");
    }

    #[test]
    fn a_script_supplies_the_settings_a_capture_cannot_carry() {
        let mut s = Settings::default();
        s.adopt(&[("uart_parity", "e")]);
        assert_eq!(s.options().uart_parity.as_deref(), Some("e"));
    }

    #[test]
    fn simulating_decodes_with_the_scripts_own_settings() {
        let mut settings = Settings::default();
        let loaded = simulate("uart", 1_000_000, &mut settings).unwrap();
        assert_eq!(loaded.protocol, schema::Protocol::Uart);
        assert!(!loaded.decoded.transactions.is_empty());
        // The parity came from the script. Without it every frame would be
        // read one bit short and the corpus would be full of false errors.
        assert_eq!(settings.uart_parity, "e");
    }

    #[test]
    fn a_capture_round_trips_through_the_writer() {
        let mut settings = Settings::default();
        let loaded = simulate("demo", 1_000_000, &mut settings).unwrap();
        let bytes = to_bytes(&loaded.capture).unwrap();
        let back = file::Capture::from_bytes(&bytes).unwrap();
        assert_eq!(back.chunks, loaded.capture.chunks);
        assert_eq!(back.session, loaded.capture.session);
    }

    /// A bookmark that a save drops is work quietly lost.
    #[test]
    fn bookmarks_survive_a_round_trip_through_the_writer() {
        let mut settings = Settings::default();
        let mut loaded = simulate("demo", 1_000_000, &mut settings).unwrap();
        loaded.capture.annotations.push(file::Annotation {
            start: 1_000,
            end: 2_000,
            label: "the nack".into(),
            note: "0x77 never answers".into(),
        });

        let bytes = to_bytes(&loaded.capture).unwrap();
        let back = file::Capture::from_bytes(&bytes).unwrap();
        assert_eq!(back.annotations, loaded.capture.annotations);
    }

    /// Joining two bursts must record the unwatched time between them: a
    /// live session that looked continuous would be a capture claiming to
    /// have seen things nobody watched.
    #[test]
    fn joined_bursts_admit_the_time_nobody_watched() {
        let mut settings = Settings::default();
        let a = simulate("demo", 1_000_000, &mut settings).unwrap().capture;
        let b = simulate("scan", 1_000_000, &mut settings).unwrap().capture;

        let joined = a.join(&b, 40_000_000, "between bursts");
        assert_eq!(joined.gaps.len(), 1);
        assert!(joined.gaps[0].reason.contains("between bursts"));
        assert_eq!(joined.chunks.len(), 2);

        // And it still round-trips through the writer, so a monitored session
        // can be saved and reopened.
        let bytes = to_bytes(&joined).unwrap();
        let back = file::Capture::from_bytes(&bytes).unwrap();
        assert_eq!(back.gaps, joined.gaps);
        assert_eq!(back.chunks, joined.chunks);
    }

    #[test]
    fn an_overridden_protocol_is_not_reported_as_a_guess() {
        let mut settings = Settings::default();
        let loaded = simulate("demo", 1_000_000, &mut settings).unwrap();
        assert!(loaded.guessed);

        settings.protocol = Some(schema::Protocol::I2c);
        let (protocol, _, _, guessed) = decode(&loaded.capture, &settings);
        assert_eq!(protocol, schema::Protocol::I2c);
        assert!(!guessed);
    }
}
