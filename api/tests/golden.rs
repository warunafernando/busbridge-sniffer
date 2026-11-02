//! The golden corpus: canonical captures and the exact output they must produce.
//!
//! Section 12.1 asks for this before the GUI, and the phase exit criteria make
//! it the check that a change did not quietly alter a decode. A unit test says
//! a decoder handles a case; a golden test says the bytes it produces today are
//! the bytes it produced when someone last looked at them and agreed.
//!
//! # Regenerating
//!
//! ```text
//! UPDATE_GOLDEN=1 cargo test -p sniffer-cli --test golden
//! ```
//!
//! Then read the diff before committing it. A golden file updated without being
//! read is a test that has been switched off.
//!
//! # The hardware capture
//!
//! `board.cap` came off a NUCLEO-H533RE driving its own self-test pattern onto
//! the sniffer taps. It is in the corpus deliberately: synthetic edges are
//! clean and evenly spaced, and real ones are neither - the interrupt latency
//! puts the timestamps where they actually fall rather than where the protocol
//! says they should. A decoder that only ever sees generated traffic is a
//! decoder that has not met an interrupt.
//!
//! **It is a frozen input, not something to re-capture.** Two captures of the
//! same pattern do not agree to the picosecond - latency varies, and the
//! interval between arming and the first edge varies more - so re-running
//! `sniffer capture` over it changes every timestamp and the golden with it.
//! Replacing it is a deliberate act, and means regenerating `board.json` and
//! reading the diff. The structural assertions below are the part that must
//! hold whatever the timestamps do.

use std::path::{Path, PathBuf};

use schema::{Decoded, Protocol};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("tests/golden")
}

fn updating() -> bool {
    std::env::var("UPDATE_GOLDEN").is_ok()
}

/// Decode the way the CLI does when nobody says otherwise: the protocol comes
/// from the capture's channel names.
fn decode(cap: &file::Capture) -> Decoded {
    decode_as(registry::guess(cap), cap)
}

/// Decode as a named protocol.
///
/// The corpus uses this rather than the guess wherever the script declares what
/// it is, because I2C and I3C share both wires and no guess can separate them -
/// the CLI has `--protocol` for the same reason. Using the guess here would
/// have made the I3C golden a record of the I2C decoder's output.
fn decode_as(protocol: Protocol, cap: &file::Capture) -> Decoded {
    // The same registry the CLI and the UI use. This test used to carry its own
    // copy of the protocol guess and the decoder wiring, which meant the golden
    // files were evidence about a code path nobody ran.
    registry::decoder_with(protocol, cap, &registry::Options::from_pairs(settings_for(protocol)))
        .decode(cap)
}

/// What a script says its traffic needs, looked up by protocol.
fn settings_for(protocol: Protocol) -> &'static [(&'static str, &'static str)] {
    simulator::SCRIPTS
        .iter()
        .find(|s| s.protocol == protocol)
        .map(|s| s.settings)
        .unwrap_or(&[])
}

/// Build a capture in memory from a simulator script.
fn from_script(name: &str, hz: u64, gap: bool) -> file::Capture {
    if gap {
        simulator::build_with_gap(name, hz).unwrap()
    } else {
        simulator::build(name, hz).unwrap()
    }
}

/// The rate each script is generated at for the corpus. A protocol whose
/// timing matters is generated at a rate it plausibly runs at.
fn rate_for(name: &str) -> u64 {
    match name {
        "uart" => 115_200,
        "can" => 500_000,
        "spi" | "mdio" | "i3c" => 1_000_000,
        // I2C scripts, including "optics", at 100 kHz - which is a tick base
        // rather than the bus clock; see the note on simulator::I2c.
        _ => 100_000,
    }
}

/// Compare a decode against its golden file, or write it when regenerating.
///
/// The comparison is on the pretty-printed JSON rather than the structure, so
/// a failure can be read as a diff - which is the only form in which anyone
/// actually checks whether a changed decode is an improvement.
fn check(name: &str, decoded: &Decoded) {
    let path = golden_dir().join(format!("{name}.json"));
    let produced = serde_json::to_string_pretty(decoded)
        .expect("a decode must serialise");

    if updating() {
        std::fs::create_dir_all(golden_dir()).unwrap();
        std::fs::write(&path, produced + "
").unwrap();
        return;
    }

    let expected = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{}: {e}
Regenerate the corpus with UPDATE_GOLDEN=1, then read                 the diff before committing it.", path.display())
    });

    if expected.trim() != produced.trim() {
        // The first differing line, because a whole decode is too much to read
        // and the first divergence is nearly always the cause of the rest.
        let mut where_ = String::from("(no line differs; only trailing space)");
        for (n, (a, b)) in expected.lines().zip(produced.lines()).enumerate() {
            if a != b {
                where_ = format!("line {}:
  golden:   {a}
  produced: {b}",
                                 n + 1);
                break;
            }
        }
        panic!("{name} no longer decodes to its golden file.
{where_}

                If the new output is right, regenerate with UPDATE_GOLDEN=1 and                 read the diff.");
    }
}

/// Every script the simulator offers gets a golden file.
///
/// Driven off the simulator's own list rather than a copy of it, so adding a
/// script adds a golden - and forgetting to check the new one in fails the run
/// rather than passing quietly.
#[test]
fn every_script_has_a_golden() {
    for s in simulator::SCRIPTS {
        let cap = from_script(s.name, rate_for(s.name), false);
        check(s.name, &decode_as(s.protocol, &cap));
    }
}

#[test]
fn traffic_with_a_hole_in_it() {
    check("demo-gap", &decode(&from_script("demo", 100_000, true)));
}

/// Each protocol's own golden, asserted rather than only compared - so a
/// regenerated golden cannot bless a decode that is wrong in a way nobody read.
#[test]
fn each_protocol_decodes_to_what_it_should() {
    let uart_cap = from_script("uart", 115_200, false);
    let uart = decode(&uart_cap);
    let text: String = uart.transactions.iter()
        .filter_map(|t| t.fields.iter().find(|f| f.name == "ascii"))
        .map(|f| f.display.clone())
        .collect();
    assert!(text.starts_with("READY"), "uart read {text:?}");
    assert!(uart.transactions.iter().any(|t| !t.errors.is_empty()),
            "the uart script has a parity and a framing error in it");

    let spi = decode(&from_script("spi", 1_000_000, false));
    assert_eq!(spi.transactions.len(), 2, "{:#?}", spi.transactions);
    assert!(spi.transactions[0].summary.contains("MOSI 9F"),
            "{}", spi.transactions[0].summary);
    assert!(spi.transactions[0].summary.contains("EF 40 18"),
            "the JEDEC id should come back on MISO: {}",
            spi.transactions[0].summary);

    let mdio = decode(&from_script("mdio", 1_000_000, false));
    assert_eq!(mdio.transactions.len(), 5, "{:#?}", mdio.transactions);
    assert!(mdio.transactions[0].summary.contains("0x0141"));
    assert!(mdio.transactions[4].summary.contains("no turnaround"),
            "the absent PHY must not be reported as data: {}",
            mdio.transactions[4].summary);

    let can = decode_as(Protocol::Can, &from_script("can", 500_000, false));
    assert_eq!(can.transactions.len(), 6, "{:#?}",
               can.transactions.iter().map(|t| &t.summary).collect::<Vec<_>>());
    assert_eq!(can.transactions[0].summary, "0x123 DATA DE AD BE EF");
    assert!(can.transactions[1].summary.contains("ext"));
    assert_eq!(can.transactions[2].kind, "REMOTE");
    assert!(can.transactions[4].summary.contains("nobody acknowledged"));
    assert!(can.transactions[5].summary.contains("CRC failed"));

    let i3c = decode_as(Protocol::I3c, &from_script("i3c", 1_000_000, false));
    assert!(i3c.transactions.iter().any(|t| t.kind == "ENTDAA"),
            "{:#?}", i3c.transactions.iter().map(|t| &t.kind).collect::<Vec<_>>());
    assert!(i3c.transactions.iter().any(|t| t.kind == "IBI"));
}

/// A protocol added to the simulator without a decoder, or the reverse, is a
/// gap in the corpus - and this is what notices.
#[test]
fn the_corpus_covers_every_decoder() {
    use std::collections::BTreeSet;
    let scripted: BTreeSet<&str> = simulator::SCRIPTS.iter()
        .map(|s| s.protocol.as_str()).collect();
    for p in ["i2c", "i3c", "spi", "mdio", "uart", "can"] {
        assert!(scripted.contains(p),
                "{p} has a decoder but no script in the golden corpus");
    }
}

/// Real edges from real hardware, timestamps and all.
#[test]
fn a_capture_from_a_board() {
    let path = golden_dir().join("board.cap");
    if !path.exists() {
        // Skipped rather than failed: the corpus is checked in, but a fresh
        // clone that has not run `sniffer capture` yet should not fail its
        // whole test run over a file only hardware can make.
        eprintln!("skipping: {} is not present. Make one with:\n  \
                   sniffer capture tests/golden/board.cap --self-test",
                  path.display());
        return;
    }
    let cap = file::Capture::open(&path).unwrap();
    let decoded = decode(&cap);

    // The self-test drives 0xA0 0x5A 0x00 0xFF, and 0xA0 as an address byte is
    // 0x50 with the write bit clear. Asserted as well as compared to the golden
    // file, so a regenerated golden cannot quietly bless a wrong decode.
    assert_eq!(decoded.transactions.len(), 1,
               "the self-test pattern is one transaction: {:#?}",
               decoded.transactions);
    let t = &decoded.transactions[0];
    assert_eq!(t.summary, "0x50 W 5A 00 FF");
    assert!(t.complete);
    assert!(t.errors.is_empty(), "{:?}", t.errors);

    check("board", &decoded);
}

/// The rule that a hole makes a transaction incomplete rather than wrong.
#[test]
fn a_gap_marks_what_it_touches_and_nothing_else() {
    let cap = from_script("demo", 100_000, true);
    let decoded = decode(&cap);

    let touched: Vec<_> = decoded
        .transactions
        .iter()
        .filter(|t| t.errors.iter()
                .any(|e| matches!(e, schema::ErrorKind::GapOverlap)))
        .collect();

    assert!(!touched.is_empty(), "a gap was injected and nothing was marked");
    for t in &touched {
        assert!(!t.complete, "#{} overlaps a gap but claims to be complete", t.id);
    }
    // And transactions nowhere near the gap are untouched, or the flag would
    // mean nothing.
    let clean = decoded.transactions.iter().filter(|t| t.complete).count();
    assert!(clean > 0, "every transaction was marked, which cannot be right");
}

/// Every field must trace to a sample range - Appendix B, for every capture in
/// the corpus rather than for one example.
#[test]
fn every_field_in_the_corpus_traces_to_samples() {
    for s in simulator::SCRIPTS {
        let name = s.name;
        let cap = from_script(name, rate_for(name), false);
        let decoded = decode_as(s.protocol, &cap);
        let edges = cap.chunks[0].len() as u32;
        for t in &decoded.transactions {
            for f in &t.fields {
                assert!(f.samples.last >= f.samples.first,
                        "{name} #{}: {} has a backwards sample range", t.id, f.name);
                assert!(f.samples.last < edges,
                        "{name} #{}: {} points past the end of the chunk",
                        t.id, f.name);
                assert!(f.end >= f.start,
                        "{name} #{}: {} ends before it starts", t.id, f.name);
            }
        }
    }
}

/// The replay acceptance criterion, across the whole corpus.
#[test]
fn every_capture_decodes_identically_twice() {
    for s in simulator::SCRIPTS {
        let cap = from_script(s.name, rate_for(s.name), false);
        assert_eq!(decode_as(s.protocol, &cap), decode_as(s.protocol, &cap),
                   "{} is not deterministic", s.name);
    }
}

/// A capture written and reopened must decode to the same thing as one decoded
/// in memory - otherwise the file format is losing something.
#[test]
fn a_round_trip_through_the_file_changes_nothing() {
    let cap = from_script("demo", 100_000, true);
    let before = decode(&cap);

    let mut bytes = std::io::Cursor::new(Vec::new());
    let mut w = file::Writer::new(&mut bytes, &cap.session).unwrap();
    for chunk in &cap.chunks {
        w.chunk(chunk).unwrap();
    }
    for gap in &cap.gaps {
        w.gap(gap).unwrap();
    }
    w.finish().unwrap();

    let reopened = file::Capture::from_bytes(&bytes.into_inner()).unwrap();
    assert_eq!(before, decode(&reopened));
}
