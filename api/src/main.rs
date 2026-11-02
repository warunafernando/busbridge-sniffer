//! The command-line tools, which section 12.1 says to build before the GUI.
//!
//! Not scaffolding for a GUI that will replace them: the acceptance criteria
//! require that capture, decoder configuration, query and export all work
//! without one, and the golden regression tests drive these same paths. A GUI
//! is another consumer of this, later.
//!
//! Every subcommand here is a step of Appendix D's first end-to-end demo, in
//! the order it lists them. `sniffer demo` runs the lot.

mod show;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use schema::{Decoded, Protocol, Severity};
use search as query;

const USAGE: &str = "\
sniffer - multi-protocol capture, decode and search

  sniffer devices
        what boards are attached

  sniffer capture <file.cap> [--port P] [--edges N] [--ms N] [--self-test]
        capture raw edges from a board and save them
        --self-test drives a known pattern on the taps, so it works with
        nothing wired

  sniffer simulate <file.cap> [--script NAME] [--hz N] [--gap]
        write a capture from synthetic traffic, no hardware needed
        --gap injects a hole, to prove gaps are reported and not hidden

  sniffer scripts
        the synthetic traffic scripts available

  sniffer decode <file.cap> [--protocol P] [--save] [--json] [--csv]
        decode and print transactions; --save writes them back into the file
        the protocol is guessed from the capture's channel names unless given
        per-protocol options: --spi-mode N --spi-bits N
                             --uart-baud N --uart-parity n|e|o
                             --mdio-preamble N --can-bitrate N

  sniffer protocols
        what can be decoded

  sniffer show <file.cap> [--from N] [--to N] [--transaction ID] [--width N]
        the waveform, with decoded fields under it

  sniffer query <file.cap> <query...> [--limit N] [--explain]
        e.g. sniffer query cap.cap addr:0x52 error:any
        --limit stops after N results without counting the rest

  sniffer bookmark <file.cap> <label> [--at <us>] [--to <us>] [--note text]
        add a named marker; --at defaults to the start of the capture
        sniffer bookmark <file.cap> --list

  sniffer info <file.cap>
        session, chunks, gaps, integrity

  sniffer measure <file.cap> [--from <us>] [--to <us>]
        duration, edges, duty cycle, effective clock, transaction rate,
        payload throughput, bus utilisation and error counts over an interval

  sniffer compare <file.cap> <id> <id>
        two transactions, field by field

  sniffer explain <file.cap> <id>
        what one transaction was, derived from its own decoded fields

  sniffer extensions [dir]
        the device and application analysers that can be applied

  sniffer analyze <file.cap> [--extension <name|dir>] [--set k=v] [--save]
        decode, then run the extensions over it; --save writes the enriched
        transactions back into the capture

  sniffer trigger <file.cap> <condition...> [--all] [--before <us>]
                  [--after <us>] [--out <clip.cap>]
        find where a condition happened; --out writes the window around it
        e.g. edge:rising:0 | low:1:for=2us | glitch:0:shorter=100ns
             start | start:i2c | addr:0x52 | type:WRITE | error:nack
             addr:0x3C then error:nack within=1ms

  sniffer monitor [--port COM7] [--ms N] [--repeat N] [--until <condition>]
                  [--self-test] [--out <file.cap>]
        capture bursts one after another, decoding each as it lands, until the
        condition matches or the repeats run out

  sniffer replay <a.cap> [b.cap]
        decode twice and prove the results are identical; with two files,
        compare them against each other

  sniffer serve [--allow-control]
        speak MCP on stdin and stdout, for an agent or an editor
        read-only unless --allow-control is given, which lets it arm the board

  sniffer api
        the local API surface, and which half of the safety boundary each
        operation is on

  sniffer version
        what this copy is, and what it was built from

  sniffer demo [dir]
        run Appendix D end to end and report each step
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let rest: Vec<&str> = args[1..].iter().map(|s| s.as_str()).collect();
    let result = match args[0].as_str() {
        "devices" => devices(),
        "capture" => capture_cmd(&rest),
        "simulate" => simulate(&rest),
        "scripts" => { list_scripts(); Ok(()) }
        "protocols" => { list_protocols(); Ok(()) }
        "decode" => decode_cmd(&rest),
        "show" => show_cmd(&rest),
        "query" => query_cmd(&rest),
        "info" => info(&rest),
        "bookmark" => bookmark(&rest),
        "measure" => measure_cmd(&rest),
        "compare" => compare_cmd(&rest),
        "explain" => explain_cmd(&rest),
        "extensions" => list_extensions(&rest),
        "analyze" | "analyse" => analyze_cmd(&rest),
        "trigger" => trigger_cmd(&rest),
        "monitor" => monitor(&rest),
        "replay" => replay(&rest),
        "serve" => serve(&rest),
        "api" => { list_api(); Ok(()) }
        "version" => { version(); Ok(()) }
        "demo" => demo(&rest),
        other => Err(format!("unknown command {other:?}\n\n{USAGE}")),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("sniffer: {message}");
            ExitCode::FAILURE
        }
    }
}

/* ---- argument helpers ---------------------------------------------------- */

fn flag(args: &[&str], name: &str) -> bool {
    args.iter().any(|a| *a == name)
}

fn option<'a>(args: &[&'a str], name: &str) -> Option<&'a str> {
    args.iter().position(|a| *a == name).and_then(|i| args.get(i + 1)).copied()
}

fn number(args: &[&str], name: &str, default: u64) -> Result<u64, String> {
    match option(args, name) {
        None => Ok(default),
        Some(v) => v.parse().map_err(|_| format!("{name} wants a number, got {v:?}")),
    }
}

fn positional<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut skip = false;
    for (i, a) in args.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with("--") {
            // Options that take a value swallow the next argument.
            let takes_value = matches!(
                *a, "--port" | "--edges" | "--ms" | "--script" | "--hz"
                  | "--from" | "--to" | "--transaction" | "--width"
                  | "--protocol" | "--spi-mode" | "--spi-bits" | "--uart-baud"
                  | "--uart-parity" | "--mdio-preamble" | "--can-bitrate"
                  | "--limit" | "--at" | "--note" | "--out" | "--before"
                  | "--after" | "--until" | "--repeat" | "--extension"
                  | "--set");
            skip = takes_value && i + 1 < args.len();
            continue;
        }
        out.push(*a);
    }
    out
}

/* ---- commands ------------------------------------------------------------ */

fn devices() -> Result<(), String> {
    let found = capture::list();
    if found.is_empty() {
        println!("no boards attached");
        println!();
        println!("A board's own USB connector needs a cable to this machine; the");
        println!("ST-LINK cable carries debug only. `sniffer simulate` needs no board.");
        return Ok(());
    }
    for port in found {
        println!("  {port}");
    }
    Ok(())
}

fn capture_cmd(args: &[&str]) -> Result<(), String> {
    let out = positional(args).first().copied()
        .ok_or("capture needs a file to write")?;
    let edges = number(args, "--edges", 8192)? as u32;
    let ms = number(args, "--ms", 200)?;
    let self_test = flag(args, "--self-test");

    let board = capture::Board::open(option(args, "--port"))
        .map_err(|e| e.to_string())?;
    println!("board   {} ({})", board.port, board.firmware);
    if self_test {
        println!("driving the self-test pattern on the taps");
    } else {
        println!("capturing for {ms} ms, up to {edges} edges");
    }

    let burst = capture::burst(&board, edges, ms, self_test)
        .map_err(|e| e.to_string())?;

    let transitions = burst.chunk.transitions();
    if transitions == 0 {
        println!();
        println!("no edges. Nothing moved on the taps - check the wiring and the");
        println!("ground, or use --self-test to prove the capture path works.");
    }

    write_capture(Path::new(out), &burst.session,
                  std::slice::from_ref(&burst.chunk), &burst.gaps, None)?;

    let span_us = burst.chunk.end.saturating_sub(burst.chunk.start) / 1_000_000;
    println!("wrote   {out}: {transitions} transitions over {span_us} us");
    if burst.full {
        println!("        the board's buffer filled, so a gap record marks the end");
    }
    Ok(())
}

fn simulate(args: &[&str]) -> Result<(), String> {
    let out = positional(args).first().copied()
        .ok_or("simulate needs a file to write")?;
    let name = option(args, "--script").unwrap_or("demo");
    let hz = number(args, "--hz", 100_000)?;

    let cap = if flag(args, "--gap") {
        simulator::build_with_gap(name, hz)
    } else {
        simulator::build(name, hz)
    }
    .ok_or_else(|| format!("no script called {name:?}; try `sniffer scripts`"))?;

    write_capture(Path::new(out), &cap.session, &cap.chunks, &cap.gaps, None)?;
    println!("wrote {out}: script {name} at {hz} Hz, {} transitions, {} gap(s)",
             cap.chunks.iter().map(|c| c.transitions()).sum::<usize>(),
             cap.gaps.len());
    Ok(())
}

fn list_scripts() {
    for s in simulator::SCRIPTS {
        println!("  {:<12} {:<5} {}", s.name, s.protocol.as_str(), s.about);
    }
}

fn write_capture(
    path: &Path,
    session: &file::Session,
    chunks: &[file::SampleChunk],
    gaps: &[file::Gap],
    decoded: Option<(&schema::DecoderInfo, &Decoded)>,
) -> Result<(), String> {
    write_capture_with(path, session, chunks, gaps, decoded, &[])
}

/// The same, keeping annotations. Bookmarks live in the file, so anything that
/// rewrites a capture has to carry them across or they are lost on the next
/// `--save`.
fn write_capture_with(
    path: &Path,
    session: &file::Session,
    chunks: &[file::SampleChunk],
    gaps: &[file::Gap],
    decoded: Option<(&schema::DecoderInfo, &Decoded)>,
    annotations: &[file::Annotation],
) -> Result<(), String> {
    let out = std::fs::File::create(path)
        .map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    let mut writer = file::Writer::new(out, session).map_err(|e| e.to_string())?;
    for chunk in chunks {
        writer.chunk(chunk).map_err(|e| e.to_string())?;
    }
    for gap in gaps {
        writer.gap(gap).map_err(|e| e.to_string())?;
    }
    if let Some((info, d)) = decoded {
        writer.decoder(info).map_err(|e| e.to_string())?;
        writer.decoded(d).map_err(|e| e.to_string())?;
    }
    for a in annotations {
        writer.annotation(a).map_err(|e| e.to_string())?;
    }
    writer.finish().map_err(|e| e.to_string())
}

fn open(path: &str) -> Result<file::Capture, String> {
    let cap = file::Capture::open(path).map_err(|e| format!("{path}: {e}"))?;
    if let Some(at) = cap.truncated_at {
        eprintln!("sniffer: {path} is truncated at byte {at}; everything before it \
                   was read and is shown");
    }
    // Here rather than in the commands that happen to draw a waveform, because
    // every command that opens a capture can be asked a timing question - show
    // and measure obviously, but also a query over a duration, or a decode
    // whose transaction times someone reads off the table.
    if let Some(warning) = cap.session.timing.warning() {
        eprintln!("sniffer: {warning}");
    }
    Ok(cap)
}

/// The decoder for a capture, and what it produced.
///
/// The protocol comes from the arguments when given and from the capture's
/// channel names otherwise. Which one was used is returned, because a decode
/// that found nothing is usually the wrong protocol and the answer should not
/// have to be guessed at twice.
fn decode_with(
    cap: &file::Capture,
    args: &[&str],
) -> Result<(Protocol, schema::DecoderInfo, Decoded), String> {
    let protocol = match option(args, "--protocol") {
        Some(name) => Protocol::parse(name).ok_or_else(|| {
            let known: Vec<&str> = registry::PROTOCOLS.iter()
                .map(|(p, _)| p.as_str()).collect();
            format!("unknown protocol {name:?}; try one of: {}", known.join(", "))
        })?,
        None => registry::guess(cap),
    };

    let options = registry::Options {
        spi_mode: option(args, "--spi-mode").and_then(|v| v.parse().ok()),
        spi_bits: option(args, "--spi-bits").and_then(|v| v.parse().ok()),
        uart_baud: option(args, "--uart-baud").and_then(|v| v.parse().ok()),
        uart_parity: option(args, "--uart-parity").map(|v| v.to_ascii_lowercase()),
        mdio_preamble: option(args, "--mdio-preamble").and_then(|v| v.parse().ok()),
        can_bitrate: option(args, "--can-bitrate").and_then(|v| v.parse().ok()),
    };

    let decoder = registry::decoder_with(protocol, cap, &options);
    Ok((protocol, decoder.info(), decoder.decode(cap)))
}

/// For callers that only want the result and have no arguments to pass.
fn decode_of(cap: &file::Capture) -> (schema::DecoderInfo, Decoded) {
    let protocol = registry::guess(cap);
    let decoder = registry::decoder(protocol, cap);
    (decoder.info(), decoder.decode(cap))
}

fn list_protocols() {
    for (p, what) in registry::PROTOCOLS {
        println!("  {:<6} {}", p.as_str(), what);
    }
}

fn decode_cmd(args: &[&str]) -> Result<(), String> {
    let path = positional(args).first().copied()
        .ok_or("decode needs a capture file")?;
    let cap = open(path)?;
    let (protocol, info, decoded) = decode_with(&cap, args)?;
    if option(args, "--protocol").is_none() && !flag(args, "--json")
        && !flag(args, "--csv")
    {
        eprintln!("decoding as {} (from the channel names: {}). \
                   --protocol overrides.",
                  protocol.as_str(), cap.session.channels.join(", "));
    }

    if flag(args, "--json") {
        println!("{}", serde_json::to_string_pretty(&decoded)
                 .map_err(|e| e.to_string())?);
    } else if flag(args, "--csv") {
        print_csv(&decoded);
    } else {
        print_table(&decoded);
    }

    if flag(args, "--save") {
        let chunks = cap.chunks.clone();
        // The bookmarks come across: a saved decode must not cost the file
        // its markers.
        write_capture_with(Path::new(path), &cap.session, &chunks, &cap.gaps,
                      Some((&info, &decoded)), &cap.annotations)?;
        eprintln!("decoded {} transaction(s) written back into {path}",
                  decoded.transactions.len());
    }
    Ok(())
}

fn print_table(decoded: &Decoded) {
    println!("{:>12}  {:<4} {:<9} {:<9} {}",
             "time (us)", "bus", "type", "severity", "summary");
    for t in &decoded.transactions {
        let mark = if !t.complete { " [incomplete]" } else { "" };
        println!("{:>12.3}  {:<4} {:<9} {:<9} {}{}",
                 t.start as f64 / 1_000_000.0,
                 t.bus.0, t.kind, t.severity.as_str(), t.summary, mark);
        for e in &t.errors {
            println!("{:>12}  {:<4} {:<9} {:<9} {}", "", "", "", "", e.as_str());
        }
    }
    for e in &decoded.events {
        println!("{:>12.3}  {:<4} {:<9} {:<9} {}",
                 e.start as f64 / 1_000_000.0, "", "event",
                 e.severity.as_str(), e.message);
    }
    println!();
    println!("{} transaction(s), {} event(s), {} with something wrong",
             decoded.transactions.len(), decoded.events.len(),
             decoded.with_errors().count());
}

/// CSV with the raw timestamp references the acceptance criteria ask for.
fn print_csv(decoded: &Decoded) {
    println!("id,bus,protocol,start_ps,end_ps,kind,severity,complete,\
              chunk,first_sample,last_sample,errors,summary");
    for t in &decoded.transactions {
        let errors = t.errors.iter().map(|e| e.as_str())
            .collect::<Vec<_>>().join("|");
        println!("{},{},{},{},{},{},{},{},{},{},{},{},{}",
                 t.id, t.bus.0, t.protocol.as_str(), t.start, t.end, t.kind,
                 t.severity.as_str(), t.complete,
                 t.samples.chunk, t.samples.first, t.samples.last,
                 errors, csv_quote(&t.summary));
    }
}

fn csv_quote(text: &str) -> String {
    if text.contains(',') || text.contains('"') {
        format!("\"{}\"", text.replace('"', "\"\""))
    } else {
        text.to_string()
    }
}

fn show_cmd(args: &[&str]) -> Result<(), String> {
    let path = positional(args).first().copied()
        .ok_or("show needs a capture file")?;
    let cap = open(path)?;
    let (_, _, decoded) = decode_with(&cap, args)?;
    let width = number(args, "--width", 100)? as usize;

    // Centre on a transaction when asked, which is Appendix D's "select a
    // bubble and synchronise" in a terminal.
    let (from, to) = if let Some(id) = option(args, "--transaction") {
        let id: u64 = id.parse().map_err(|_| "--transaction wants an id")?;
        let t = decoded.transactions.iter().find(|t| t.id == id)
            .ok_or_else(|| format!("no transaction {id} in this capture"))?;
        let pad = (t.end - t.start) / 8 + 1;
        (t.start.saturating_sub(pad), t.end + pad)
    } else {
        let from = number(args, "--from", cap.index.first_time)?;
        let to = number(args, "--to", cap.index.last_time)?;
        (from, to)
    };

    show::waveform(&cap, &decoded, from, to, width);
    Ok(())
}

fn query_cmd(args: &[&str]) -> Result<(), String> {
    let words = positional(args);
    let path = words.first().copied().ok_or("query needs a capture file")?;
    let text = words[1..].join(" ");
    if text.trim().is_empty() {
        println!("a query looks like:");
        for (name, what) in query::KNOWN {
            println!("  {name:<10} {what}");
        }
        // And the fields this capture's own decoder emits, which is what makes
        // the language protocol-native rather than a fixed vocabulary.
        if let Ok(cap) = file::Capture::open(path) {
            let protocol = registry::guess(&cap);
            let decoder = registry::decoder(protocol, &cap);
            let fields = decoder.search_fields();
            if !fields.is_empty() {
                println!();
                println!("fields this capture's {} decoder emits:", protocol.as_str());
                for f in fields {
                    println!("  {:<10} {}", f.name, f.help);
                }
            }
        }
        return Ok(());
    }

    let cap = open(path)?;
    let (_, _, decoded) = decode_with(&cap, args)?;
    let q = query::parse(&text).map_err(|e| e.to_string())?;

    // Planned against the index rather than scanned, so --limit costs the
    // results asked for instead of the whole capture. Section 6.2.
    let index = query::Index::build(&decoded);
    let limit = match option(args, "--limit") {
        Some(n) => Some(n.parse::<usize>()
            .map_err(|_| format!("--limit wants a number, not {n:?}"))?),
        None => None,
    };

    let mut hits = index.hits(&q, &decoded);
    // One more than asked for, so "and more follow" is a fact rather than a
    // guess - and still not a count of the whole capture.
    let wanted = limit.map(|n| n + 1).unwrap_or(usize::MAX);
    let rows: Vec<usize> = hits.by_ref().take(wanted).collect();
    let examined = hits.examined();
    let more = limit.map(|n| rows.len() > n).unwrap_or(false);
    let shown = limit.map(|n| n.min(rows.len())).unwrap_or(rows.len());

    if more {
        println!("first {shown} match(es) for {text:?}, and more follow");
    } else {
        println!("{shown} of {} transaction(s) match {text:?}",
                 decoded.transactions.len());
    }
    if flag(args, "--explain") {
        println!("examined {examined} candidate(s) to produce {shown}; \
                  the index holds {} row(s)", index.rows());
    }
    println!();
    for row in rows.iter().take(shown) {
        let t = &decoded.transactions[*row];
        let mark = if !t.complete { " [incomplete]" } else { "" };
        println!("  #{:<4} {:>12.3} us  {:<9} {}{}",
                 t.id, t.start as f64 / 1_000_000.0, t.kind, t.summary, mark);
    }
    if shown == 0 {
        println!("  nothing. `sniffer decode {path}` shows everything there is.");
    }
    Ok(())
}

fn info(args: &[&str]) -> Result<(), String> {
    let path = positional(args).first().copied()
        .ok_or("info needs a capture file")?;
    let cap = open(path)?;
    let (start, end) = cap.span();

    println!("source        {}", cap.session.source);
    println!("device        {}", cap.session.device_id);
    println!("firmware      {}", cap.session.firmware_version);
    println!("written by    {}", cap.session.host_software);
    println!("started       {}", cap.session.started_utc);
    println!("channels      {}", cap.session.channels.join(", "));
    println!("tick rate     {} Hz", cap.session.tick_hz);
    println!("format        v{} schema v{}",
             cap.session.format_version, cap.session.schema_version);
    println!();
    println!("chunks        {}", cap.chunks.len());
    println!("transitions   {}", cap.index.edge_count.saturating_sub(cap.chunks.len() as u64));
    println!("span          {:.3} us", (end - start) as f64 / 1_000_000.0);
    println!("decoders      {}", if cap.decoders.is_empty() { "none recorded".into() }
             else { cap.decoders.iter()
                    .map(|d| format!("{} {}", d.name, d.version))
                    .collect::<Vec<_>>().join(", ") });
    println!("cached decode {} transaction(s)", cap.decoded.transactions.len());

    if !cap.annotations.is_empty() {
        println!();
        println!("bookmarks     {}", cap.annotations.len());
        for a in &cap.annotations {
            let span = if a.end > a.start {
                format!("{:.3} us to {:.3} us",
                        a.start as f64 / 1_000_000.0, a.end as f64 / 1_000_000.0)
            } else {
                format!("{:.3} us", a.start as f64 / 1_000_000.0)
            };
            println!("  {span}  {}{}", a.label,
                     if a.note.is_empty() { String::new() }
                     else { format!("  - {}", a.note) });
        }
    }

    println!();
    if cap.gaps.is_empty() && cap.truncated_at.is_none() {
        println!("integrity     no gaps recorded");
    } else {
        println!("integrity     {} gap(s){}", cap.gaps.len(),
                 match cap.truncated_at {
                     Some(at) => format!(", and the file is truncated at byte {at}"),
                     None => String::new(),
                 });
        for g in &cap.gaps {
            println!("  {:.3} us  {:.3} us  {}{}",
                     g.start as f64 / 1_000_000.0,
                     g.end as f64 / 1_000_000.0,
                     g.reason,
                     match g.lost {
                         Some(n) => format!(" ({n} lost)"),
                         None => " (amount unknown)".into(),
                     });
        }
    }
    Ok(())
}

/// What this copy is.
///
/// Nothing here checks for updates by itself - a bench tool that phones home
/// is a bench tool people stop trusting. This prints what the copy is so it
/// can be compared with whatever release is on offer, and reads the build
/// manifest the packaging script leaves beside the executable when there is
/// one.
fn version() {
    println!("sniffer {}", env!("CARGO_PKG_VERSION"));

    let beside = std::env::current_exe().ok()
        .and_then(|exe| exe.parent().map(|d| d.join("build.json")));
    match beside.filter(|p| p.exists()) {
        Some(path) => {
            println!();
            match std::fs::read_to_string(&path) {
                Ok(text) => println!("{}", text.trim()),
                Err(e) => println!("{}: {e}", path.display()),
            }
        }
        None => {
            println!();
            println!("built from source; there is no build manifest beside \
                      this executable. `scripts\\package.ps1` writes one.");
        }
    }

    println!();
    println!("extensions    {}", match extend::extensions_dir() {
        Some(dir) => format!("{} ({} found)", dir.display(),
                             extend::Manifest::discover(&dir).len()),
        None => "none found".to_string(),
    });
    println!("capture       needs the board's own USB cable; the ST-LINK \
              cable carries debug only");
}

/// Speak MCP on stdin and stdout.
fn serve(args: &[&str]) -> Result<(), String> {
    let allow_control = flag(args, "--allow-control");
    // To stderr: stdout is the protocol, and a greeting on it would be a
    // parse error at the other end.
    eprintln!("sniffer MCP on stdin/stdout, {} tools{}",
              if allow_control { "all" } else { "read-only" },
              if allow_control {
                  " - capture control is ENABLED and can arm the board"
              } else {
                  ""
              });
    service::mcp::serve(allow_control).map_err(|e| e.to_string())
}

/// The API surface, with the boundary section 9.2 asks for.
fn list_api() {
    println!("read-only:");
    for o in service::OPERATIONS.iter()
        .filter(|o| o.kind == service::Kind::Read)
    {
        println!("  {:<22} {}", o.name, o.about);
    }
    println!();
    println!("control (needs --allow-control over MCP):");
    for o in service::OPERATIONS.iter()
        .filter(|o| o.kind == service::Kind::Control)
    {
        println!("  {:<22} {}", o.name, o.about);
    }
}

/// Find where a condition happened, and optionally take the window around it.
fn trigger_cmd(args: &[&str]) -> Result<(), String> {
    let words = positional(args);
    let path = words.first().copied().ok_or("trigger needs a capture file")?;
    let text = words[1..].join(" ");
    if text.trim().is_empty() {
        return Err("trigger needs a condition. Try edge:rising:0, \
                    low:1:for=2us, start:i2c, addr:0x52, error:nack, or \
                    `addr:0x3C then error:nack within=1ms`.".into());
    }

    let condition = trigger::parse(&text)?;
    let cap = open(path)?;
    let decoded = if condition.needs_decode() {
        decode_with(&cap, args)?.2
    } else {
        // An edge trigger needs no decoder, and saying so is the difference
        // between working on a capture whose protocol is unknown and not.
        Decoded::default()
    };

    println!("condition     {}", condition.describe());
    println!("class         {}{}", condition.class().as_str(),
             if condition.hardware_class() {
                 " (a class a capture engine could arm)"
             } else {
                 " (software only)"
             });
    println!("evaluated     in software, over the captured samples");
    if !trigger::hardware_available() {
        println!("              {}", trigger::NO_HARDWARE_TRIGGER);
    }
    println!();

    let matches = trigger::find(&cap, &decoded, &condition);
    if matches.is_empty() {
        println!("no match in {path}");
        return Ok(());
    }

    let show = if flag(args, "--all") { matches.len() } else { 20.min(matches.len()) };
    println!("{} match(es){}", matches.len(),
             if show < matches.len() {
                 format!("; the first {show}, and --all for the rest")
             } else {
                 String::new()
             });
    for m in matches.iter().take(show) {
        println!("  {:>12.3} us  {}{}", m.at as f64 / 1_000_000.0, m.what,
                 match m.transaction {
                     Some(id) => format!("  (#{id})"),
                     None => String::new(),
                 });
    }

    if let Some(out) = option(args, "--out") {
        let before = number(args, "--before", 100)? * 1_000_000;
        let after = number(args, "--after", 100)? * 1_000_000;
        let at = matches[0].at;
        let (from, to) = trigger::window(&cap, at, before, after);
        let clip = cap.clip(from, to);
        write_capture_with(Path::new(out), &clip.session, &clip.chunks,
                           &clip.gaps, None, &clip.annotations)?;
        println!();
        println!("wrote {out}: {:.3} us to {:.3} us around the first match, \
                  {} transition(s)",
                 from as f64 / 1_000_000.0, to as f64 / 1_000_000.0,
                 clip.chunks.iter().map(|c| c.transitions()).sum::<usize>());
    }
    Ok(())
}

/// Capture bursts one after another, decoding each as it lands.
///
/// Section 7 of the plan wants live decoded results and event markers during
/// acquisition. This hardware captures in bursts - arm, wait, drain - so a
/// "live" session is a sequence of them, and the time between two bursts is
/// time nobody watched. That becomes a gap record rather than being papered
/// over, which is the same rule the rest of the product follows.
fn monitor(args: &[&str]) -> Result<(), String> {
    let board = capture::Board::open(option(args, "--port"))
        .map_err(|e| e.0)?;
    println!("monitoring {} ({}), firmware {}",
             board.port, board.serial, board.firmware);

    let edges = number(args, "--edges", 8192)? as u32;
    let ms = number(args, "--ms", 200)?;
    let repeats = number(args, "--repeat", 5)?;
    // With nothing wired to the taps there is nothing to watch, so the board
    // drives its own pattern instead - the only way to monitor real edges on
    // a bench with no bus attached.
    let self_test = flag(args, "--self-test");
    let until = match option(args, "--until") {
        Some(text) => Some(trigger::parse(text)?),
        None => None,
    };
    if let Some(condition) = &until {
        println!("stopping when: {}", condition.describe());
    }
    println!();

    let mut whole: Option<file::Capture> = None;
    let mut matched = false;

    for round in 1..=repeats {
        let started = std::time::Instant::now();
        let burst = capture::burst(&board, edges, ms, self_test)
            .map_err(|e| e.0)?;
        let transitions = burst.chunk.transitions();

        let index = file::rebuild_index(std::slice::from_ref(&burst.chunk),
                                        &burst.gaps, &Decoded::default());
        let one = file::Capture {
            session: burst.session,
            chunks: vec![burst.chunk],
            gaps: burst.gaps,
            decoders: vec![],
            decoded: Decoded::default(),
            annotations: vec![],
            index,
            truncated_at: None,
        };

        // Decoded as it lands, which is the live part.
        let (_, decoded) = decode_of(&one);
        let worst = worst(&decoded);
        println!("burst {round}: {transitions} transition(s), {} \
                  transaction(s), worst {}{}",
                 decoded.transactions.len(), worst.as_str(),
                 if burst.full { ", the board's ring filled" } else { "" });
        for t in decoded.transactions.iter().take(6) {
            println!("    {:>10.3} us  {:<9} {}",
                     t.start as f64 / 1_000_000.0, t.kind, t.summary);
        }
        if decoded.transactions.len() > 6 {
            println!("    and {} more", decoded.transactions.len() - 6);
        }

        // Event markers during acquisition: the trigger, checked per burst.
        if let Some(condition) = &until {
            if let Some(hit) = trigger::first(&one, &decoded, condition) {
                println!("    -> {} at {:.3} us into this burst",
                         hit.what, hit.at as f64 / 1_000_000.0);
                matched = true;
            }
        }

        // What the bus did between two bursts is unknown, and how long that
        // was is measurable: the round trip minus what was watched.
        let quiet = started.elapsed().as_nanos() as u64 * 1_000;
        let watched = one.span().1;
        let unwatched = quiet.saturating_sub(watched);

        whole = Some(match whole {
            None => one,
            Some(before) => before.join(&one, unwatched.max(1),
                                        "between bursts: nothing was watched"),
        });

        if matched {
            break;
        }
    }

    let Some(whole) = whole else { return Err("no bursts were captured".into()) };
    println!();
    let (first, last) = whole.span();
    println!("{} burst(s) joined: {:.3} ms, {} gap(s) where nothing was \
              watched",
             whole.chunks.len(), (last - first) as f64 / 1e9, whole.gaps.len());
    if until.is_some() && !matched {
        println!("the condition never matched");
    }

    if let Some(out) = option(args, "--out") {
        write_capture_with(Path::new(out), &whole.session, &whole.chunks,
                           &whole.gaps, None, &whole.annotations)?;
        println!("wrote {out}");
    }
    Ok(())
}

/// Where the extensions are: the argument, then the shipped directory.
fn extensions_root(args: &[&str]) -> Result<PathBuf, String> {
    if let Some(dir) = positional(args).first() {
        let path = PathBuf::from(dir);
        if path.is_dir() {
            return Ok(path);
        }
    }
    extend::extensions_dir().ok_or_else(|| {
        "no extensions directory found. It ships beside the executable and \
         lives in `extensions/` in the source tree; name one on the command \
         line to use another.".to_string()
    })
}

fn list_extensions(args: &[&str]) -> Result<(), String> {
    let root = extensions_root(args)?;
    let found = extend::Manifest::discover(&root);
    println!("{}", root.display());
    if found.is_empty() {
        println!("  nothing here. An extension is a directory with an \
                  extension.json in it.");
        return Ok(());
    }
    for m in &found {
        println!();
        println!("  {} {}", m.name, m.version);
        println!("    {}", m.about);
        println!("    protocols: {}", if m.protocols.is_empty() {
            "any".to_string()
        } else {
            m.protocols.join(", ")
        });
        println!("    runs: {}", m.command.join(" "));
        if !m.settings.is_empty() {
            let settings: Vec<String> = m.settings.iter()
                .map(|(k, v)| format!("{k}={v}")).collect();
            println!("    settings: {}", settings.join(" "));
        }
        for f in &m.search_fields {
            println!("    field {:<20} {}", f.name, f.help);
        }
    }
    Ok(())
}

/// Decode, then hand the transactions to the extensions.
fn analyze_cmd(args: &[&str]) -> Result<(), String> {
    let words = positional(args);
    let path = words.first().copied().ok_or("analyze needs a capture file")?;
    let cap = open(path)?;
    let (protocol, info, mut decoded) = decode_with(&cap, args)?;

    let root = extend::extensions_dir();
    let all = root.as_deref().map(extend::Manifest::discover).unwrap_or_default();

    // Named, or every one that handles this protocol. Defaulting to all of
    // them is what makes `analyze` a single step for the common case.
    let wanted: Vec<extend::Manifest> = match option(args, "--extension") {
        Some(name) => {
            let as_dir = PathBuf::from(name);
            if as_dir.is_dir() {
                vec![extend::Manifest::load(&as_dir)?]
            } else {
                let found = all.iter().find(|m| m.name == name).cloned();
                vec![found.ok_or_else(|| format!(
                    "no extension called {name:?}. `sniffer extensions` lists \
                     what there is."))?]
            }
        }
        None => all.into_iter().filter(|m| m.handles(protocol)).collect(),
    };

    if wanted.is_empty() {
        return Err(format!(
            "no extension handles {}. `sniffer extensions` lists what there is.",
            protocol.as_str()));
    }

    // --set k=v, repeatable.
    let mut overrides: std::collections::BTreeMap<String, String> =
        Default::default();
    for (i, a) in args.iter().enumerate() {
        if *a == "--set" {
            if let Some(pair) = args.get(i + 1) {
                match pair.split_once('=') {
                    Some((k, v)) => {
                        overrides.insert(k.to_string(), v.to_string());
                    }
                    None => return Err(format!(
                        "--set wants key=value, not {pair:?}")),
                }
            }
        }
    }

    let mut any = false;
    for manifest in &wanted {
        match extend::run(manifest, protocol, &mut decoded, &overrides) {
            Ok(report) => {
                any = true;
                println!("{} {}: {} transaction(s) enriched, {} field(s), \
                          {} warning(s) in {:?}",
                         manifest.name, manifest.version, report.touched,
                         report.fields_added, report.warnings, report.took);
                for note in &report.notes {
                    println!("  note: {note}");
                }
                for problem in &report.rejected {
                    // Never silent: output the host could not use is output
                    // somebody meant.
                    eprintln!("  ignored: {problem}");
                }
                if !report.stderr.is_empty() {
                    eprintln!("  stderr: {}", report.stderr);
                }
            }
            Err(e) => eprintln!("{}: {e}", manifest.name),
        }
    }
    if !any {
        return Err("every extension failed".into());
    }

    println!();
    print_table(&decoded);

    // The derived fields, which are the point of the exercise and are not in
    // the one-line summaries.
    for t in &decoded.transactions {
        let derived: Vec<&schema::Field> = t.fields.iter()
            .filter(|f| f.name.contains('.'))
            .collect();
        if derived.is_empty() {
            continue;
        }
        println!();
        println!("  #{} {} {}", t.id, t.kind, t.summary);
        for f in derived {
            println!("      {:<22} {}", f.name, f.display);
        }
    }

    if flag(args, "--save") {
        let mut enriched = info.clone();
        // Recorded as the pipeline that produced it, not as the decoder
        // alone: a saved decode has to say what enriched it, or the file
        // claims the decoder emitted fields it has never heard of.
        for m in &wanted {
            enriched.settings.push((format!("extension.{}", m.name),
                                    m.version.clone()));
        }
        write_capture_with(Path::new(path), &cap.session, &cap.chunks, &cap.gaps,
                           Some((&enriched, &decoded)), &cap.annotations)?;
        println!();
        println!("written back into {path}");
    }
    Ok(())
}

/// Measure an interval: section 7's range measurement, in a terminal.
fn measure_cmd(args: &[&str]) -> Result<(), String> {
    let path = positional(args).first().copied()
        .ok_or("measure needs a capture file")?;
    let cap = open(path)?;
    let (_, _, decoded) = decode_with(&cap, args)?;
    let (first, last) = cap.span();

    let micros = |name: &str, fallback: u64| -> Result<u64, String> {
        match option(args, name) {
            None => Ok(fallback),
            Some(v) => {
                let us: f64 = v.parse()
                    .map_err(|_| format!("{name} wants microseconds, not {v:?}"))?;
                Ok((us * 1_000_000.0) as u64)
            }
        }
    };
    let from = micros("--from", first)?;
    let to = micros("--to", last)?;

    let m = measure::measure(&cap, &decoded, from, to);
    println!("interval      {} to {}  ({})",
             measure::human_time(m.start), measure::human_time(m.end),
             measure::human_time(m.duration));
    if m.gap_overlap {
        println!("              a gap touches this interval, so every count \
                  below is a lower bound");
    }
    println!();
    println!("{:<8} {:>7} {:>7} {:>9} {:>12} {:>12}",
             "channel", "edges", "rising", "duty", "clock", "shortest");
    for c in &m.channels {
        println!("{:<8} {:>7} {:>7} {:>8.1}% {:>12} {:>12}",
                 c.name, c.edges, c.rising, c.duty * 100.0,
                 match c.frequency_hz {
                     Some(hz) => measure::human_rate(hz),
                     None => "-".into(),
                 },
                 match c.shortest {
                     Some(w) => measure::human_time(w),
                     None => "-".into(),
                 });
    }

    println!();
    println!("transactions  {} ({:.1}/s){}", m.transactions,
             m.transaction_rate_hz,
             if m.errors > 0 { format!(", {} with problems", m.errors) }
             else { String::new() });
    println!("payload       {} byte(s), {}", m.payload_bytes,
             measure::human_bytes_per_second(m.payload_bytes_per_second));
    println!("utilisation   {:.1}% of the interval carried a transaction",
             m.utilisation * 100.0);
    Ok(())
}

/// Two transactions, field by field.
fn compare_cmd(args: &[&str]) -> Result<(), String> {
    let words = positional(args);
    let path = words.first().copied().ok_or("compare needs a capture file")?;
    let ids: Vec<u64> = words[1..].iter()
        .filter_map(|w| w.parse().ok()).collect();
    if ids.len() != 2 {
        return Err("compare needs two transaction ids".into());
    }

    let cap = open(path)?;
    let (_, _, decoded) = decode_with(&cap, args)?;
    let find = |id: u64| decoded.transactions.iter().find(|t| t.id == id)
        .ok_or_else(|| format!("no transaction #{id}; there are {}",
                               decoded.transactions.len()));
    let a = find(ids[0])?;
    let b = find(ids[1])?;

    let c = measure::compare(a, b);
    println!("#{} {} {}", a.id, a.kind, a.summary);
    println!("#{} {} {}", b.id, b.kind, b.summary);
    println!();
    if let Some(why) = &c.why_not {
        println!("not directly comparable: {why}");
        println!();
    }
    if c.identical_content() {
        println!("every field is the same; only the timing differs");
    }
    println!("{:<16} {:>18} {:>18}", "field", format!("#{}", a.id),
             format!("#{}", b.id));
    for f in &c.fields {
        let mark = if f.differs() { "*" } else { " " };
        println!("{mark}{:<15} {:>18} {:>18}", f.name,
                 f.a.clone().unwrap_or_else(|| "-".into()),
                 f.b.clone().unwrap_or_else(|| "-".into()));
    }
    if let Some((x, y)) = &c.severity {
        println!("*{:<15} {:>18} {:>18}", "severity", x, y);
    }
    if let Some((x, y)) = &c.errors {
        println!("*{:<15} {:>18} {:>18}", "errors",
                 if x.is_empty() { "-".into() } else { x.join(",") },
                 if y.is_empty() { "-".into() } else { y.join(",") });
    }
    println!(" {:<15} {:>18} {:>18}", "length",
             measure::human_time(c.duration.0),
             measure::human_time(c.duration.1));
    Ok(())
}

/// What one transaction was, from its own fields.
fn explain_cmd(args: &[&str]) -> Result<(), String> {
    let words = positional(args);
    let path = words.first().copied().ok_or("explain needs a capture file")?;
    let id: u64 = words.get(1).copied()
        .ok_or("explain needs a transaction id")?
        .parse().map_err(|_| "the transaction id has to be a number")?;

    let cap = open(path)?;
    let (_, _, decoded) = decode_with(&cap, args)?;
    let t = decoded.transactions.iter().find(|t| t.id == id)
        .ok_or_else(|| format!("no transaction #{id}; there are {}",
                               decoded.transactions.len()))?;

    for line in measure::explain(t) {
        println!("{:<9} {}", line.kind, line.text);
    }
    Ok(())
}

/// Add a named marker to a capture, or list the ones it has.
///
/// Bookmarks belong in the file rather than in a sidecar: section 7 wants them
/// synchronized with the overview strip and carried into exports, and the
/// capture container already has an annotation record for exactly this. A
/// sidecar would be a second place for them to disagree.
fn bookmark(args: &[&str]) -> Result<(), String> {
    let words = positional(args);
    let path = words.first().copied().ok_or("bookmark needs a capture file")?;
    let cap = open(path)?;

    if flag(args, "--list") || words.len() < 2 {
        if cap.annotations.is_empty() {
            println!("no bookmarks in {path}");
        }
        for (n, a) in cap.annotations.iter().enumerate() {
            println!("  {n}  {:.3} us  {}{}", a.start as f64 / 1_000_000.0,
                     a.label,
                     if a.note.is_empty() { String::new() }
                     else { format!("  - {}", a.note) });
        }
        return Ok(());
    }

    let label = words[1..].join(" ");
    let (first, _) = cap.span();
    let micros = |name: &str, fallback: u64| -> Result<u64, String> {
        match option(args, name) {
            None => Ok(fallback),
            Some(v) => {
                let us: f64 = v.parse()
                    .map_err(|_| format!("{name} wants microseconds, not {v:?}"))?;
                Ok((us * 1_000_000.0) as u64)
            }
        }
    };
    let start = micros("--at", first)?;
    let end = micros("--to", start)?;

    let mut annotations = cap.annotations.clone();
    annotations.push(file::Annotation {
        start,
        end,
        label: label.clone(),
        note: option(args, "--note").unwrap_or("").to_string(),
    });

    // Rewritten through the same writer everything else uses, decode and all,
    // so a bookmark cannot cost the file its cached decode.
    let decoded = if cap.decoded.transactions.is_empty() {
        None
    } else {
        cap.decoders.first().map(|info| (info, &cap.decoded))
    };
    write_capture_with(Path::new(path), &cap.session, &cap.chunks, &cap.gaps,
                       decoded, &annotations)?;
    println!("added {label:?} at {:.3} us; {path} now has {} bookmark(s)",
             start as f64 / 1_000_000.0, annotations.len());
    Ok(())
}

fn replay(args: &[&str]) -> Result<(), String> {
    let files = positional(args);
    let a = files.first().copied().ok_or("replay needs a capture file")?;

    let cap_a = open(a)?;
    let first = decode_of(&cap_a).1;
    let second = decode_of(&cap_a).1;

    if first != second {
        return Err(format!(
            "{a} decoded differently on two runs of the same build. \
             Replay determinism is an acceptance criterion, so this is a bug."));
    }
    println!("{a}: decoded twice, identical - {} transaction(s)",
             first.transactions.len());

    if let Some(b) = files.get(1) {
        let cap_b = open(b)?;
        let other = decode_of(&cap_b).1;
        if first == other {
            println!("{b}: identical to {a}");
        } else {
            println!("{b}: differs from {a}");
            report_difference(&first, &other);
            return Err("the two captures do not decode alike".into());
        }
    }
    Ok(())
}

fn report_difference(a: &Decoded, b: &Decoded) {
    if a.transactions.len() != b.transactions.len() {
        println!("  {} transaction(s) against {}",
                 a.transactions.len(), b.transactions.len());
    }
    for (i, (x, y)) in a.transactions.iter().zip(&b.transactions).enumerate() {
        if x != y {
            println!("  first difference at #{i}:");
            println!("    {} {} {}", x.id, x.kind, x.summary);
            println!("    {} {} {}", y.id, y.kind, y.summary);
            return;
        }
    }
}

/// Appendix D, run start to finish.
///
/// Each step prints what it proved. It is a demo and a test at once: every
/// step that can fail returns an error, so this doubles as the end-to-end
/// regression the specification's exit criteria ask for.
fn demo(args: &[&str]) -> Result<(), String> {
    let dir = PathBuf::from(positional(args).first().copied().unwrap_or("."));
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let clean = dir.join("demo.cap");
    let holed = dir.join("demo-gap.cap");

    let step = |n: u32, what: &str| println!("\n{n}. {what}");

    step(1, "capture two channels and save a versioned capture file");
    let built = simulator::build("demo", 100_000).unwrap();
    write_capture(&clean, &built.session, &built.chunks, &built.gaps, None)?;
    println!("   {} -> {} transitions", clean.display(),
             built.chunks[0].transitions());

    step(2, "reopen the file and decode a known I2C transaction set");
    let cap = open(clean.to_str().unwrap())?;
    let (info, decoded) = decode_of(&cap);
    println!("   {} transaction(s) from {} {}",
             decoded.transactions.len(), info.name, info.version);
    if decoded.transactions.is_empty() {
        return Err("the demo capture decoded to nothing".into());
    }

    step(3, "show raw SDA/SCL with the decode under it");
    let first = &decoded.transactions[0];
    show::waveform(&cap, &decoded, first.start, first.end, 90);

    step(4, "select a transaction and see its fields, each with a sample range");
    println!("   #{} {} {}", first.id, first.kind, first.summary);
    for f in &first.fields {
        println!("      {:<12} {:<8} at {:.3} us, samples {}..{}",
                 f.name, f.display, f.start as f64 / 1_000_000.0,
                 f.samples.first, f.samples.last);
    }

    step(5, "run a protocol-native query and navigate the results");
    for text in ["addr:0x52", "addr:0x52 error:any", "type:READ"] {
        let q = query::parse(text).map_err(|e| e.to_string())?;
        let hits = q.run(&decoded);
        println!("   {:<24} {} hit(s){}", text, hits.len(),
                 match hits.first() {
                     Some(t) => format!(": #{} {}", t.id, t.summary),
                     None => String::new(),
                 });
    }

    step(6, "inject packet loss and show an explicit gap");
    let holed_built = simulator::build_with_gap("demo", 100_000).unwrap();
    write_capture(&holed, &holed_built.session, &holed_built.chunks,
                  &holed_built.gaps, None)?;
    let holed_cap = open(holed.to_str().unwrap())?;
    let (_, holed_decoded) = decode_of(&holed_cap);
    let gaps = holed_cap.gaps.len();
    let flagged = holed_decoded.transactions.iter()
        .filter(|t| t.errors.iter().any(|e| matches!(e, schema::ErrorKind::GapOverlap)))
        .count();
    println!("   {} -> {gaps} gap record(s); {flagged} transaction(s) marked \
              incomplete because of them", holed.display());
    if gaps == 0 {
        return Err("a gap was injected and none was recorded".into());
    }

    step(7, "replay: the same capture decodes identically");
    let again = decode_of(&cap).1;
    if again != decoded {
        return Err("the same capture decoded differently on a second pass".into());
    }
    println!("   identical transaction ids and fields on both passes");

    step(8, "export as JSON and CSV with raw timestamp references");
    let json = dir.join("demo.json");
    let csv = dir.join("demo.csv");
    std::fs::write(&json, serde_json::to_string_pretty(&decoded)
                   .map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut rows = String::from(
        "id,bus,protocol,start_ps,end_ps,kind,severity,complete,\
         chunk,first_sample,last_sample,errors,summary\n");
    for t in &decoded.transactions {
        rows.push_str(&format!("{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
            t.id, t.bus.0, t.protocol.as_str(), t.start, t.end, t.kind,
            t.severity.as_str(), t.complete, t.samples.chunk,
            t.samples.first, t.samples.last,
            t.errors.iter().map(|e| e.as_str()).collect::<Vec<_>>().join("|"),
            csv_quote(&t.summary)));
    }
    std::fs::write(&csv, rows).map_err(|e| e.to_string())?;
    println!("   {} and {}", json.display(), csv.display());

    println!("\nall eight steps passed.");
    Ok(())
}

/// Used by the demo's summary line and by tests.
#[allow(dead_code)]
fn worst(decoded: &Decoded) -> Severity {
    decoded.transactions.iter().map(|t| t.severity).max().unwrap_or(Severity::Info)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An option that takes a value must swallow it. Forgetting to declare
    /// one here does not fail loudly - the value becomes a search term, and
    /// `--limit 2` quietly searched for "2".
    #[test]
    fn value_taking_options_do_not_leak_into_the_query() {
        let args = ["cap.cap", "type:WRITE", "--limit", "2", "--explain"];
        assert_eq!(positional(&args), vec!["cap.cap", "type:WRITE"]);
        assert_eq!(option(&args, "--limit"), Some("2"));
        assert!(flag(&args, "--explain"));

        let args = ["cap.cap", "before the fix", "--at", "12.5", "--note", "hi"];
        assert_eq!(positional(&args), vec!["cap.cap", "before the fix"]);
        assert_eq!(option(&args, "--at"), Some("12.5"));
        assert_eq!(option(&args, "--note"), Some("hi"));

        // A trigger condition is positional, so an option's value landing in
        // it turns the value into part of the condition - which is how
        // `--out clip.cap` became a condition nobody could mean.
        let args = ["cap.cap", "error:nack", "--out", "clip.cap",
                    "--before", "50"];
        assert_eq!(positional(&args), vec!["cap.cap", "error:nack"]);
        assert_eq!(option(&args, "--out"), Some("clip.cap"));
    }

    #[test]
    fn options_and_positionals_separate() {
        let args = ["out.cap", "--script", "demo", "--gap", "--hz", "400000"];
        assert_eq!(positional(&args), vec!["out.cap"]);
        assert_eq!(option(&args, "--script"), Some("demo"));
        assert_eq!(number(&args, "--hz", 1).unwrap(), 400_000);
        assert!(flag(&args, "--gap"));
        assert!(!flag(&args, "--self-test"));
    }

    /// A value that looks like a flag must still be taken as the value, or
    /// `--port --edges` silently captures from a board called "--edges".
    #[test]
    fn a_value_is_consumed_even_when_it_looks_like_a_flag() {
        let args = ["a.cap", "--port", "--odd", "--gap"];
        assert_eq!(option(&args, "--port"), Some("--odd"));
        assert_eq!(positional(&args), vec!["a.cap"]);
    }

    #[test]
    fn a_bad_number_is_reported_rather_than_defaulted() {
        let args = ["--hz", "fast"];
        assert!(number(&args, "--hz", 100).is_err());
    }

    #[test]
    fn csv_quoting_handles_commas_and_quotes() {
        assert_eq!(csv_quote("plain"), "plain");
        assert_eq!(csv_quote("a,b"), "\"a,b\"");
        assert_eq!(csv_quote("say \"hi\""), "\"say \"\"hi\"\"\"");
    }
}
