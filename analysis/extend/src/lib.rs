//! The extension host: device and application analysers, in Python.
//!
//! Section 8's pipeline is
//!
//! ```text
//! raw samples -> protocol decoder -> normalized transactions
//!             -> device analyzer -> application analyzer -> UI/search/export
//! ```
//!
//! and the two rules that shape everything here are in the same section: an
//! extension "should never need raw USB/capture access", and there is "no
//! direct GUI drawing API in v1; extensions return structured data and
//! presentation hints". So an extension is a program that reads transactions
//! and writes derived fields. That is all it can do, which is what makes it
//! safe to run somebody else's.
//!
//! # Why a subprocess rather than an embedded interpreter
//!
//! Section 8.2 asks for "CPU/time/memory limits and clear failure reporting".
//! An embedded interpreter shares the analyser's address space: an extension
//! that spins, allocates without bound, or segfaults in a C module takes the
//! window down with it, and no amount of API design prevents that. A
//! subprocess can be timed out and killed, its output can be capped, and its
//! crash is a report rather than a lost capture.
//!
//! It also means the extension API is a wire format instead of a binding, so
//! an extension can be written in anything that can read a line of JSON - and
//! the same format is what the CLI, the window and a future remote host all
//! speak.
//!
//! # The protocol
//!
//! One JSON object per line, in both directions.
//!
//! Host to extension, in order:
//!
//! ```text
//! {"hello": 1, "protocol": "i2c", "settings": {...}}
//! {"transaction": { ...the schema's transaction, verbatim... }}
//! ...one line per transaction, in capture order...
//! {"end": true}
//! ```
//!
//! Extension to host, any time, in any order:
//!
//! ```text
//! {"id": 12, "fields": [{"name": "cmis.page", "display": "0x11"}]}
//! {"id": 12, "label": "read temperature"}
//! {"id": 12, "warning": "page select without a following read"}
//! {"note": "anything at all, printed by the CLI as progress"}
//! ```
//!
//! Streaming and batch are the same thing seen from two ends: the host writes
//! every transaction and then closes its side, and an extension may answer as
//! it reads or wait until `end` and answer all at once. Section 8.2 asks for
//! both and this serves both without two code paths.
//!
//! Anything the host does not understand is ignored rather than fatal, so a
//! newer extension talking to an older host degrades instead of failing.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use schema::{Decoded, ErrorKind, Field, FieldKind, Severity};
use serde::{Deserialize, Serialize};

/// What an extension declares about itself.
///
/// Section 8.2: "Extension manifest declares supported protocols, required
/// settings, and searchable fields."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default)]
    pub about: String,
    /// Protocol names it can analyse, e.g. `["i2c"]`. Empty means any.
    #[serde(default)]
    pub protocols: Vec<String>,
    /// The program to run, argv style: `["python", "cmis.py"]`.
    pub command: Vec<String>,
    /// Settings it wants, with defaults. Passed through in the hello line, and
    /// overridable by the caller.
    #[serde(default)]
    pub settings: BTreeMap<String, String>,
    /// Fields it adds, so search can offer them before it has ever run.
    #[serde(default)]
    pub search_fields: Vec<SearchField>,
    /// How long it may take, in milliseconds. Section 8.2's time limit.
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    /// How much it may say, in bytes. An extension in a loop printing lines is
    /// the commonest way to exhaust memory, and it is not the host's job to
    /// buffer it.
    #[serde(default = "default_output_cap")]
    pub max_output_bytes: usize,

    /// Where it was loaded from. Filled in by the loader, not by the file.
    #[serde(skip)]
    pub dir: PathBuf,
}

fn default_version() -> String {
    "0.0.0".into()
}

fn default_timeout() -> u64 {
    10_000
}

fn default_output_cap() -> usize {
    8 * 1024 * 1024
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchField {
    pub name: String,
    #[serde(default)]
    pub help: String,
}

impl Manifest {
    /// Load one extension from its directory.
    pub fn load(dir: &Path) -> Result<Manifest, String> {
        let path = dir.join("extension.json");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        let mut manifest: Manifest = serde_json::from_str(&text)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if manifest.command.is_empty() {
            return Err(format!("{}: the manifest has no command to run",
                               path.display()));
        }
        manifest.dir = dir.to_path_buf();
        Ok(manifest)
    }

    /// Every extension in a directory of them.
    pub fn discover(root: &Path) -> Vec<Manifest> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(root) else { return found };
        let mut dirs: Vec<PathBuf> = entries.flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir())
            .collect();
        dirs.sort();
        for dir in dirs {
            // A directory that is not an extension is not an error - the
            // extensions folder is somewhere people put things.
            if let Ok(m) = Manifest::load(&dir) {
                found.push(m);
            }
        }
        found
    }

    pub fn handles(&self, protocol: schema::Protocol) -> bool {
        self.protocols.is_empty()
            || self.protocols.iter().any(|p| p.eq_ignore_ascii_case(protocol.as_str()))
    }
}

/// What one run produced.
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Transactions that gained at least one field, label or warning.
    pub touched: usize,
    pub fields_added: usize,
    pub labels: usize,
    pub warnings: usize,
    /// Lines the extension wanted a human to see.
    pub notes: Vec<String>,
    /// Lines the host could not use, with why. Never silent: an extension
    /// whose output is being dropped has to be able to find out.
    pub rejected: Vec<String>,
    /// Anything the extension wrote to stderr, which is where a Python
    /// traceback goes.
    pub stderr: String,
    pub took: Duration,
    /// True when the extension was killed for running over its time limit.
    pub timed_out: bool,
}

// ---------------------------------------------------------------------------
// The wire format
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct Hello<'a> {
    hello: u32,
    protocol: &'a str,
    settings: &'a BTreeMap<String, String>,
}

/// One thing an extension can say about a transaction.
#[derive(Debug, Default, Deserialize)]
struct Result_ {
    #[serde(default)]
    id: Option<u64>,
    #[serde(default)]
    fields: Vec<ResultField>,
    /// A semantic name for what the transaction was: "read temperature".
    #[serde(default)]
    label: Option<String>,
    #[serde(default)]
    warning: Option<String>,
    #[serde(default)]
    warnings: Vec<String>,
    /// A presentation hint, kept as a field so nothing in the UI has to know
    /// what an extension meant by it.
    #[serde(default)]
    severity: Option<String>,
    /// For grouping: this transaction is part of that one.
    #[serde(default)]
    parent: Option<u64>,
    /// Progress or commentary, not attached to any transaction.
    #[serde(default)]
    note: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ResultField {
    name: String,
    /// What to show. Required: only the extension knows how its value should
    /// read.
    display: String,
    #[serde(default)]
    value: Option<u64>,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    severity: Option<String>,
}

fn field_kind(name: Option<&str>) -> FieldKind {
    match name.unwrap_or("text").to_ascii_lowercase().as_str() {
        "address" => FieldKind::Address,
        "data" => FieldKind::Data,
        "flag" => FieldKind::Flag,
        "count" => FieldKind::Count,
        "duration" => FieldKind::Duration,
        _ => FieldKind::Text,
    }
}

fn severity(name: Option<&str>) -> Option<Severity> {
    match name.map(|s| s.to_ascii_lowercase()).as_deref() {
        Some("info") => Some(Severity::Info),
        Some("notice") => Some(Severity::Notice),
        Some("warning") | Some("warn") => Some(Severity::Warning),
        Some("error") => Some(Severity::Error),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Running one
// ---------------------------------------------------------------------------

/// Run an extension over a decode, adding what it says to the transactions.
///
/// `decoded` is modified in place. Nothing is removed and no existing field is
/// overwritten: an extension adds meaning to a decode, it does not get to
/// disagree with the decoder about what was on the wire. A field whose name
/// already exists is prefixed with the extension's name, so two extensions
/// cannot silently fight over `page` either.
pub fn run(
    manifest: &Manifest,
    protocol: schema::Protocol,
    decoded: &mut Decoded,
    overrides: &BTreeMap<String, String>,
) -> Result<Report, String> {
    let started = Instant::now();
    let mut report = Report::default();

    let mut settings = manifest.settings.clone();
    for (k, v) in overrides {
        settings.insert(k.clone(), v.clone());
    }

    let (program, args) = manifest.command.split_first()
        .ok_or("the manifest has no command to run")?;
    let mut child = Command::new(program)
        .args(args)
        .current_dir(&manifest.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {}: {e}", manifest.command.join(" ")))?;

    // The transactions go out on another thread. An extension that answers as
    // it reads would otherwise deadlock the host: both sides blocked, each
    // waiting for the other's pipe to drain.
    let mut stdin = child.stdin.take().ok_or("no stdin on the child")?;
    let hello = serde_json::to_string(&Hello {
        hello: 1,
        protocol: protocol.as_str(),
        settings: &settings,
    }).map_err(|e| e.to_string())?;
    let lines: Vec<String> = decoded.transactions.iter()
        .map(|t| serde_json::json!({ "transaction": t }).to_string())
        .collect();

    let writer = std::thread::spawn(move || {
        // Errors here are not fatal on their own: an extension is allowed to
        // stop reading once it has seen enough, and the broken pipe that
        // causes is not a failure of the run.
        let _ = writeln!(stdin, "{hello}");
        for line in lines {
            if writeln!(stdin, "{line}").is_err() {
                return;
            }
        }
        let _ = writeln!(stdin, "{}", serde_json::json!({"end": true}));
        let _ = stdin.flush();
    });

    // Read what it says, with a cap and a deadline.
    let stdout = child.stdout.take().ok_or("no stdout on the child")?;
    let deadline = Duration::from_millis(manifest.timeout_ms.max(1));
    let cap = manifest.max_output_bytes;

    let (tx, rx) = std::sync::mpsc::channel::<std::result::Result<String, String>>();
    let reader = std::thread::spawn(move || {
        let mut seen = 0usize;
        for line in BufReader::new(stdout).lines() {
            match line {
                Ok(line) => {
                    seen += line.len() + 1;
                    if seen > cap {
                        let _ = tx.send(Err(format!(
                            "the extension wrote more than {cap} bytes; the rest \
                             is ignored")));
                        return;
                    }
                    if tx.send(Ok(line)).is_err() {
                        return;
                    }
                }
                Err(e) => {
                    let _ = tx.send(Err(e.to_string()));
                    return;
                }
            }
        }
    });

    // Index by id once: an extension may answer in any order, and finding
    // each transaction by scanning would be quadratic on a long capture.
    let mut where_is: BTreeMap<u64, usize> = BTreeMap::new();
    for (i, t) in decoded.transactions.iter().enumerate() {
        where_is.insert(t.id, i);
    }

    let mut touched: std::collections::BTreeSet<u64> = Default::default();
    loop {
        let left = deadline.checked_sub(started.elapsed());
        let Some(left) = left else {
            report.timed_out = true;
            break;
        };
        match rx.recv_timeout(left) {
            Ok(Ok(line)) => {
                apply_line(&line, decoded, &where_is, &mut report, &mut touched,
                           &manifest.name);
            }
            Ok(Err(problem)) => {
                report.rejected.push(problem);
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                report.timed_out = true;
                break;
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    if report.timed_out {
        // Section 8.2's time limit, enforced rather than requested.
        let _ = child.kill();
    }
    let _ = writer.join();
    let _ = reader.join();

    let output = child.wait_with_output()
        .map_err(|e| format!("waiting for the extension: {e}"))?;
    report.stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    report.took = started.elapsed();
    report.touched = touched.len();

    if report.timed_out {
        return Err(format!(
            "{} ran for longer than its {} ms limit and was stopped; {} \
             transaction(s) had been enriched{}",
            manifest.name, manifest.timeout_ms, report.touched,
            if report.stderr.is_empty() { String::new() }
            else { format!("\n{}", report.stderr) }));
    }
    if !output.status.success() {
        return Err(format!(
            "{} exited with {}{}",
            manifest.name,
            output.status.code().map(|c| c.to_string())
                .unwrap_or_else(|| "a signal".into()),
            if report.stderr.is_empty() { String::new() }
            else { format!("\n{}", report.stderr) }));
    }

    Ok(report)
}

fn apply_line(
    line: &str,
    decoded: &mut Decoded,
    where_is: &BTreeMap<u64, usize>,
    report: &mut Report,
    touched: &mut std::collections::BTreeSet<u64>,
    extension: &str,
) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let parsed: Result_ = match serde_json::from_str(line) {
        Ok(p) => p,
        Err(e) => {
            // Kept, not swallowed: an extension printing debug to stdout is
            // the commonest mistake, and silence makes it a mystery.
            report.rejected.push(format!("{e}: {}", clip(line)));
            return;
        }
    };

    if let Some(note) = parsed.note {
        report.notes.push(note);
    }

    let Some(id) = parsed.id else {
        // A line with no id and no note says nothing about anything.
        if parsed.fields.is_empty() && parsed.label.is_none() {
            return;
        }
        report.rejected.push(format!("no transaction id: {}", clip(line)));
        return;
    };
    let Some(&index) = where_is.get(&id) else {
        report.rejected.push(format!("no transaction #{id} in this decode"));
        return;
    };
    let t = &mut decoded.transactions[index];

    for f in parsed.fields {
        // Namespaced on collision rather than overwriting: the decoder's
        // account of the wire wins, and two extensions cannot fight over a
        // name either.
        let name = if t.fields.iter().any(|existing| existing.name == f.name) {
            format!("{extension}.{}", f.name)
        } else {
            f.name
        };
        t.fields.push(Field {
            name,
            value: f.value,
            display: f.display,
            kind: field_kind(f.kind.as_deref()),
            // A derived field covers the transaction it was derived from: it
            // did not come from a narrower part of the wire, and pretending
            // otherwise would put a false highlight on the waveform.
            start: t.start,
            end: t.end,
            samples: t.samples,
            severity: severity(f.severity.as_deref()).unwrap_or(Severity::Info),
        });
        report.fields_added += 1;
        touched.insert(id);
    }

    if let Some(label) = parsed.label {
        // As a field rather than a rewritten summary: the summary is the
        // decoder's, and an extension that could rewrite it could hide what
        // was actually on the wire.
        t.fields.push(Field {
            name: format!("{extension}.what"),
            value: None,
            display: label,
            kind: FieldKind::Text,
            start: t.start,
            end: t.end,
            samples: t.samples,
            severity: Severity::Info,
        });
        report.labels += 1;
        report.fields_added += 1;
        touched.insert(id);
    }

    let warnings = parsed.warning.into_iter().chain(parsed.warnings);
    for w in warnings {
        t.errors.push(ErrorKind::Other(format!("{extension}: {w}")));
        if t.severity < Severity::Warning {
            t.severity = Severity::Warning;
        }
        report.warnings += 1;
        touched.insert(id);
    }

    if let Some(s) = severity(parsed.severity.as_deref()) {
        // Raised, never lowered: an extension must not be able to quieten a
        // decoder's finding.
        if t.severity < s {
            t.severity = s;
        }
        touched.insert(id);
    }

    if let Some(parent) = parsed.parent {
        if where_is.contains_key(&parent) && parent != id {
            t.parent = Some(parent);
            touched.insert(id);
        } else {
            report.rejected.push(format!(
                "#{id} cannot be part of #{parent}"));
        }
    }
}

fn clip(text: &str) -> String {
    if text.chars().count() <= 120 {
        text.to_string()
    } else {
        text.chars().take(117).collect::<String>() + "..."
    }
}

/// Where the shipped extensions live, if they can be found.
///
/// Beside the executable first, so an installed copy finds its own; then the
/// source tree, so a development build finds them without being installed.
pub fn extensions_dir() -> Option<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("extensions"));
            // target/debug/../../extensions
            if let Some(up) = dir.parent().and_then(|p| p.parent()) {
                candidates.push(up.join("extensions"));
            }
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("extensions"));
    }
    candidates.into_iter().find(|p| p.is_dir())
}

/// The searchable fields every discovered extension declares.
pub fn declared_fields(manifests: &[Manifest]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for m in manifests {
        for f in &m.search_fields {
            out.push((f.name.clone(), format!("{} ({})", f.help, m.name)));
        }
    }
    out
}

/// The transaction schema version an extension is written against.
///
/// Section 8.2 asks for a versioned transaction schema; this is that version,
/// sent in the hello line so an extension can refuse a schema it does not
/// understand rather than misreading it.
pub const SCHEMA_VERSION: u16 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    /// Python, however it is spelled here.
    fn python() -> String {
        for candidate in ["python", "python3", "py"] {
            if Command::new(candidate).arg("--version")
                .stdout(Stdio::null()).stderr(Stdio::null())
                .status().map(|s| s.success()).unwrap_or(false)
            {
                return candidate.to_string();
            }
        }
        panic!("the extension host runs Python extensions, and no python was \
                found on PATH");
    }

    /// Write a throwaway extension into a temporary directory.
    fn extension(name: &str, script: &str, extra: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sniffer-ext-{name}"));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("run.py"), script).unwrap();
        let manifest = format!(
            r#"{{"name": "{name}", "command": ["{}", "run.py"], "protocols": \
               ["i2c"] {extra} }}"#,
            python());
        // The manifest is JSON, so the line continuation above has to go.
        let manifest = manifest.replace("\\\n", "").replace("               ", "");
        std::fs::write(dir.join("extension.json"), manifest).unwrap();
        dir
    }

    fn demo() -> (schema::Protocol, Decoded) {
        let cap = simulator::build("demo", 1_000_000).unwrap();
        let protocol = registry::guess(&cap);
        let decoded = registry::decoder(protocol, &cap).decode(&cap);
        (protocol, decoded)
    }

    const ECHO_ADDRESS: &str = r#"
import json, sys

# Read the hello line, then a transaction per line, and name each one after
# the address it carried. The simplest possible device analyser.
hello = json.loads(sys.stdin.readline())
assert hello["hello"] == 1, hello
for line in sys.stdin:
    msg = json.loads(line)
    if "end" in msg:
        break
    t = msg["transaction"]
    address = None
    for f in t["fields"]:
        if f["name"] == "address":
            address = f["display"]
    if address is not None:
        print(json.dumps({"id": t["id"], "fields": [
            {"name": "device", "display": "module at " + address}]}))
        print(json.dumps({"id": t["id"], "label": "spoken to " + address}))
sys.stdout.flush()
"#;

    #[test]
    fn an_extension_adds_fields_to_the_transactions_it_recognises() {
        let dir = extension("echo", ECHO_ADDRESS, "");
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();

        let report = run(&manifest, protocol, &mut decoded, &BTreeMap::new())
            .expect("the extension should run");
        assert!(report.touched > 0, "nothing was enriched");
        assert_eq!(report.rejected, Vec::<String>::new(),
                   "the host dropped output it should have used");
        assert!(report.stderr.is_empty(), "stderr: {}", report.stderr);

        let first = &decoded.transactions[0];
        let device = first.fields.iter().find(|f| f.name == "device")
            .expect("the derived field is missing");
        assert!(device.display.contains("0x52"));
        assert!(first.fields.iter().any(|f| f.name == "echo.what"),
                "the label should arrive as a field of its own");
    }

    /// A derived field must not claim to come from a narrower part of the wire
    /// than the transaction it was derived from - the waveform highlight would
    /// be a lie.
    #[test]
    fn a_derived_field_points_at_the_whole_transaction() {
        let dir = extension("echo2", ECHO_ADDRESS, "");
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();
        run(&manifest, protocol, &mut decoded, &BTreeMap::new()).unwrap();

        let t = &decoded.transactions[0];
        let derived = t.fields.iter().find(|f| f.name == "device").unwrap();
        assert_eq!((derived.start, derived.end), (t.start, t.end));
        assert_eq!(derived.samples, t.samples);
    }

    const COLLIDE: &str = r#"
import json, sys
json.loads(sys.stdin.readline())
for line in sys.stdin:
    msg = json.loads(line)
    if "end" in msg:
        break
    t = msg["transaction"]
    # Deliberately reuse a name the decoder already used.
    print(json.dumps({"id": t["id"], "fields": [
        {"name": "address", "display": "not really"}]}))
sys.stdout.flush()
"#;

    /// The decoder's account of the wire wins. An extension reusing a field
    /// name gets namespaced, not obeyed.
    #[test]
    fn an_extension_cannot_overwrite_a_decoders_field() {
        let dir = extension("collide", COLLIDE, "");
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();
        run(&manifest, protocol, &mut decoded, &BTreeMap::new()).unwrap();

        let t = &decoded.transactions[0];
        let original = t.fields.iter().filter(|f| f.name == "address")
            .collect::<Vec<_>>();
        assert_eq!(original.len(), 1, "the decoder's field must stay unique");
        assert_eq!(original[0].display, "0x52", "and unchanged");
        assert!(t.fields.iter().any(|f| f.name == "collide.address"),
                "the extension's claim is kept, under its own name");
    }

    const WARN: &str = r#"
import json, sys
json.loads(sys.stdin.readline())
for line in sys.stdin:
    msg = json.loads(line)
    if "end" in msg:
        break
    t = msg["transaction"]
    print(json.dumps({"id": t["id"], "warning": "looks wrong to me"}))
sys.stdout.flush()
"#;

    #[test]
    fn a_warning_becomes_an_error_on_the_transaction_and_raises_its_severity() {
        let dir = extension("warn", WARN, "");
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();
        run(&manifest, protocol, &mut decoded, &BTreeMap::new()).unwrap();

        let t = &decoded.transactions[0];
        assert!(t.severity >= Severity::Warning);
        assert!(t.errors.iter().any(|e| e.as_str().contains("looks wrong")));
        assert!(t.errors.iter().any(|e| e.as_str().starts_with("warn:")),
                "an extension's finding says which extension found it");
    }

    const QUIETEN: &str = r#"
import json, sys
json.loads(sys.stdin.readline())
for line in sys.stdin:
    msg = json.loads(line)
    if "end" in msg:
        break
    t = msg["transaction"]
    print(json.dumps({"id": t["id"], "severity": "info"}))
sys.stdout.flush()
"#;

    /// Severity is raised, never lowered: an extension that could quieten a
    /// NACK would be a way to hide a fault.
    #[test]
    fn an_extension_cannot_quieten_a_decoders_finding() {
        let dir = extension("quieten", QUIETEN, "");
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();
        let before: Vec<Severity> = decoded.transactions.iter()
            .map(|t| t.severity).collect();
        run(&manifest, protocol, &mut decoded, &BTreeMap::new()).unwrap();
        let after: Vec<Severity> = decoded.transactions.iter()
            .map(|t| t.severity).collect();
        assert_eq!(before, after);
    }

    const SPIN: &str = r#"
import sys, time
sys.stdin.readline()
while True:
    time.sleep(0.05)
"#;

    /// Section 8.2's time limit. An extension that never finishes must be a
    /// report, not a hung window.
    #[test]
    fn an_extension_that_never_finishes_is_stopped_and_reported() {
        let dir = extension("spin", SPIN, r#", "timeout_ms": 700"#);
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();

        let started = Instant::now();
        let err = run(&manifest, protocol, &mut decoded, &BTreeMap::new())
            .expect_err("a spinning extension has to fail");
        assert!(err.contains("limit"), "unhelpful message: {err}");
        assert!(started.elapsed() < Duration::from_secs(5),
                "it took {:?} to give up", started.elapsed());
    }

    const FLOOD: &str = r#"
import json, sys
json.loads(sys.stdin.readline())
line = json.dumps({"id": 1, "fields": [{"name": "x", "display": "y" * 200}]})
for _ in range(100000):
    print(line)
sys.stdout.flush()
"#;

    /// And the output limit, for the same reason: an extension in a printing
    /// loop must not be able to exhaust the host's memory.
    #[test]
    fn an_extension_that_floods_its_output_is_cut_off() {
        let dir = extension("flood", FLOOD,
                            r#", "max_output_bytes": 20000, "timeout_ms": 8000"#);
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();

        // Either outcome is correct - cut off mid-run, or killed for the time
        // its flood took - and both must leave the host standing.
        match run(&manifest, protocol, &mut decoded, &BTreeMap::new()) {
            Ok(report) => assert!(report.rejected.iter()
                .any(|r| r.contains("more than")),
                "the cap should have been reported: {:?}", report.rejected),
            Err(e) => assert!(e.contains("limit") || e.contains("exited"),
                              "unexpected failure: {e}"),
        }
        // The fields that did arrive are on the transaction, not lost.
        assert!(decoded.transactions[0].fields.iter().any(|f| f.name == "x"));
    }

    const RUBBISH: &str = r#"
import json, sys
json.loads(sys.stdin.readline())
print("this is not json at all")
print(json.dumps({"id": 999999, "label": "no such transaction"}))
print(json.dumps({"note": "just saying"}))
sys.stdout.flush()
"#;

    /// Output the host cannot use is reported rather than swallowed: an
    /// extension printing debug to stdout is the commonest mistake there is.
    #[test]
    fn output_the_host_cannot_use_is_reported() {
        let dir = extension("rubbish", RUBBISH, "");
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();
        let report = run(&manifest, protocol, &mut decoded, &BTreeMap::new())
            .unwrap();

        assert_eq!(report.notes, vec!["just saying".to_string()]);
        assert_eq!(report.rejected.len(), 2, "{:?}", report.rejected);
        assert!(report.rejected.iter().any(|r| r.contains("not json")
                                            || r.contains("expected")));
        assert!(report.rejected.iter().any(|r| r.contains("999999")));
    }

    const CRASH: &str = r#"
import sys
sys.stdin.readline()
raise SystemExit("I cannot analyse this")
"#;

    #[test]
    fn a_crashing_extension_reports_what_it_said_before_it_died() {
        let dir = extension("crash", CRASH, "");
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();
        let err = run(&manifest, protocol, &mut decoded, &BTreeMap::new())
            .expect_err("a crash is a failure");
        assert!(err.contains("I cannot analyse this"),
                "the extension's own message has to reach the user: {err}");
    }

    const SETTINGS: &str = r#"
import json, sys
hello = json.loads(sys.stdin.readline())
print(json.dumps({"note": "page=" + str(hello["settings"].get("page"))}))
sys.stdout.flush()
"#;

    #[test]
    fn settings_come_from_the_manifest_and_the_caller_overrides_them() {
        let dir = extension("settings", SETTINGS,
                            r#", "settings": {"page": "0"}"#);
        let manifest = Manifest::load(&dir).unwrap();
        let (protocol, mut decoded) = demo();

        let report = run(&manifest, protocol, &mut decoded, &BTreeMap::new())
            .unwrap();
        assert_eq!(report.notes, vec!["page=0".to_string()]);

        let mut overrides = BTreeMap::new();
        overrides.insert("page".to_string(), "0x11".to_string());
        let report = run(&manifest, protocol, &mut decoded, &overrides).unwrap();
        assert_eq!(report.notes, vec!["page=0x11".to_string()]);
    }

    // ---- the shipped analysers -----------------------------------------

    /// The extensions directory in the source tree.
    fn shipped(name: &str) -> Manifest {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent().unwrap()          // analysis
            .parent().unwrap()          // sniffer
            .join("extensions")
            .join(name);
        Manifest::load(&dir).unwrap_or_else(|e| panic!("{name}: {e}"))
    }

    fn decode_script(script: &str, hz: u64) -> (schema::Protocol, Decoded) {
        let cap = simulator::build(script, hz).unwrap();
        let protocol = registry::guess(&cap);
        let decoded = registry::decoder(protocol, &cap).decode(&cap);
        (protocol, decoded)
    }

    fn derived<'a>(t: &'a schema::Transaction, name: &str) -> Option<&'a str> {
        t.fields.iter().find(|f| f.name == name).map(|f| f.display.as_str())
    }

    /// Section 8.1: "I2C transfer -> CMIS page/register analyzer -> field name
    /// + semantic value". The two bytes 0x1A 0x31 are 26.191 C, and the
    /// analyser has to say so.
    #[test]
    fn the_cmis_analyser_decodes_a_module_conversation() {
        let (protocol, mut decoded) = decode_script("optics", 100_000);
        let report = run(&shipped("cmis"), protocol, &mut decoded,
                         &BTreeMap::new()).unwrap();
        assert!(report.stderr.is_empty(), "stderr: {}", report.stderr);
        assert_eq!(report.rejected, Vec::<String>::new());

        let temperature = decoded.transactions.iter()
            .find_map(|t| derived(t, "cmis.temperature"))
            .expect("no temperature was decoded");
        assert_eq!(temperature, "26.191 C");

        let voltage = decoded.transactions.iter()
            .find_map(|t| derived(t, "cmis.voltage"))
            .expect("no voltage was decoded");
        assert_eq!(voltage, "3.2820 V");

        let identifier = decoded.transactions.iter()
            .find_map(|t| derived(t, "cmis.identifier"))
            .expect("no identifier was decoded");
        assert_eq!(identifier, "QSFP-DD");
    }

    /// And the refusal, which matters more than the decode: a register in an
    /// upper page nobody selected must not be given a name.
    #[test]
    fn the_cmis_analyser_will_not_name_a_register_it_cannot_know() {
        let (protocol, mut decoded) = decode_script("optics", 100_000);
        run(&shipped("cmis"), protocol, &mut decoded, &BTreeMap::new()).unwrap();

        // The optics script ends with a read at 0x51, which never had a page
        // selected.
        let unknown: Vec<&schema::Transaction> = decoded.transactions.iter()
            .filter(|t| derived(t, "cmis.device")
                .map(|d| d.contains("0x51")).unwrap_or(false))
            .collect();
        assert_eq!(unknown.len(), 2, "the script has two transfers to 0x51");
        for t in unknown {
            assert!(derived(t, "cmis.field").is_none(),
                    "it named a register in a page nobody selected");
            assert!(t.errors.iter().any(|e| e.as_str().contains("page")),
                    "and it has to say why it did not");
        }
    }

    /// Section 8.1: "MDIO C45 read -> PHY register database -> symbolic
    /// register and decoded bits".
    #[test]
    fn the_phy_analyser_names_registers_and_decodes_their_bits() {
        let (protocol, mut decoded) = decode_script("mdio", 1_000_000);
        let report = run(&shipped("phy"), protocol, &mut decoded,
                         &BTreeMap::new()).unwrap();
        assert!(report.stderr.is_empty(), "stderr: {}", report.stderr);

        // The mdio script reads BMSR (register 1) with 0x796D in it: link up
        // and autonegotiation complete.
        let bmsr = decoded.transactions.iter()
            .find(|t| derived(t, "phy.link").is_some())
            .expect("BMSR was not recognised");
        assert_eq!(derived(bmsr, "phy.link"), Some("up"));
        assert_eq!(derived(bmsr, "phy.autoneg"), Some("complete"));
        assert!(derived(bmsr, "phy.register").unwrap().starts_with("BMSR"));

        // And BMCR, written as 0x1200: autonegotiation enabled and restarted.
        let bmcr = decoded.transactions.iter()
            .find(|t| derived(t, "phy.control").is_some())
            .expect("BMCR was not recognised");
        let control = derived(bmcr, "phy.control").unwrap();
        assert!(control.contains("autonegotiation enable"), "{control}");
        assert!(control.contains("restart"), "{control}");
    }

    /// Section 8.1: "CAN frame -> DBC analyzer -> named signals and
    /// engineering units". 0xDEAD little-endian at 0.25 rpm a count.
    #[test]
    fn the_dbc_analyser_turns_a_frame_into_engineering_units() {
        let (protocol, mut decoded) = decode_script("can", 500_000);
        let report = run(&shipped("dbc"), protocol, &mut decoded,
                         &BTreeMap::new()).unwrap();
        assert!(report.stderr.is_empty(), "stderr: {}", report.stderr);

        let engine = decoded.transactions.iter()
            .find(|t| derived(t, "dbc.message") == Some("EngineData"))
            .expect("0x123 is in the database");
        // DE AD BE EF: EngineSpeed is bytes 0 and 1 little-endian, 0xADDE
        // counts of 0.25 rpm.
        assert_eq!(derived(engine, "dbc.EngineSpeed"), Some("11127.5 rpm"));
        // CoolantTemp is byte 2, offset -40: 0xBE is 190, so 150 C.
        assert_eq!(derived(engine, "dbc.CoolantTemp"), Some("150 C"));
        // Both are outside the database's stated range, and saying so is the
        // point of having the range in the database.
        assert!(engine.errors.iter().any(|e| e.as_str().contains("above its")),
                "the out-of-range signals were not reported");

        // An id the database does not know gets named as unknown, not guessed.
        let unknown = decoded.transactions.iter()
            .find(|t| derived(t, "dbc.message") == Some("not in the database"))
            .expect("0x000 is not in the database");
        assert!(unknown.fields.iter().all(|f| !f.name.starts_with("dbc.Engine")),
                "it decoded signals for a message it does not have");
    }

    /// A remote frame asks for a message and carries no payload. Decoding
    /// signals out of it produced three warnings per frame about data that
    /// was never meant to be there.
    #[test]
    fn the_dbc_analyser_does_not_read_signals_out_of_a_remote_frame() {
        let (protocol, mut decoded) = decode_script("can", 500_000);
        run(&shipped("dbc"), protocol, &mut decoded, &BTreeMap::new()).unwrap();

        let remote = decoded.transactions.iter()
            .find(|t| t.kind == "REMOTE")
            .expect("the can script sends a remote frame");
        assert!(derived(remote, "dbc.request").is_some(),
                "a remote frame should be reported as a request");
        assert!(!remote.errors.iter().any(|e| e.as_str().contains("past the end")),
                "it tried to read signals out of a frame with no payload");
    }

    /// Every shipped extension has to load, name its protocols, and declare
    /// the fields it adds - the manifest is what search offers before an
    /// extension has ever run.
    #[test]
    fn every_shipped_extension_declares_itself_properly() {
        for name in ["cmis", "phy", "dbc"] {
            let m = shipped(name);
            assert_eq!(m.name, name);
            assert!(!m.protocols.is_empty(), "{name} handles everything?");
            assert!(!m.search_fields.is_empty(),
                    "{name} adds fields but declares none");
            assert!(!m.about.is_empty(), "{name} does not say what it is");
            assert!(m.timeout_ms > 0);
            for f in &m.search_fields {
                assert!(f.name.contains('.'),
                        "{name} declares {:?}, which would collide with a \
                         decoder's own field name", f.name);
                assert!(!f.help.is_empty(), "{name}: {:?} has no help", f.name);
            }
        }
    }

    #[test]
    fn a_manifest_without_a_command_is_refused_rather_than_run() {
        let dir = std::env::temp_dir().join("sniffer-ext-nocommand");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("extension.json"),
                       r#"{"name": "broken", "command": []}"#).unwrap();
        let err = Manifest::load(&dir).expect_err("it has nothing to run");
        assert!(err.contains("no command"));
    }

    #[test]
    fn an_extension_declares_which_protocols_it_handles() {
        let dir = extension("only-i2c", ECHO_ADDRESS, "");
        let m = Manifest::load(&dir).unwrap();
        assert!(m.handles(schema::Protocol::I2c));
        assert!(!m.handles(schema::Protocol::Can));

        // An empty list means "anything", which is what an application-level
        // analyser wants.
        let dir = extension("any", ECHO_ADDRESS, r#", "x": 1"#);
        let mut m = Manifest::load(&dir).unwrap();
        m.protocols.clear();
        assert!(m.handles(schema::Protocol::Can));
    }
}
