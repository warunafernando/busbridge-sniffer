//! The desktop analyser.
//!
//! Phase 4 of the specification: a device and capture toolbar, a bus and
//! channel pane, a timeline with raw waveforms and decode bubbles, pan and
//! zoom, and a data table and inspector that stay in step with it.
//!
//! # One implementation, three front ends
//!
//! Nothing here decodes anything. The registry picks the decoder, the decoder
//! crates do the work, the search crate runs the filter box, and all three are
//! the same code the CLI runs - which is what the acceptance criteria mean by
//! the CLI, the GUI and the API sharing one implementation. A GUI with its own
//! quick version of a decoder is how a product ends up with two answers to the
//! same question.
//!
//! # What this window is for
//!
//! Section 1's core principle: the raw data stays visible and trustworthy, and
//! decoding is a layer on top of it that can always be checked. So the
//! waveform is the brightest thing on screen, every decoded field can be
//! clicked back to the samples it came from, and a gap in the capture is drawn
//! across the whole height rather than mentioned in a status bar.

#![forbid(unsafe_code)]

mod inspector;
mod overview;
mod source;
mod style;
mod table;
mod timeline;
mod workspace;

use eframe::egui;
use egui::RichText;

use schema::{Decoded, Picos, Protocol};

use source::{Loaded, Settings};
use style::Palette;
use timeline::View;
use workspace::Workspace;

/// How many result rows the table holds at once.
///
/// A burst capture produces a few thousand transactions, so this is never
/// reached in practice - it is the bound that keeps a large imported capture
/// from turning one keystroke in the filter box into a full intersection.
/// When it is hit the header says so rather than pretending the rest do not
/// exist.
const ROW_CAP: usize = 5_000;

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{USAGE}");
        return Ok(());
    }

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1360.0, 860.0])
            .with_min_inner_size([900.0, 560.0])
            .with_title("Sniffer"),
        ..Default::default()
    };

    eframe::run_native(
        "sniffer-ui",
        options,
        Box::new(|cc| {
            style::install(&cc.egui_ctx);
            Ok(Box::new(App::new(&args)))
        }),
    )
}

const USAGE: &str = "\
sniffer-ui - the desktop analyser

  sniffer-ui [capture.cap]
  sniffer-ui --simulate <script>
  sniffer-ui --capture [--port COM7] [--self-test]
  sniffer-ui <capture.cap> --filter 'error:any'

With no arguments it opens empty; use the toolbar to load a capture,
simulate one, or capture from a board.";

/// Which side panel the left column is showing.
#[derive(PartialEq, Eq, Clone, Copy)]
enum LeftPane {
    Session,
    Open,
}

struct App {
    palette: Palette,
    loaded: Option<Loaded>,
    settings: Settings,

    view: View,
    /// One per channel; a channel switched off is not drawn.
    visible: Vec<bool>,
    selected: Option<u64>,
    /// Set for one frame when the selection changed away from the table, so
    /// the table scrolls to it rather than fighting the user's scrolling.
    scroll_table_to: Option<u64>,

    query_text: String,
    query: Option<search::Query>,
    query_error: Option<String>,
    rows: Vec<usize>,
    /// True when the filter matched more rows than the table is holding.
    rows_truncated: bool,
    /// Postings for the current decode, rebuilt whenever it changes.
    index: Option<search::Index>,
    /// Where we are in `rows`, for next and previous result.
    result_at: Option<usize>,

    /// The device and application analysers that were found on disk.
    extensions: Vec<extend::Manifest>,
    /// Which of them have been applied to the decode on screen.
    applied: Vec<String>,
    analyse_job: Option<source::AnalyseJob>,

    workspace: Workspace,
    /// The name to save the current query under.
    save_query_as: String,
    /// The label for the next bookmark.
    bookmark_label: String,
    /// The last time the pointer was over the timeline: where a bookmark or a
    /// measurement cursor goes.
    cursor: Option<Picos>,
    /// The A and B measurement cursors.
    cursors: measure::Cursors,

    /// What the trigger builder currently says.
    trigger_text: String,
    /// The parsed condition, or why it will not parse.
    trigger: Option<trigger::Condition>,
    trigger_error: Option<String>,
    /// Where it matched, in time order.
    trigger_hits: Vec<trigger::Match>,
    /// How many bursts a monitor run should take.
    monitor_rounds: String,
    /// A transaction held aside to compare the selection against.
    pinned: Option<u64>,

    left: LeftPane,
    browse_dir: std::path::PathBuf,
    path_text: String,
    save_text: String,

    script: String,
    script_hz: String,

    port: String,
    burst: source::BurstRequest,
    burst_ms_text: String,
    burst_edges_text: String,
    job: Option<source::Job>,

    status: String,
    status_bad: bool,
}

impl App {
    fn new(args: &[String]) -> Self {
        let mut app = App {
            palette: Palette::dark(),
            loaded: None,
            settings: Settings::default(),
            view: View { start: 0, end: 1_000_000 },
            visible: Vec::new(),
            selected: None,
            scroll_table_to: None,
            query_text: String::new(),
            query: None,
            query_error: None,
            rows: Vec::new(),
            rows_truncated: false,
            index: None,
            result_at: None,
            extensions: extend::extensions_dir()
                .map(|dir| extend::Manifest::discover(&dir))
                .unwrap_or_default(),
            applied: Vec::new(),
            analyse_job: None,
            workspace: Workspace::load(),
            save_query_as: String::new(),
            bookmark_label: String::new(),
            cursor: None,
            cursors: measure::Cursors::default(),
            trigger_text: String::new(),
            trigger: None,
            trigger_error: None,
            trigger_hits: Vec::new(),
            monitor_rounds: "5".into(),
            pinned: None,
            left: LeftPane::Session,
            browse_dir: Workspace::load().last_dir
                .filter(|d| d.is_dir())
                .or_else(|| source::likely_directories().first().cloned())
                .unwrap_or_else(|| std::path::PathBuf::from(".")),
            path_text: String::new(),
            save_text: "capture.cap".into(),
            script: "demo".into(),
            script_hz: "1000000".into(),
            port: String::new(),
            burst: source::BurstRequest::default(),
            burst_ms_text: "200".into(),
            burst_edges_text: "8192".into(),
            job: None,
            status: "Open a capture, simulate one, or capture from a board.".into(),
            status_bad: false,
        };

        // The arguments are the same three ways in that the toolbar offers, so
        // a capture can be opened straight from a shell or a file manager.
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--simulate" => {
                    if let Some(name) = args.get(i + 1) {
                        app.script = name.clone();
                        app.do_simulate();
                        i += 1;
                    }
                }
                "--capture" => app.start_burst(),
                "--self-test" => {
                    app.burst.self_test = true;
                    app.start_burst();
                }
                "--port" => {
                    if let Some(p) = args.get(i + 1) {
                        app.port = p.clone();
                        i += 1;
                    }
                }
                "--filter" => {
                    if let Some(q) = args.get(i + 1) {
                        // After whatever was loaded, so the rows are filtered
                        // rather than the filter being cleared by the load.
                        app.set_query(q.clone());
                        i += 1;
                    }
                }
                other if !other.starts_with('-') => {
                    app.open_path(std::path::Path::new(other));
                }
                _ => {}
            }
            i += 1;
        }
        app
    }

    // ---- loading ----------------------------------------------------------

    fn open_path(&mut self, path: &std::path::Path) {
        match source::open_file(path, &self.settings) {
            Ok(loaded) => {
                if let Some(dir) = path.parent() {
                    if dir.is_dir() {
                        self.browse_dir = dir.to_path_buf();
                        self.workspace.last_dir = Some(dir.to_path_buf());
                    }
                }
                self.workspace.opened(path);
                self.workspace.save();
                self.adopt(loaded);
                self.left = LeftPane::Session;
            }
            Err(e) => self.fail(e),
        }
    }

    fn do_simulate(&mut self) {
        let hz: u64 = self.script_hz.trim().parse().unwrap_or(1_000_000);
        let script = self.script.clone();
        match source::simulate(&script, hz, &mut self.settings) {
            Ok(loaded) => self.adopt(loaded),
            Err(e) => self.fail(e),
        }
    }

    fn start_burst(&mut self) {
        if self.job.is_some() {
            return;
        }
        self.burst.settle_ms = self.burst_ms_text.trim().parse().unwrap_or(200);
        self.burst.max_edges = self.burst_edges_text.trim().parse().unwrap_or(8192);
        let port = match self.port.trim() {
            "" => None,
            p => Some(p.to_string()),
        };
        let job = source::Job::burst(port, self.burst);
        self.status = format!("{}...", job.what);
        self.status_bad = false;
        self.job = Some(job);
    }

    fn adopt(&mut self, loaded: Loaded) {
        let (first, last) = loaded.capture.span();
        self.view = View::fit(first, last);
        self.visible = vec![true; loaded.capture.session.channels.len()];
        self.selected = None;
        self.scroll_table_to = None;
        self.status = format!(
            "{}: {} transitions, {} transactions, {}",
            loaded.name,
            loaded.capture.chunks.iter().map(|c| c.transitions()).sum::<usize>(),
            loaded.decoded.transactions.len(),
            style::duration_label(last.saturating_sub(first)));
        if let Some(at) = loaded.capture.truncated_at {
            self.status.push_str(&format!(
                "  - truncated at byte {at}; everything before it was read"));
        }
        self.status_bad = false;
        self.applied.clear();
        self.loaded = Some(loaded);
        self.reindex();

        // The trigger is about this capture, so it is re-evaluated against
        // the new one rather than left showing matches from the last.
        if self.trigger.is_some() {
            let text = self.trigger_text.clone();
            self.set_trigger(text);
        }
    }

    fn fail(&mut self, message: String) {
        self.status = message;
        self.status_bad = true;
    }

    /// Decode again with the current settings, keeping the view where it is.
    fn redecode(&mut self) {
        let Some(loaded) = self.loaded.as_mut() else { return };
        let (protocol, info, decoded, guessed) =
            source::decode(&loaded.capture, &self.settings);
        loaded.protocol = protocol;
        loaded.info = info;
        loaded.decoded = decoded;
        loaded.guessed = guessed;
        self.selected = None;
        self.applied.clear();
        self.status = format!("decoded as {}: {} transactions",
                              protocol.as_str(),
                              loaded.decoded.transactions.len());
        self.status_bad = false;
        self.reindex();
    }

    /// Rebuild the postings for the decode, then the visible rows.
    ///
    /// Once per decode, not per keystroke: the index is what makes each
    /// keystroke cheap, so building it per keystroke would be exactly wrong.
    fn reindex(&mut self) {
        self.index = self.loaded.as_ref().map(|l| search::Index::build(&l.decoded));
        self.refilter();
    }

    /// Run an extension over the decode on screen.
    fn analyse(&mut self, manifest: extend::Manifest) {
        if self.analyse_job.is_some() {
            return;
        }
        let Some(loaded) = self.loaded.as_ref() else { return };
        let job = source::AnalyseJob::start(
            manifest, loaded.protocol, loaded.decoded.clone(),
            Default::default());
        self.status = format!("{}...", job.what);
        self.status_bad = false;
        self.analyse_job = Some(job);
    }

    /// The analysers worth offering for what is on screen.
    fn usable_extensions(&self) -> Vec<extend::Manifest> {
        let Some(loaded) = self.loaded.as_ref() else { return Vec::new() };
        self.extensions.iter()
            .filter(|m| m.handles(loaded.protocol))
            .cloned()
            .collect()
    }

    fn refilter(&mut self) {
        self.result_at = None;
        self.rows_truncated = false;
        let Some(loaded) = self.loaded.as_ref() else {
            self.rows.clear();
            return;
        };

        self.rows = match (&self.index, &self.query) {
            // Planned against the postings, stopping at the cap: the first
            // page costs the first page. Section 6.2.
            (Some(index), Some(q)) => index.page(q, &loaded.decoded, 0, ROW_CAP),
            (_, None) => (0..loaded.decoded.transactions.len().min(ROW_CAP))
                .collect(),
            // No index yet, which only happens before the first decode.
            (None, Some(q)) => table::filter(&loaded.decoded, Some(q)),
        };
        self.rows_truncated = self.rows.len() >= ROW_CAP;
    }

    fn set_query(&mut self, text: String) {
        self.query_text = text;
        if self.query_text.trim().is_empty() {
            self.query = None;
            self.query_error = None;
        } else {
            match search::parse(&self.query_text) {
                Ok(q) => {
                    self.query = Some(q);
                    self.query_error = None;
                }
                Err(e) => {
                    // The old filter stays in force while the new one is being
                    // typed, so the table does not empty itself between
                    // keystrokes.
                    self.query_error = Some(e.to_string());
                }
            }
        }
        self.refilter();
    }

    fn decoded(&self) -> Option<&Decoded> {
        self.loaded.as_ref().map(|l| &l.decoded)
    }

    fn select(&mut self, id: Option<u64>, from_table: bool) {
        self.selected = id;
        if !from_table {
            self.scroll_table_to = id;
        }
    }

    fn zoom_to_transaction(&mut self, id: u64) {
        let Some(d) = self.decoded() else { return };
        if let Some(t) = d.transactions.iter().find(|t| t.id == id) {
            self.view = View::fit(t.start, t.end);
        }
    }

    fn fit_all(&mut self) {
        if let Some(loaded) = self.loaded.as_ref() {
            let (first, last) = loaded.capture.span();
            self.view = View::fit(first, last);
        }
    }

    // ---- panels -----------------------------------------------------------

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.selectable_label(self.left == LeftPane::Open, "Open").clicked() {
                self.left = if self.left == LeftPane::Open {
                    LeftPane::Session
                } else {
                    LeftPane::Open
                };
            }

            ui.separator();

            // ---- simulate ----
            egui::ComboBox::from_id_salt("script")
                .selected_text(self.script.clone())
                .width(110.0)
                .show_ui(ui, |ui| {
                    for s in simulator::SCRIPTS {
                        if ui.selectable_label(self.script == s.name, s.name)
                            .on_hover_text(format!("{} - {}", s.protocol.as_str(),
                                                   s.about))
                            .clicked()
                        {
                            self.script = s.name.to_string();
                        }
                    }
                });
            if ui.button("Simulate")
                .on_hover_text("Generate this script's traffic. Deterministic: \
                                the same script gives the same edges every time.")
                .clicked()
            {
                self.do_simulate();
            }

            ui.separator();

            // ---- board ----
            ui.label(RichText::new("board").small().color(self.palette.dim));
            ui.add(egui::TextEdit::singleline(&mut self.port)
                .hint_text("port").desired_width(64.0));
            ui.add(egui::TextEdit::singleline(&mut self.burst_ms_text)
                .desired_width(44.0))
                .on_hover_text("How long to watch the bus, in milliseconds. \
                                A burst: the board's ring holds 8192 edges.");
            let busy = self.job.is_some();
            ui.add_enabled_ui(!busy, |ui| {
                if ui.button("Capture").clicked() {
                    self.burst.self_test = false;
                    self.start_burst();
                }
                if ui.button("Self test")
                    .on_hover_text("The board drives a known pattern on its own \
                                    taps and captures it. With nothing wired to \
                                    the headers this is the only way to get real \
                                    edges out of real hardware.")
                    .clicked()
                {
                    self.burst.self_test = true;
                    self.start_burst();
                }
            });
            if busy {
                ui.spinner();
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if self.loaded.is_some() {
                    ui.add(egui::TextEdit::singleline(&mut self.save_text)
                        .desired_width(140.0));
                    if ui.button("Save as").clicked() {
                        self.save();
                    }
                }
            });
        });
    }

    fn decode_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(RichText::new("decode as").small().color(self.palette.dim));
            let current = match self.settings.protocol {
                None => "auto".to_string(),
                Some(p) => p.as_str().to_string(),
            };
            let mut changed = false;
            egui::ComboBox::from_id_salt("protocol")
                .selected_text(current).width(84.0)
                .show_ui(ui, |ui| {
                    if ui.selectable_label(self.settings.protocol.is_none(),
                                           "auto")
                        .on_hover_text("Work it out from the capture's channel \
                                        names.")
                        .clicked()
                    {
                        self.settings.protocol = None;
                        changed = true;
                    }
                    for (p, what) in registry::PROTOCOLS {
                        if ui.selectable_label(self.settings.protocol == Some(*p),
                                               p.as_str())
                            .on_hover_text(*what).clicked()
                        {
                            self.settings.protocol = Some(*p);
                            changed = true;
                        }
                    }
                });

            // Only the settings that mean something for the protocol in force.
            let showing = self.settings.protocol
                .or_else(|| self.loaded.as_ref().map(|l| l.protocol));
            let field = |ui: &mut egui::Ui, label: &str,
                             text: &mut String, width: f32, hint: &str| {
                ui.label(RichText::new(label).small().color(self.palette.dim));
                ui.add(egui::TextEdit::singleline(text).desired_width(width))
                    .on_hover_text(hint);
            };
            match showing {
                Some(Protocol::Spi) => {
                    field(ui, "mode", &mut self.settings.spi_mode, 30.0,
                          "0 to 3: CPOL and CPHA. Sampling is on the rising \
                           edge when they are equal.");
                    field(ui, "bits", &mut self.settings.spi_bits, 30.0,
                          "Bits per word, default 8.");
                }
                Some(Protocol::Uart) => {
                    field(ui, "baud", &mut self.settings.uart_baud, 62.0,
                          "Leave empty to measure it from the narrowest pulse.");
                    field(ui, "parity", &mut self.settings.uart_parity, 30.0,
                          "n, e or o. A capture cannot say - the parity bit \
                           looks like a data bit until you know how many \
                           there are.");
                }
                Some(Protocol::Mdio) => {
                    field(ui, "preamble", &mut self.settings.mdio_preamble, 34.0,
                          "Preamble bits expected, default 32.");
                }
                Some(Protocol::Can) => {
                    field(ui, "bitrate", &mut self.settings.can_bitrate, 68.0,
                          "Bits per second, default 500000.");
                }
                _ => {}
            }

            if ui.button("Decode").clicked() || changed {
                self.redecode();
            }

            ui.separator();

            // ---- the filter ----
            ui.label(RichText::new("filter").small().color(self.palette.dim));
            let mut text = self.query_text.clone();
            let response = ui.add(egui::TextEdit::singleline(&mut text)
                .hint_text("addr:0x52 error:nack")
                .desired_width(240.0))
                .on_hover_text(filter_help());
            if response.changed() {
                self.set_query(text);
            }
            if let Some(e) = &self.query_error {
                ui.label(RichText::new(e).small().color(self.palette.warn));
            }
            if !self.query_text.is_empty() && ui.small_button("clear").clicked() {
                self.set_query(String::new());
            }
            let found = self.rows.len();
            if self.query.is_some() {
                ui.label(RichText::new(format!("{found}{} match",
                    if self.rows_truncated { "+" } else { "" }))
                    .small().color(if found == 0 {
                        self.palette.warn
                    } else {
                        self.palette.good
                    }));
            }

            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Fit").on_hover_text("Show the whole capture (F)")
                    .clicked()
                {
                    self.fit_all();
                }
                if ui.button("+").clicked() {
                    let mid = self.view.start + self.view.span() / 2;
                    let limits = self.limits();
                    self.view.zoom_about(0.6, mid, limits);
                }
                if ui.button("-").clicked() {
                    let mid = self.view.start + self.view.span() / 2;
                    let limits = self.limits();
                    self.view.zoom_about(1.0 / 0.6, mid, limits);
                }
                let mut walk = 0i32;
                if ui.button("next")
                    .on_hover_text("Next result, and zoom to it (N)")
                    .clicked() { walk = 1 }
                if ui.button("prev")
                    .on_hover_text("Previous result (P)")
                    .clicked() { walk = -1 }
                match walk {
                    1 => self.walk_result(true),
                    -1 => self.walk_result(false),
                    _ => {}
                }
            });
        });
    }

    /// Next or previous result, wrapping.
    ///
    /// The set walked is whatever the filter currently matches - with no
    /// filter, every transaction. Section 6.2 asks for next/previous over
    /// results and for results to be a persistent filter; making these the
    /// same set is what stops the keys and the table from disagreeing about
    /// what "next" means.
    /// One-click presets, saved searches, and what the partial word could be.
    ///
    /// Section 6.2 asks for errors-only and bus-only as one-click presets,
    /// autocomplete from the active decoders, and named saved searches. They
    /// share a row because they are all "fill the filter box for me".
    fn search_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("presets").small().color(self.palette.dim));
            if ui.small_button("errors")
                .on_hover_text("Everything with an error or left incomplete")
                .clicked()
            {
                self.preset("error:any");
            }
            if ui.small_button("clean").clicked() {
                self.preset("error:none");
            }
            // One button per bus the decode actually produced, which is the
            // bus-only view. Nothing to offer on a single-bus capture, so it
            // is not shown.
            let buses = self.buses();
            if buses.len() > 1 {
                for bus in buses {
                    if ui.small_button(format!("bus {bus}")).clicked() {
                        self.preset(&format!("bus:{bus}"));
                    }
                }
            }

            // ---- completion ----
            // The last word of the query, matched against the fields this
            // decode carries plus the language's own terms. Clicking one
            // finishes the word.
            let partial = self.query_text
                .rsplit(char::is_whitespace).next().unwrap_or("").to_string();
            if !partial.is_empty() && !partial.contains(':') {
                let offers = self.completions(&partial);
                if !offers.is_empty() {
                    ui.separator();
                    ui.label(RichText::new("try").small().color(self.palette.dim));
                }
                for name in offers.iter().take(6) {
                    if ui.small_button(format!("{name}:")).clicked() {
                        let head = self.query_text
                            .strip_suffix(&partial).unwrap_or("").to_string();
                        self.set_query(format!("{head}{name}:"));
                    }
                }
            }

            // ---- saved searches ----
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.add(egui::TextEdit::singleline(&mut self.save_query_as)
                    .hint_text("name").desired_width(84.0));
                if ui.small_button("save")
                    .on_hover_text("Keep this query under that name, for every \
                                    later session")
                    .clicked()
                {
                    let name = self.save_query_as.clone();
                    let query = self.query_text.clone();
                    if self.workspace.remember(&name, &query) {
                        self.workspace.save();
                        self.save_query_as.clear();
                        self.status = format!("saved {name:?} as {query:?}");
                        self.status_bad = false;
                    } else {
                        self.status = "a saved search needs both a name and a \
                                       query in the filter box".into();
                        self.status_bad = true;
                    }
                }
                let saved = self.workspace.searches.clone();
                let mut forget = None;
                for s in saved.iter().rev() {
                    let response = ui.small_button(&s.name)
                        .on_hover_text(format!("{}\n\nright-click to forget",
                                               s.query));
                    if response.clicked() {
                        self.preset(&s.query);
                    }
                    if response.secondary_clicked() {
                        forget = Some(s.name.clone());
                    }
                }
                if let Some(name) = forget {
                    self.workspace.forget(&name);
                    self.workspace.save();
                }
            });
        });
    }

    /// The measurement between the cursors, under the region it measures.
    ///
    /// Section 7's timing cursors and range measurement are the same numbers
    /// over the same interval, so they are one readout rather than two panels
    /// that could disagree about the same two edges.
    fn readout(&mut self, ui: &mut egui::Ui) {
        let Some(loaded) = self.loaded.as_ref() else { return };
        let Some((from, to)) = self.cursors.interval() else {
            ui.horizontal(|ui| {
                ui.label(RichText::new(
                    "right-click the timeline (or press A) to drop measurement \
                     cursors").small().color(self.palette.dim));
                if let (Some(a), None) = (self.cursors.a, self.cursors.b) {
                    ui.label(RichText::new(format!(
                        "A at {}  -  drop B to measure", style::time_label(a)))
                        .small().color(self.palette.accent));
                }
            });
            return;
        };

        let m = measure::measure(&loaded.capture, &loaded.decoded, from, to);
        let mut clear = false;
        ui.horizontal_wrapped(|ui| {
            let fact = |ui: &mut egui::Ui, name: &str, value: String,
                        colour: egui::Color32| {
                ui.label(RichText::new(name).small().color(self.palette.dim));
                ui.label(RichText::new(value).small().strong().color(colour));
                ui.add_space(6.0);
            };

            fact(ui, "A to B", measure::human_time(m.duration),
                 self.palette.accent);
            if m.duration > 0 {
                fact(ui, "=", measure::human_rate(1e12 / m.duration as f64),
                     self.palette.dim);
            }
            for c in &m.channels {
                let text = match c.frequency_hz {
                    Some(hz) => format!("{} edges, {}, {:.0}% high",
                                        c.edges, measure::human_rate(hz),
                                        c.duty * 100.0),
                    None => format!("{} edges, {:.0}% high", c.edges,
                                    c.duty * 100.0),
                };
                fact(ui, &c.name, text, self.palette.text);
            }
            fact(ui, "transactions", format!("{}{}", m.transactions,
                 if m.errors > 0 { format!(" ({} bad)", m.errors) }
                 else { String::new() }),
                 if m.errors > 0 { self.palette.warn } else { self.palette.text });
            fact(ui, "payload", format!("{} B, {}", m.payload_bytes,
                 measure::human_bytes_per_second(m.payload_bytes_per_second)),
                 self.palette.text);
            fact(ui, "busy", format!("{:.0}%", m.utilisation * 100.0),
                 self.palette.text);
            if m.gap_overlap {
                ui.label(RichText::new(
                    "a gap touches this interval, so these are lower bounds")
                    .small().color(self.palette.bad));
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),
                |ui| {
                    if ui.small_button("clear")
                        .on_hover_text("Put the cursors away (C)").clicked()
                    {
                        clear = true;
                    }
                });
        });
        if clear {
            self.cursors.clear();
        }
    }

    /// Parse what is in the trigger box, and find where it matches.
    ///
    /// Evaluated over the samples already captured, which is what makes the
    /// pre-trigger window free: everything before the match is there.
    fn set_trigger(&mut self, text: String) {
        self.trigger_text = text;
        self.trigger_hits.clear();
        if self.trigger_text.trim().is_empty() {
            self.trigger = None;
            self.trigger_error = None;
            return;
        }
        match trigger::parse(&self.trigger_text) {
            Ok(condition) => {
                self.trigger_error = None;
                if let Some(loaded) = self.loaded.as_ref() {
                    self.trigger_hits = trigger::find(&loaded.capture,
                                                      &loaded.decoded,
                                                      &condition);
                }
                self.trigger = Some(condition);
            }
            Err(e) => {
                // The last good condition stays in force while a new one is
                // being typed, as the filter box does.
                self.trigger_error = Some(e);
            }
        }
    }

    /// Just the times, for the timeline and the overview strip.
    fn trigger_times(&self) -> Vec<Picos> {
        self.trigger_hits.iter().map(|m| m.at).collect()
    }

    /// Section 10's builder, and honest about where it runs.
    fn trigger_pane(&mut self, ui: &mut egui::Ui) {
        // Collected while drawing and acted on afterwards: both of these
        // replace what the window is looking at.
        let mut clip_to_trigger = false;
        let mut start_monitor = false;

        ui.add_space(8.0);
        ui.label(RichText::new("TRIGGER").small().color(self.palette.dim));
        ui.separator();

        let mut text = self.trigger_text.clone();
        let response = ui.add(egui::TextEdit::singleline(&mut text)
            .hint_text("edge:rising:0")
            .desired_width(f32::INFINITY))
            .on_hover_text(trigger_help());
        if response.changed() {
            self.set_trigger(text);
        }

        if let Some(e) = &self.trigger_error {
            ui.label(RichText::new(e).small().color(self.palette.warn));
        }

        if let Some(condition) = self.trigger.clone() {
            ui.label(RichText::new(condition.describe()).small()
                .color(self.palette.text));
            ui.label(RichText::new(format!(
                "class: {}{}", condition.class().as_str(),
                if condition.hardware_class() {
                    ", which a capture engine could arm"
                } else {
                    ", software only"
                })).small().color(self.palette.dim));
            // The distinction section 10 asks the builder to make, and the
            // honest answer for this board.
            ui.label(RichText::new(if trigger::hardware_available() {
                    "runs: in hardware"
                } else {
                    "runs: in software, over the captured samples"
                }).small().color(self.palette.notice))
                .on_hover_text(trigger::NO_HARDWARE_TRIGGER);

            let hits = self.trigger_hits.len();
            ui.label(RichText::new(match hits {
                    0 => "no match in this capture".to_string(),
                    1 => "1 match".to_string(),
                    n => format!("{n} matches"),
                }).small().color(if hits == 0 {
                    self.palette.warn
                } else {
                    self.palette.trigger
                }));

            // The matches themselves, and the window around one - which is
            // what a pre-trigger capture would have kept.
            let hits: Vec<(Picos, String, Option<u64>)> = self.trigger_hits.iter()
                .take(12)
                .map(|m| (m.at, m.what.clone(), m.transaction))
                .collect();
            for (at, what, transaction) in hits {
                if ui.selectable_label(false, RichText::new(format!(
                    "{}  {}", style::time_label(at), what))
                    .small().color(self.palette.trigger))
                    .on_hover_text("Click to look at it")
                    .clicked()
                {
                    let span = self.view.span().max(2_000);
                    self.view = View { start: at.saturating_sub(span / 2),
                                       end: at + span / 2 };
                    if let Some(id) = transaction {
                        self.select(Some(id), false);
                    }
                }
            }
            if self.trigger_hits.len() > 12 {
                ui.label(RichText::new(format!("and {} more",
                    self.trigger_hits.len() - 12)).small()
                    .color(self.palette.dim));
            }

            if !self.trigger_hits.is_empty() {
                ui.horizontal(|ui| {
                    if ui.small_button("clip around first")
                        .on_hover_text("Keep 100 us either side of the first \
                                        match and work on that - what a \
                                        hardware trigger would have kept in \
                                        its ring buffer")
                        .clicked()
                    {
                        clip_to_trigger = true;
                    }
                });
            }
        }

        // ---- live monitoring -------------------------------------------------
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("live").small().color(self.palette.dim));
            ui.add(egui::TextEdit::singleline(&mut self.monitor_rounds)
                .desired_width(30.0))
                .on_hover_text("How many bursts to take");
            let busy = self.job.is_some();
            ui.add_enabled_ui(!busy, |ui| {
                if ui.small_button("monitor")
                    .on_hover_text("Take one burst after another, stopping when \
                                    the trigger matches. The time between two \
                                    bursts is unwatched, and is recorded as a \
                                    gap.")
                    .clicked()
                {
                    start_monitor = true;
                }
            });
            if busy {
                ui.spinner();
            }
        });

        if clip_to_trigger {
            self.clip_to_trigger();
        }
        if start_monitor {
            self.start_monitor();
        }
    }

    /// Keep the window around the first match and work on that.
    ///
    /// The capture on disk is untouched; this is the excerpt a hardware
    /// trigger's ring buffer would have handed over, and it says so in its own
    /// session source.
    fn clip_to_trigger(&mut self) {
        let Some(hit) = self.trigger_hits.first().map(|m| m.at) else { return };
        let Some(loaded) = self.loaded.as_ref() else { return };
        let (from, to) = trigger::window(&loaded.capture, hit,
                                         100_000_000, 100_000_000);
        let clipped = loaded.capture.clip(from, to);
        let (protocol, info, decoded, guessed) =
            source::decode(&clipped, &self.settings);
        let name = format!("{} clipped", loaded.name);
        let origin = loaded.origin.clone();
        self.adopt(Loaded {
            name, origin, capture: clipped, decoded, info, protocol, guessed,
        });
        // The condition is still what the user asked for, so find it again in
        // the excerpt - it should be in there, and if it is not that is worth
        // seeing.
        let text = self.trigger_text.clone();
        self.set_trigger(text);
    }

    /// Take bursts one after another until the trigger matches.
    fn start_monitor(&mut self) {
        if self.job.is_some() {
            return;
        }
        self.burst.settle_ms = self.burst_ms_text.trim().parse().unwrap_or(200);
        self.burst.max_edges = self.burst_edges_text.trim().parse().unwrap_or(8192);
        let rounds = self.monitor_rounds.trim().parse().unwrap_or(5);
        let port = match self.port.trim() {
            "" => None,
            p => Some(p.to_string()),
        };
        let job = source::Job::monitor(port, self.burst, rounds,
                                       self.trigger.clone(),
                                       self.settings.clone());
        self.status = format!("{}...", job.what);
        self.status_bad = false;
        self.job = Some(job);
    }

    /// Which buses this decode produced.
    fn buses(&self) -> Vec<u16> {
        let Some(loaded) = self.loaded.as_ref() else { return Vec::new() };
        let mut buses: Vec<u16> = loaded.decoded.transactions.iter()
            .map(|t| t.bus.0).collect();
        buses.sort_unstable();
        buses.dedup();
        buses
    }

    /// Field and term names starting with `partial`.
    ///
    /// From three places, in this order of usefulness: the fields this decode
    /// actually carried, the fields the active decoder says it can emit, and
    /// the language's own terms. The first is the one that makes it
    /// protocol-native - `can.id` is offered on a CAN capture and not on an
    /// I2C one.
    fn completions(&self, partial: &str) -> Vec<String> {
        let partial = partial.to_ascii_lowercase();
        let mut out: Vec<String> = Vec::new();
        let push = |name: &str, out: &mut Vec<String>| {
            if name.to_ascii_lowercase().starts_with(&partial)
                && !out.iter().any(|n| n == name)
            {
                out.push(name.to_string());
            }
        };

        if let Some(index) = &self.index {
            for name in index.field_names() {
                push(name, &mut out);
            }
        }
        if let Some(loaded) = self.loaded.as_ref() {
            let decoder = registry::decoder_with(loaded.protocol, &loaded.capture,
                                                 &self.settings.options());
            for f in decoder.search_fields() {
                push(f.name, &mut out);
            }
        }
        // What the analysers add, even before one has run: section 6.2 wants
        // autocomplete from the active decoders, and an analyser that declares
        // cmis.temperature is as much a source of fields as a decoder.
        for m in &self.extensions {
            for f in &m.search_fields {
                push(&f.name, &mut out);
            }
        }
        for (name, _) in search::KNOWN {
            push(name, &mut out);
        }
        out
    }

    // ---- bookmarks --------------------------------------------------------

    /// Add a marker where the pointer last was, or on the selection.
    ///
    /// Section 7 wants bookmarks named, shown on the overview strip, and
    /// carried into exports. They are `Annotation` records in the capture
    /// file, so saving the capture carries them and the CLI can read them -
    /// rather than a sidecar that could disagree with the capture it is about.
    fn add_bookmark(&mut self) {
        let at = self.cursor.or_else(|| {
            let d = self.decoded()?;
            let id = self.selected?;
            d.transactions.iter().find(|t| t.id == id).map(|t| t.start)
        });
        let Some(at) = at else {
            self.fail("point at the timeline, or select a transaction, first"
                      .into());
            return;
        };

        let Some(loaded) = self.loaded.as_mut() else { return };
        let label = if self.bookmark_label.trim().is_empty() {
            format!("bookmark {}", loaded.capture.annotations.len() + 1)
        } else {
            self.bookmark_label.trim().to_string()
        };
        loaded.capture.annotations.push(file::Annotation {
            start: at,
            end: at,
            label: label.clone(),
            note: String::new(),
        });
        loaded.capture.annotations.sort_by_key(|a| a.start);
        self.bookmark_label.clear();
        self.status = format!("bookmarked {label:?} at {}",
                              style::time_label(at));
        self.status_bad = false;
    }

    fn walk_result(&mut self, forward: bool) {
        if self.rows.is_empty() {
            self.status = match &self.query {
                Some(_) => format!("nothing matches {:?}", self.query_text),
                None => "nothing decoded to walk".into(),
            };
            self.status_bad = false;
            return;
        }

        // Where we are: the selection if it is in the results, else the
        // position last walked to, else before the beginning.
        let current = self.selected
            .and_then(|id| self.row_of(id))
            .or(self.result_at);

        let next = match (current, forward) {
            (None, true) => 0,
            (None, false) => self.rows.len() - 1,
            (Some(at), true) => (at + 1) % self.rows.len(),
            (Some(at), false) => (at + self.rows.len() - 1) % self.rows.len(),
        };
        self.result_at = Some(next);

        let Some(loaded) = self.loaded.as_ref() else { return };
        let Some(t) = self.rows.get(next)
            .and_then(|row| loaded.decoded.transactions.get(*row))
        else { return };

        let (id, start, end) = (t.id, t.start, t.end);
        self.view = View::fit(start, end);
        self.select(Some(id), false);
        self.status = format!("result {} of {}{}", next + 1, self.rows.len(),
                              if self.rows_truncated { " listed" } else { "" });
        self.status_bad = false;
    }

    /// Where a transaction sits in the current results, if it is in them.
    fn row_of(&self, id: u64) -> Option<usize> {
        let loaded = self.loaded.as_ref()?;
        self.rows.iter().position(|row| {
            loaded.decoded.transactions.get(*row).map(|t| t.id) == Some(id)
        })
    }

    /// Set the filter to a preset and jump to its first result.
    fn preset(&mut self, query: &str) {
        self.set_query(query.to_string());
        if !self.rows.is_empty() {
            self.walk_result(true);
        }
    }

    fn limits(&self) -> (Picos, Picos) {
        self.loaded.as_ref().map(|l| l.capture.span()).unwrap_or((0, 1_000_000))
    }

    fn session_pane(&mut self, ui: &mut egui::Ui) {
        // Collected while drawing and applied afterwards: the capture is
        // borrowed for the whole pane, and a bookmark changes it.
        let mut add_bookmark = false;
        let mut remove_bookmark: Option<usize> = None;
        let mut run_extension: Option<extend::Manifest> = None;

        let Some(loaded) = self.loaded.as_ref() else {
            ui.add_space(8.0);
            ui.label(RichText::new("No capture loaded").color(self.palette.dim));
            return;
        };

        let s = &loaded.capture.session;
        ui.label(RichText::new(&loaded.name).strong());
        ui.label(RichText::new(loaded.origin.describe()).small()
            .color(self.palette.dim));
        ui.add_space(6.0);

        egui::Grid::new("session").num_columns(2).spacing([8.0, 2.0]).show(ui, |ui| {
            let mut fact = |name: &str, value: String| {
                ui.label(RichText::new(name).small().color(self.palette.dim));
                ui.label(RichText::new(value).small());
                ui.end_row();
            };
            fact("source", s.source.clone());
            if !s.device_id.is_empty() {
                fact("device", s.device_id.clone());
            }
            if !s.firmware_version.is_empty() {
                fact("firmware", s.firmware_version.clone());
            }
            fact("started", s.started_utc.clone());
            fact("tick rate", format!("{} Hz", s.tick_hz));
            fact("edges", loaded.capture.chunks.iter()
                .map(|c| c.transitions()).sum::<usize>().to_string());
            let (first, last) = loaded.capture.span();
            fact("span", style::duration_label(last.saturating_sub(first)));
        });

        ui.add_space(8.0);
        ui.label(RichText::new("DECODER").small().color(self.palette.dim));
        ui.separator();
        ui.label(RichText::new(format!("{} {}", loaded.info.name,
                                       loaded.info.version)).small());
        if loaded.guessed {
            ui.label(RichText::new(format!(
                "protocol guessed as {} from the channel names",
                loaded.protocol.as_str())).small().color(self.palette.dim));
        }
        for (k, v) in &loaded.info.settings {
            ui.label(RichText::new(format!("{k} = {v}")).small()
                .color(self.palette.dim));
        }

        ui.add_space(8.0);
        ui.label(RichText::new("CHANNELS").small().color(self.palette.dim));
        ui.separator();
        for (i, name) in s.channels.iter().enumerate() {
            if self.visible.len() <= i {
                self.visible.push(true);
            }
            ui.checkbox(&mut self.visible[i], name);
        }

        // ---- what the decode found -------------------------------------------
        // The schema's own count, which is what the CLI prints. Counting by
        // severity here instead disagreed with it over every NACK - which is
        // severity notice, and is the thing people are looking for.
        let problems = loaded.decoded.with_errors().count();
        let incomplete = loaded.decoded.transactions.iter()
            .filter(|t| !t.complete).count();
        ui.add_space(8.0);
        ui.label(RichText::new("DECODE").small().color(self.palette.dim));
        ui.separator();
        ui.label(RichText::new(format!("{} transactions",
                                       loaded.decoded.transactions.len())).small());
        if problems > 0 {
            ui.label(RichText::new(format!("{problems} with errors or warnings"))
                .small().color(self.palette.warn));
        } else if !loaded.decoded.transactions.is_empty() {
            ui.label(RichText::new("no errors or warnings").small()
                .color(self.palette.good));
        }
        if incomplete > 0 {
            ui.label(RichText::new(format!("{incomplete} incomplete"))
                .small().color(self.palette.warn));
        }

        // ---- analysers --------------------------------------------------------
        // Section 8's device and application analysers. Offered only when one
        // handles the protocol in force, because a list of things that cannot
        // apply is worse than no list.
        let usable = self.usable_extensions();
        if !usable.is_empty() {
            ui.add_space(8.0);
            ui.label(RichText::new("ANALYSERS").small().color(self.palette.dim));
            ui.separator();
            for m in usable {
                let already = self.applied.iter().any(|n| *n == m.name);
                ui.horizontal(|ui| {
                    let label = format!("{} {}", m.name, m.version);
                    if already {
                        ui.label(RichText::new(label).small()
                            .color(self.palette.good));
                        ui.label(RichText::new("applied").small()
                            .color(self.palette.dim));
                    } else {
                        ui.label(RichText::new(label).small());
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if ui.small_button("apply")
                                    .on_hover_text(format!(
                                        "{}\n\nAdds fields; it cannot change \
                                         what the decoder found.", m.about))
                                    .clicked()
                                {
                                    run_extension = Some(m.clone());
                                }
                            });
                    }
                });
            }
            if self.analyse_job.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("analysing").small()
                        .color(self.palette.dim));
                });
            }
        }

        // ---- bookmarks --------------------------------------------------------
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label(RichText::new("BOOKMARKS").small().color(self.palette.dim));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.small_button("add")
                    .on_hover_text("At the pointer, or on the selection (B)")
                    .clicked()
                {
                    add_bookmark = true;
                }
                ui.add(egui::TextEdit::singleline(&mut self.bookmark_label)
                    .hint_text("label").desired_width(90.0));
            });
        });
        ui.separator();
        if loaded.capture.annotations.is_empty() {
            ui.label(RichText::new(
                "none yet. Point at the timeline and press B; they are saved \
                 into the capture file.").small().color(self.palette.dim));
        }
        let marks: Vec<(usize, Picos, String)> = loaded.capture.annotations.iter()
            .enumerate()
            .map(|(i, a)| (i, a.start, a.label.clone()))
            .collect();
        for (i, at, label) in marks {
            ui.horizontal(|ui| {
                if ui.selectable_label(false, RichText::new(format!(
                    "{}  {label}", style::time_label(at)))
                    .small().color(self.palette.bookmark))
                    .on_hover_text("Click to go there")
                    .clicked()
                {
                    let span = self.view.span();
                    self.view = View { start: at.saturating_sub(span / 2),
                                       end: at + span / 2 };
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        if ui.small_button("x").clicked() {
                            remove_bookmark = Some(i);
                        }
                    });
            });
        }

        // ---- gaps -------------------------------------------------------------
        if !loaded.capture.gaps.is_empty() {
            ui.add_space(8.0);
            ui.label(RichText::new("GAPS").small().color(self.palette.bad));
            ui.separator();
            let gaps: Vec<(Picos, Picos, String)> = loaded.capture.gaps.iter()
                .map(|g| (g.start, g.end, g.reason.clone())).collect();
            for (start, end, reason) in gaps {
                if ui.selectable_label(false, RichText::new(format!(
                    "{}  {}", style::time_label(start), reason))
                    .small().color(self.palette.bad))
                    .on_hover_text("Data is missing here. Click to look at it.")
                    .clicked()
                {
                    self.view = View::fit(start, end.max(start + 1_000));
                }
            }
        }

        // The capture is no longer borrowed, so the two intentions gathered
        // above can be carried out.
        if add_bookmark {
            self.add_bookmark();
        }
        if let Some(i) = remove_bookmark {
            if let Some(loaded) = self.loaded.as_mut() {
                if i < loaded.capture.annotations.len() {
                    let gone = loaded.capture.annotations.remove(i);
                    self.status = format!("removed {:?}", gone.label);
                    self.status_bad = false;
                }
            }
        }
        if let Some(manifest) = run_extension {
            self.analyse(manifest);
        }

        self.trigger_pane(ui);
    }

    fn open_pane(&mut self, ui: &mut egui::Ui) {
        ui.label(RichText::new("OPEN A CAPTURE").small().color(self.palette.dim));
        ui.separator();

        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.path_text)
                .hint_text("path to a .cap file").desired_width(150.0));
            if ui.button("Open").clicked() {
                let path = std::path::PathBuf::from(self.path_text.trim());
                self.open_path(&path);
            }
        });

        ui.add_space(6.0);
        ui.label(RichText::new(self.browse_dir.display().to_string()).small()
            .color(self.palette.dim));
        ui.horizontal(|ui| {
            if ui.small_button("up").clicked() {
                if let Some(parent) = self.browse_dir.parent() {
                    self.browse_dir = parent.to_path_buf();
                }
            }
            for dir in source::likely_directories() {
                let label = dir.file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_else(|| dir.display().to_string());
                if ui.small_button(label).clicked() {
                    self.browse_dir = dir;
                }
            }
        });

        ui.add_space(4.0);
        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            // Directories first, so the list can be walked; then the captures.
            let mut subdirs: Vec<std::path::PathBuf> = std::fs::read_dir(&self.browse_dir)
                .map(|entries| entries.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.is_dir())
                    .collect())
                .unwrap_or_default();
            subdirs.sort();
            for dir in subdirs.into_iter().take(40) {
                let name = dir.file_name().map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                if ui.selectable_label(false, RichText::new(format!("[{name}]"))
                    .small().color(self.palette.dim)).clicked()
                {
                    self.browse_dir = dir;
                }
            }

            let files = source::captures_in(&self.browse_dir);
            if files.is_empty() {
                ui.label(RichText::new("no .cap files here").small()
                    .color(self.palette.dim));
            }
            let mut chosen = None;
            for path in files {
                let name = path.file_name().map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if ui.selectable_label(false, RichText::new(name).small())
                    .on_hover_text(format!("{}\n{} bytes", path.display(), size))
                    .clicked()
                {
                    chosen = Some(path);
                }
            }
            if let Some(path) = chosen {
                self.open_path(&path);
            }
        });
    }

    /// Where a relative save name lands: where the user has been browsing if
    /// they chose it themselves, else the working directory.
    fn save_dir(&self) -> std::path::PathBuf {
        self.workspace.last_dir.clone()
            .filter(|d| d.is_dir())
            .or_else(|| std::env::current_dir().ok())
            .unwrap_or_else(|| std::path::PathBuf::from("."))
    }

    fn save(&mut self) {
        let Some(loaded) = self.loaded.as_ref() else { return };
        let name = self.save_text.trim();
        if name.is_empty() {
            self.fail("give the file a name first".into());
            return;
        }
        // Relative names go where the program was started, not where the
        // file browser happens to be pointing: on a fresh install that is the
        // golden corpus directory, and a capture saved into the test data is
        // a mess to notice later.
        let path = if std::path::Path::new(name).is_absolute() {
            std::path::PathBuf::from(name)
        } else {
            self.save_dir().join(name)
        };
        // Refusing rather than overwriting: a capture that took a bench setup
        // to produce is not something to lose to a name typed twice.
        if path.exists() {
            self.fail(format!("{} already exists; choose another name",
                              path.display()));
            return;
        }
        match source::to_bytes(&loaded.capture)
            .and_then(|bytes| std::fs::write(&path, bytes)
                .map_err(|e| format!("cannot write {}: {e}", path.display())))
        {
            Ok(()) => {
                self.status = format!("wrote {}", path.display());
                self.status_bad = false;
            }
            Err(e) => self.fail(e),
        }
    }

    fn keys(&mut self, ctx: &egui::Context) {
        // Not while a text box has the keyboard, or typing "f" in the filter
        // would jump the view.
        if ctx.memory(|m| m.focused().is_some()) {
            return;
        }
        let limits = self.limits();
        let step = (self.view.span() / 8).max(1) as i64;
        ctx.input(|i| {
            let mid = self.view.start + self.view.span() / 2;
            if i.key_pressed(egui::Key::F) {
                self.fit_all();
            }
            if i.key_pressed(egui::Key::Plus) || i.key_pressed(egui::Key::Equals) {
                self.view.zoom_about(0.6, mid, limits);
            }
            if i.key_pressed(egui::Key::Minus) {
                self.view.zoom_about(1.0 / 0.6, mid, limits);
            }
            if i.key_pressed(egui::Key::ArrowLeft) {
                self.view.pan(-step);
            }
            if i.key_pressed(egui::Key::ArrowRight) {
                self.view.pan(step);
            }
            if i.key_pressed(egui::Key::Home) {
                let span = self.view.span();
                self.view.start = limits.0;
                self.view.end = limits.0 + span;
            }
        });
        if ctx.input(|i| i.key_pressed(egui::Key::N)) {
            self.walk_result(true);
        }
        if ctx.input(|i| i.key_pressed(egui::Key::P)) {
            self.walk_result(false);
        }
        if ctx.input(|i| i.key_pressed(egui::Key::B)) {
            self.add_bookmark();
        }
        // A drops the next measurement cursor where the pointer is; C puts
        // them away. Right-clicking the timeline does the same as A, for
        // anyone who would rather not learn a key.
        if ctx.input(|i| i.key_pressed(egui::Key::A)) {
            match self.cursor {
                Some(at) => {
                    self.cursors.place(at);
                    self.status_bad = false;
                }
                None => self.fail("point at the timeline first".into()),
            }
        }
        if ctx.input(|i| i.key_pressed(egui::Key::C)) {
            self.cursors.clear();
        }
    }
}

fn trigger_help() -> String {
    "One trigger builder for hardware and software conditions - section 10.\n\n\
     edge:rising:0        an edge on a channel\n\
     edge:0               either direction\n\
     low:1:for=2us        a level held\n\
     glitch:0:shorter=100ns   a narrow pulse\n\
     start | start:i2c    the framing a transaction begins with\n\
     addr:0x52            a decoded field, as in a search\n\
     type:WRITE\n\
     error:nack | error:any\n\
     A then B within=5ms  a sequence\n\n\
     Spaces mean and, commas mean or.".to_string()
}

fn filter_help() -> String {
    let mut text = String::from(
        "The same query language the CLI uses.\n\nFields:\n");
    for (name, what) in search::KNOWN {
        text.push_str(&format!("  {name:<10} {what}\n"));
    }
    text.push_str("\nTerms are separated by spaces and every one must \
                   match. A bare word matches the summary.\n\nExamples:\
                   \n  addr:0x52\n  error:nack\n  addr:0x52 type:READ\
                   \n  incomplete:true");
    text
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // The context is cloned rather than borrowed from the Ui, because the
        // panels below need the Ui itself and one borrow would exclude the
        // other. Context is a handle, so this is a refcount.
        let ctx = ui.ctx().clone();
        let ctx = &ctx;
        // A capture running on the hardware finishes on its own thread, so keep
        // drawing until it lands rather than waiting for a mouse move.
        if self.job.is_some() || self.analyse_job.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(80));
        }
        if let Some(job) = self.analyse_job.as_mut() {
            if let Some(result) = job.poll() {
                let name = job.what.trim_start_matches("running ").to_string();
                self.analyse_job = None;
                match result {
                    Ok((decoded, report)) => {
                        if let Some(loaded) = self.loaded.as_mut() {
                            loaded.decoded = decoded;
                        }
                        self.applied.push(name.clone());
                        self.status = format!(
                            "{name}: {} transaction(s) enriched, {} field(s), \
                             {} warning(s)",
                            report.touched, report.fields_added,
                            report.warnings);
                        for problem in &report.rejected {
                            // Never silent, in the window either.
                            self.status.push_str(&format!("  -  ignored: {problem}"));
                        }
                        self.status_bad = false;
                        self.reindex();
                    }
                    Err(e) => self.fail(format!("{name}: {e}")),
                }
            }
        }
        if let Some(job) = self.job.as_mut() {
            if let Some(result) = job.poll() {
                self.job = None;
                match result {
                    Ok((name, capture)) => {
                        let (protocol, info, decoded, guessed) =
                            source::decode(&capture, &self.settings);
                        self.adopt(Loaded {
                            name: format!("board {name}"),
                            origin: source::Origin::Board(name),
                            capture, decoded, info, protocol, guessed,
                        });
                    }
                    Err(e) => self.fail(e),
                }
            }
        }

        self.keys(ctx);

        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(3.0);
            self.toolbar(ui);
            ui.add_space(2.0);
            self.decode_bar(ui);
            ui.add_space(2.0);
            self.search_bar(ui);
            ui.add_space(3.0);
        });

        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal(|ui| {
                let colour = if self.status_bad {
                    self.palette.bad
                } else {
                    self.palette.dim
                };
                ui.label(RichText::new(&self.status).small().color(colour));
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center),
                    |ui| {
                        ui.label(RichText::new(
                            "drag to pan, wheel to zoom, F to fit, N and P for \
                             results, A to measure, B to bookmark").small()
                            .color(self.palette.dim));
                    });
            });
        });

        egui::Panel::left("left").resizable(true).default_size(232.0)
            .show(ui, |ui| {
                egui::ScrollArea::vertical().auto_shrink([false, false])
                    .show(ui, |ui| {
                        match self.left {
                            LeftPane::Session => self.session_pane(ui),
                            LeftPane::Open => self.open_pane(ui),
                        }
                    });
            });

        egui::Panel::right("inspector").resizable(true).default_size(280.0)
            .show(ui, |ui| {
                let Some(loaded) = self.loaded.as_ref() else {
                    ui.add_space(8.0);
                    ui.label(RichText::new("Nothing loaded")
                        .color(self.palette.dim));
                    return;
                };
                let action = inspector::Inspector {
                    decoded: &loaded.decoded,
                    selected: self.selected,
                    pinned: self.pinned,
                    palette: &self.palette,
                }.show(ui);
                if let Some((start, end)) = action.zoom_to {
                    self.view = View::fit(start, end);
                }
                if let Some(id) = action.select {
                    self.select(Some(id), false);
                }
                if let Some(id) = action.pin {
                    self.pinned = Some(id);
                    self.status = format!("#{id} pinned; select another to \
                                           compare them");
                    self.status_bad = false;
                }
                if action.unpin {
                    self.pinned = None;
                }
            });

        egui::Panel::bottom("table").resizable(true)
            .default_size(230.0).min_size(80.0)
            .show(ui, |ui| {
                let Some(loaded) = self.loaded.as_ref() else { return };
                let action = table::Table {
                    decoded: &loaded.decoded,
                    rows: &self.rows,
                    truncated: self.rows_truncated,
                    selected: self.selected,
                    scroll_to: self.scroll_table_to.take(),
                    palette: &self.palette,
                }.show(ui);
                if let Some(id) = action.selected {
                    self.select(Some(id), true);
                }
                if let Some(id) = action.zoom_to {
                    self.zoom_to_transaction(id);
                }
            });

        egui::CentralPanel::default().show(ui, |ui| {
            if self.loaded.is_none() {
                self.welcome(ui);
                return;
            }

            // Its own strip, claimed before the waveform: the timeline's
            // scroll area fills everything left over, so anything drawn after
            // it is drawn nowhere. Taken before `loaded` is borrowed, because
            // the readout measures through &mut self.
            egui::Panel::bottom("readout").show(ui, |ui| {
                ui.add_space(2.0);
                self.readout(ui);
                ui.add_space(2.0);
            });

            let triggers = self.trigger_times();
            let Some(loaded) = self.loaded.as_ref() else { return };

            let mut view = self.view;
            let moved = overview::Overview {
                capture: &loaded.capture,
                decoded: &loaded.decoded,
                triggers: &triggers,
                view: &mut view,
                palette: &self.palette,
            }.show(ui);
            if moved {
                self.view = view;
            }

            ui.add_space(4.0);

            let mut view = self.view;
            let cursors = self.cursors;
            let interaction = egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    timeline::Timeline {
                        capture: &loaded.capture,
                        decoded: &loaded.decoded,
                        bookmarks: &loaded.capture.annotations,
                        cursors,
                        triggers: &triggers,
                        view: &mut view,
                        visible: &self.visible,
                        selected: self.selected,
                        palette: &self.palette,
                    }.show(ui)
                }).inner;
            self.view = view;

            if let Some(id) = interaction.selected {
                self.select(Some(id), false);
            }
            // Where a bookmark goes when B is pressed. Kept from frame to
            // frame, because the pointer is not over the timeline while the
            // label is being typed in the side pane.
            if interaction.hover_time.is_some() {
                self.cursor = interaction.hover_time;
            }
            if let Some(at) = interaction.place_cursor {
                self.cursors.place(at);
            }
        });
    }
}

impl App {
    fn welcome(&mut self, ui: &mut egui::Ui) {
        ui.add_space(28.0);
        ui.vertical_centered(|ui| {
            ui.label(RichText::new("Sniffer").size(22.0).strong());
            ui.label(RichText::new(
                "Multi-protocol bus analyser - I2C, I3C, SPI, MDIO, UART, CAN")
                .color(self.palette.dim));
            ui.add_space(16.0);
            ui.label(RichText::new(
                "Simulate a script from the toolbar to see decoded traffic \
                 without hardware,\nor connect a BUSBRIDGE board and capture \
                 a burst.").color(self.palette.dim));
            ui.add_space(16.0);
            if ui.button("Simulate the Appendix D demo").clicked() {
                self.script = "demo".into();
                self.do_simulate();
            }
            if ui.button("Open a capture file").clicked() {
                self.left = LeftPane::Open;
            }

            // What was open last time. A window that forgets everything
            // between sessions is one people leave open for weeks to avoid
            // setting up again.
            let recent: Vec<std::path::PathBuf> = self.workspace.recent.iter()
                .filter(|p| p.exists())
                .cloned()
                .collect();
            if !recent.is_empty() {
                ui.add_space(16.0);
                ui.label(RichText::new("RECENT").small()
                    .color(self.palette.dim));
                let mut open = None;
                for path in recent {
                    let name = path.file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_else(|| path.display().to_string());
                    if ui.selectable_label(false, RichText::new(name).small())
                        .on_hover_text(path.display().to_string())
                        .clicked()
                    {
                        open = Some(path);
                    }
                }
                if let Some(path) = open {
                    self.open_path(&path);
                }
            }
        });
    }
}
