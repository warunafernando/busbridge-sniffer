//! The data table: one row per transaction, kept in step with the timeline.
//!
//! Section 2.4 wants selection synchronised both ways - a row selected here
//! moves the timeline, a bubble clicked there scrolls to the row - and section
//! 2.5 wants the table filtered by the same query language the CLI uses. Both
//! matter more than they sound: a table that scrolls independently of the
//! waveform is two tools that disagree, and a filter with its own syntax is a
//! second language to learn for the same question.
//!
//! Rows are drawn only where they are visible. A capture with fifty thousand
//! transactions must scroll at the frame rate, and laying out fifty thousand
//! rows to show forty of them does not.

use eframe::egui;
use egui::{Align, RichText, Ui};

use schema::{Decoded, Transaction};

use crate::style::Palette;

/// What the user did in the table.
#[derive(Debug, Default)]
pub struct Action {
    /// A row was clicked: select it.
    pub selected: Option<u64>,
    /// A row was double-clicked: select it and zoom the timeline to it.
    pub zoom_to: Option<u64>,
}

pub struct Table<'a> {
    pub decoded: &'a Decoded,
    /// Indices into `decoded.transactions` that pass the filter, in order.
    pub rows: &'a [usize],
    /// True when the filter matched more than the rows being held.
    pub truncated: bool,
    pub selected: Option<u64>,
    /// Set when the selection changed elsewhere, so the table scrolls to it.
    pub scroll_to: Option<u64>,
    pub palette: &'a Palette,
}

impl Table<'_> {
    pub fn show(&mut self, ui: &mut Ui) -> Action {
        let mut action = Action::default();
        let row_h = 20.0;

        header(ui, self.palette, self.rows.len(),
               self.decoded.transactions.len(), self.truncated);

        // Where the selected row is among the filtered rows, for scrolling to
        // it. Computed before drawing, because the row itself is only laid out
        // when it happens to be on screen.
        let target = self.scroll_to.and_then(|id| {
            self.rows.iter().position(|&i| {
                self.decoded.transactions.get(i).map(|t| t.id) == Some(id)
            })
        });

        let mut area = egui::ScrollArea::vertical().auto_shrink([false, false]);
        if let Some(row) = target {
            // Placed a little above centre: what follows a transaction is
            // usually what is being looked for next.
            let y = row as f32 * row_h;
            area = area.vertical_scroll_offset(
                (y - ui.available_height() * 0.4).max(0.0));
        }

        area.show_rows(ui, row_h, self.rows.len(), |ui, range| {
            for row in range {
                let Some(&index) = self.rows.get(row) else { continue };
                let Some(t) = self.decoded.transactions.get(index) else { continue };
                let chosen = self.selected == Some(t.id);
                let response = self.row(ui, t, chosen, row_h);
                if response.clicked() {
                    action.selected = Some(t.id);
                }
                if response.double_clicked() {
                    action.selected = Some(t.id);
                    action.zoom_to = Some(t.id);
                }
            }
        });

        action
    }

    fn row(&self, ui: &mut Ui, t: &Transaction, chosen: bool, row_h: f32)
        -> egui::Response
    {
        let full = egui::vec2(ui.available_width(), row_h);
        let (rect, response) = ui.allocate_exact_size(full, egui::Sense::click());

        if chosen {
            ui.painter().rect_filled(rect, egui::CornerRadius::same(3),
                                     self.palette.tint(self.palette.accent, 0.22));
        } else if crate::inspector::is_problem(t) {
            ui.painter().rect_filled(rect, egui::CornerRadius::same(3),
                                     self.palette.tint(
                                         self.palette.severity(t.severity), 0.10));
        }

        let colour = if crate::inspector::is_problem(t) {
            self.palette.severity(t.severity)
        } else {
            self.palette.text
        };

        let font = egui::TextStyle::Small.resolve(ui.style());
        let mut x = rect.left() + 6.0;
        let mut cell = |text: String, width: f32| {
            ui.painter().text(
                egui::Pos2::new(x, rect.center().y),
                egui::Align2::LEFT_CENTER, text, font.clone(), colour);
            x += width;
        };

        cell(crate::style::time_label(t.start), 96.0);
        cell(crate::style::duration_label(t.end.saturating_sub(t.start)), 82.0);
        cell(t.protocol.as_str().to_string(), 46.0);
        cell(t.kind.clone(), 104.0);

        // The remainder of the row is the summary, plus the flags that change
        // how it should be read. "incomplete" is not decoration: it means the
        // transaction ran into a gap or the end of the capture, and the bytes
        // shown are only what was seen.
        let mut tail = t.summary.clone();
        if !t.complete {
            tail.push_str("   [incomplete]");
        }
        for e in &t.errors {
            tail.push_str("   ");
            tail.push_str(e.as_str());
        }
        cell(tail, 0.0);

        response.on_hover_text(hover_text(t))
    }
}

fn header(ui: &mut Ui, palette: &Palette, shown: usize, total: usize,
          truncated: bool) {
    ui.horizontal(|ui| {
        let small = |ui: &mut Ui, text: &str, width: f32| {
            let (rect, _) = ui.allocate_exact_size(
                egui::vec2(width, 16.0), egui::Sense::hover());
            ui.painter().text(
                egui::Pos2::new(rect.left(), rect.center().y),
                egui::Align2::LEFT_CENTER, text,
                egui::TextStyle::Small.resolve(ui.style()), palette.dim);
        };
        ui.add_space(6.0);
        small(ui, "TIME", 96.0);
        small(ui, "LENGTH", 82.0);
        small(ui, "BUS", 46.0);
        small(ui, "WHAT", 104.0);
        small(ui, "DETAIL", 160.0);
        ui.with_layout(egui::Layout::right_to_left(Align::Center), |ui| {
            // "and more" rather than a count: with an index the number of
            // matches beyond the page is the one thing that would cost a walk
            // of the whole capture, which is what the paging is avoiding.
            let text = if truncated {
                format!("first {shown} matches of {total} transactions")
            } else if shown == total {
                format!("{total} transactions")
            } else {
                format!("{shown} of {total} shown")
            };
            ui.label(RichText::new(text).small().color(palette.dim));
        });
    });
    ui.separator();
}

fn hover_text(t: &Transaction) -> String {
    let mut text = format!("#{} {} {}\n{} to {}",
        t.id, t.kind, t.summary,
        crate::style::time_label(t.start), crate::style::time_label(t.end));
    if !t.complete {
        text.push_str("\nincomplete: it ran into a gap or the end of the capture");
    }
    if !t.fields.is_empty() {
        text.push('\n');
        for f in t.fields.iter().take(8) {
            text.push_str(&format!("\n{}: {}", f.name, f.display));
        }
        if t.fields.len() > 8 {
            text.push_str(&format!("\nand {} more", t.fields.len() - 8));
        }
    }
    text
}

/// Which transactions pass a filter.
///
/// Indices rather than references so the caller can keep the list across
/// frames without borrowing the decode, and so an empty query costs nothing
/// but a range.
pub fn filter(decoded: &Decoded, query: Option<&search::Query>) -> Vec<usize> {
    match query {
        None => (0..decoded.transactions.len()).collect(),
        Some(q) => decoded.transactions.iter().enumerate()
            .filter(|(_, t)| q.matches(t))
            .map(|(i, _)| i)
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo() -> Decoded {
        let cap = simulator::build("demo", 1_000_000).unwrap();
        let protocol = registry::guess(&cap);
        registry::decoder(protocol, &cap).decode(&cap)
    }

    #[test]
    fn no_query_shows_every_row() {
        let d = demo();
        assert_eq!(filter(&d, None).len(), d.transactions.len());
    }

    #[test]
    fn a_query_narrows_the_rows_and_keeps_their_order() {
        let d = demo();
        let q = search::parse("addr:0x52").unwrap();
        let rows = filter(&d, Some(&q));
        assert!(!rows.is_empty(), "the demo traffic addresses 0x52");
        assert!(rows.len() < d.transactions.len(),
                "it also addresses 0x3C and 0x77, so this must narrow");
        assert!(rows.windows(2).all(|w| w[0] < w[1]),
                "rows must stay in capture order");
        // And the same query the CLI would run, against the same engine.
        assert_eq!(rows.len(), q.run(&d).len());
    }

    #[test]
    fn a_filter_that_matches_nothing_is_empty_rather_than_everything() {
        let d = demo();
        let q = search::parse("addr:0x11").unwrap();
        assert!(filter(&d, Some(&q)).is_empty());
    }
}
