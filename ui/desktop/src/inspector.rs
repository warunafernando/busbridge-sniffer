//! The inspector: everything known about one transaction.
//!
//! Section 2.4 asks for a field-level breakdown with each field traceable back
//! to the samples it came from. That last part is the specification's core
//! principle in miniature - a decode you cannot check against the waveform is
//! a claim, not evidence - so every field here can be clicked to put the
//! timeline on exactly the edges it was read from.

use eframe::egui;
use egui::{RichText, Ui};

use schema::{Decoded, Severity, Transaction};

use crate::style::Palette;

/// What the inspector wants the rest of the window to do.
#[derive(Debug, Default)]
pub struct Action {
    /// Put the timeline on this interval - a field, or the whole transaction.
    pub zoom_to: Option<(schema::Picos, schema::Picos)>,
    pub select: Option<u64>,
    /// Hold this one aside to compare the next selection against.
    pub pin: Option<u64>,
    pub unpin: bool,
}

pub struct Inspector<'a> {
    pub decoded: &'a Decoded,
    pub selected: Option<u64>,
    /// Held aside for comparison, if anything is.
    pub pinned: Option<u64>,
    pub palette: &'a Palette,
}

impl Inspector<'_> {
    pub fn show(&mut self, ui: &mut Ui) -> Action {
        let mut action = Action::default();

        let Some(t) = self.selected
            .and_then(|id| self.decoded.transactions.iter().find(|t| t.id == id))
        else {
            self.nothing_selected(ui);
            return action;
        };

        egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&t.kind).strong().size(14.0)
                    .color(self.palette.severity(t.severity)));
                ui.label(RichText::new(t.protocol.as_str()).small()
                    .color(self.palette.dim));
            });
            ui.label(RichText::new(&t.summary).color(self.palette.text));
            ui.add_space(4.0);

            egui::Grid::new("transaction-facts").num_columns(2).spacing([10.0, 3.0])
                .show(ui, |ui| {
                    self.fact(ui, "id", format!("#{}", t.id));
                    self.fact(ui, "bus", format!("{}", t.bus.0));
                    self.fact(ui, "starts", crate::style::time_label(t.start));
                    self.fact(ui, "ends", crate::style::time_label(t.end));
                    self.fact(ui, "length", crate::style::duration_label(
                        t.end.saturating_sub(t.start)));
                    self.fact(ui, "severity", t.severity.as_str().to_string());
                    self.fact(ui, "samples", format!(
                        "chunk {}, edges {}..{}",
                        t.samples.chunk, t.samples.first, t.samples.last));
                    if let Some(parent) = t.parent {
                        self.fact(ui, "part of", format!("#{parent}"));
                    }
                });

            if !t.complete {
                ui.add_space(4.0);
                ui.label(RichText::new(
                    "Incomplete: this ran into a gap or the end of the capture. \
                     What is shown is only what was seen.")
                    .small().color(self.palette.warn));
            }

            if !t.errors.is_empty() {
                ui.add_space(6.0);
                ui.label(RichText::new("PROBLEMS").small().color(self.palette.dim));
                for e in &t.errors {
                    ui.label(RichText::new(format!("- {}", e.as_str()))
                        .color(self.palette.bad));
                }
            }

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                if ui.button("Zoom to this").clicked() {
                    action.zoom_to = Some((t.start, t.end));
                }
                if let Some(parent) = t.parent {
                    if ui.button("Go to parent").clicked() {
                        action.select = Some(parent);
                    }
                }
                if self.pinned == Some(t.id) {
                    if ui.button("Unpin").clicked() {
                        action.unpin = true;
                    }
                } else if ui.button("Pin to compare")
                    .on_hover_text("Hold this one aside; select another and \
                                    the differences appear here")
                    .clicked()
                {
                    action.pin = Some(t.id);
                }
            });

            // ---- comparison ---------------------------------------------------
            // Section 7: two compatible transactions, field by field. Shown
            // instead of the plain field list when something is pinned, since
            // the pinned value beside each field is the field list plus more.
            let against = self.pinned
                .filter(|id| *id != t.id)
                .and_then(|id| self.decoded.transactions.iter()
                    .find(|p| p.id == id));
            if let Some(other) = against {
                self.comparison(ui, other, t);
            }

            // ---- what it was, derived ------------------------------------------
            ui.add_space(8.0);
            ui.label(RichText::new("WHAT HAPPENED").small()
                .color(self.palette.dim));
            ui.separator();
            for line in measure::explain(t) {
                let colour = match line.kind {
                    "problem" if !t.errors.is_empty() || !t.complete =>
                        self.palette.bad,
                    "problem" => self.palette.good,
                    "evidence" => self.palette.dim,
                    _ => self.palette.text,
                };
                ui.label(RichText::new(line.text).small().color(colour));
            }

            ui.add_space(8.0);
            ui.label(RichText::new("FIELDS").small().color(self.palette.dim));
            ui.separator();
            if t.fields.is_empty() {
                ui.label(RichText::new("this decoder reported no fields")
                    .small().color(self.palette.dim));
            }
            for field in &t.fields {
                if let Some(zoom) = self.field(ui, field) {
                    action.zoom_to = Some(zoom);
                }
            }

            let children: Vec<&Transaction> = self.decoded.transactions.iter()
                .filter(|c| c.parent == Some(t.id)).collect();
            if !children.is_empty() {
                ui.add_space(8.0);
                ui.label(RichText::new("PARTS").small().color(self.palette.dim));
                ui.separator();
                for child in children {
                    if ui.selectable_label(false, RichText::new(format!(
                        "{}  {}", child.kind, child.summary)).small()).clicked()
                    {
                        action.select = Some(child.id);
                    }
                }
            }
        });

        action
    }

    /// A pinned transaction against the selected one, field by field.
    fn comparison(&self, ui: &mut Ui, a: &Transaction, b: &Transaction) {
        let c = measure::compare(a, b);
        ui.add_space(8.0);
        ui.label(RichText::new(format!("COMPARED WITH #{}", a.id)).small()
            .color(self.palette.accent));
        ui.separator();
        if let Some(why) = &c.why_not {
            ui.label(RichText::new(why).small().color(self.palette.warn));
        }
        if c.identical_content() {
            ui.label(RichText::new(
                "every field is the same; only the timing differs")
                .small().color(self.palette.good));
        }

        egui::Grid::new("comparison").num_columns(3).spacing([8.0, 2.0])
            .show(ui, |ui| {
                ui.label(RichText::new("field").small().color(self.palette.dim));
                ui.label(RichText::new(format!("#{}", a.id)).small()
                    .color(self.palette.dim));
                ui.label(RichText::new(format!("#{}", b.id)).small()
                    .color(self.palette.dim));
                ui.end_row();

                for f in &c.fields {
                    let colour = if f.differs() {
                        self.palette.warn
                    } else {
                        self.palette.dim
                    };
                    ui.label(RichText::new(&f.name).small().color(colour));
                    ui.label(RichText::new(f.a.clone()
                        .unwrap_or_else(|| "-".into())).small().monospace()
                        .color(colour));
                    ui.label(RichText::new(f.b.clone()
                        .unwrap_or_else(|| "-".into())).small().monospace()
                        .color(colour));
                    ui.end_row();
                }

                ui.label(RichText::new("length").small().color(self.palette.dim));
                ui.label(RichText::new(measure::human_time(c.duration.0))
                    .small().monospace().color(self.palette.dim));
                ui.label(RichText::new(measure::human_time(c.duration.1))
                    .small().monospace().color(self.palette.dim));
                ui.end_row();
            });
    }

    fn fact(&self, ui: &mut Ui, name: &str, value: String) {
        ui.label(RichText::new(name).small().color(self.palette.dim));
        ui.label(RichText::new(value).small().color(self.palette.text));
        ui.end_row();
    }

    /// One field. Returns the interval to zoom to when it is clicked.
    fn field(&self, ui: &mut Ui, field: &schema::Field)
        -> Option<(schema::Picos, schema::Picos)>
    {
        let colour = if field.severity >= Severity::Warning {
            self.palette.severity(field.severity)
        } else {
            self.palette.text
        };

        let response = ui.horizontal(|ui| {
            ui.label(RichText::new(&field.name).small().color(self.palette.dim));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(RichText::new(&field.display).monospace().color(colour));
            });
        }).response;

        let response = response.interact(egui::Sense::click());
        let hover = format!(
            "{} = {}\n{} to {}\nchunk {}, edges {}..{}\n\nClick to put the \
             timeline on the samples this was read from.",
            field.name, field.display,
            crate::style::time_label(field.start),
            crate::style::time_label(field.end),
            field.samples.chunk, field.samples.first, field.samples.last);

        if response.hovered() {
            ui.painter().rect_filled(
                response.rect.expand2(egui::vec2(2.0, 0.0)),
                egui::CornerRadius::same(3),
                self.palette.tint(self.palette.accent, 0.10));
        }
        let response = response.on_hover_text(hover);
        if response.clicked() {
            Some((field.start, field.end))
        } else {
            None
        }
    }

    fn nothing_selected(&self, ui: &mut Ui) {
        ui.add_space(10.0);
        ui.label(RichText::new("Nothing selected").color(self.palette.dim));
        ui.add_space(4.0);
        ui.label(RichText::new(
            "Click a bubble on the timeline or a row in the table. Fields \
             appear here, and clicking one puts the timeline on the samples \
             it was decoded from.")
            .small().color(self.palette.dim));

        let errors: Vec<&Transaction> = self.decoded.transactions.iter()
            .filter(|t| is_problem(t)).collect();
        if !errors.is_empty() {
            ui.add_space(10.0);
            ui.label(RichText::new(format!("{} need attention", errors.len()))
                .small().color(self.palette.warn));
        }
    }
}

/// Is this a transaction worth walking to?
///
/// The schema's own definition - any error, or incomplete - rather than a
/// severity threshold. A NACK is severity `notice`, and it is the single most
/// looked-for thing on an I2C bus; a threshold of `warning` would have walked
/// straight past every one of them. `Decoded::with_errors` is what the CLI
/// counts, so this is the same answer in both front ends.
pub fn is_problem(t: &Transaction) -> bool {
    !t.errors.is_empty() || !t.complete
}

#[cfg(test)]
mod tests {
    use super::*;

    fn demo() -> Decoded {
        // The demo traffic contains a NACK, so it has a problem to find.
        let cap = simulator::build("demo", 1_000_000).unwrap();
        let protocol = registry::guess(&cap);
        registry::decoder(protocol, &cap).decode(&cap)
    }

    /// A NACK is severity `notice`. Judging problems by severity would skip
    /// it, which would be the commonest I2C fault there is going unmarked.
    #[test]
    fn a_nack_is_a_problem_even_though_it_is_only_a_notice() {
        let d = demo();
        let nack = d.transactions.iter()
            .find(|t| t.errors.iter().any(|e| e.as_str().contains("nack")))
            .expect("the demo traffic addresses 0x77, which does not answer");
        assert!(nack.severity < Severity::Warning);
        assert!(is_problem(nack));
    }

    /// And the same set the CLI counts, so the two front ends cannot disagree
    /// about how many things are wrong with the same capture.
    #[test]
    fn problems_are_what_the_schema_calls_problems() {
        let d = demo();
        let mine = d.transactions.iter().filter(|t| is_problem(t)).count();
        assert_eq!(mine, d.with_errors().count());
        assert_eq!(mine, 1, "one NACK in the demo traffic");
    }

    #[test]
    fn a_clean_transaction_is_not_a_problem() {
        let d = demo();
        let clean = d.transactions.iter().find(|t| t.errors.is_empty()).unwrap();
        assert!(!is_problem(clean));
    }
}
