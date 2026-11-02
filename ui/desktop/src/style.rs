//! The palette, and how times are written.
//!
//! Small on purpose. A waveform tool draws nearly everything itself, so what is
//! needed here is a set of colours every panel agrees on and one function for
//! formatting a time - the thing most likely to be written five different ways
//! in five places.

use eframe::egui;
use egui::Color32;

use schema::{Picos, Severity};

pub struct Palette {
    pub text: Color32,
    pub dim: Color32,
    pub accent: Color32,
    pub good: Color32,
    pub notice: Color32,
    pub warn: Color32,
    pub bad: Color32,
    pub trace: Color32,
    pub plot_bg: Color32,
    pub gap_fill: Color32,
    pub cursor: Color32,
    /// Bookmarks. Their own colour, because sharing the pointer's amber made a
    /// saved marker and the mouse look like the same thing.
    pub bookmark: Color32,
    /// Trigger matches. Another mark on the same timeline, so another colour.
    pub trigger: Color32,
    pub panel: Color32,
}

impl Palette {
    pub fn dark() -> Self {
        Palette {
            text: Color32::from_rgb(0xD8, 0xE2, 0xEC),
            dim: Color32::from_rgb(0x84, 0x95, 0xA6),
            accent: Color32::from_rgb(0x4F, 0xB3, 0xE8),
            good: Color32::from_rgb(0x7A, 0xC7, 0x8E),
            notice: Color32::from_rgb(0x6F, 0xB6, 0xD8),
            warn: Color32::from_rgb(0xE0, 0xB1, 0x5C),
            bad: Color32::from_rgb(0xE0, 0x7A, 0x5F),
            // The trace is the brightest thing on the plot. It is the raw data,
            // and the specification's core principle is that the raw data stays
            // visible and trustworthy - so nothing drawn on top outshines it.
            trace: Color32::from_rgb(0x8F, 0xE3, 0xB0),
            plot_bg: Color32::from_rgb(0x10, 0x14, 0x18),
            gap_fill: Color32::from_rgba_unmultiplied(0xE0, 0x7A, 0x5F, 0x28),
            cursor: Color32::from_rgb(0xE8, 0xC0, 0x6A),
            bookmark: Color32::from_rgb(0xC0, 0x8C, 0xE0),
            trigger: Color32::from_rgb(0xFF, 0x8A, 0xB4),
            panel: Color32::from_rgb(0x18, 0x1D, 0x23),
        }
    }

    pub fn severity(&self, s: Severity) -> Color32 {
        match s {
            Severity::Info => self.accent,
            Severity::Notice => self.notice,
            Severity::Warning => self.warn,
            Severity::Error => self.bad,
        }
    }

    /// The colour at low opacity, for a fill behind text.
    ///
    /// Color32 premultiplies, so the channels come back scaled - which is
    /// correct for a translucent fill and wrong for anything treating the
    /// result as an opaque colour.
    pub fn tint(&self, colour: Color32, alpha: f32) -> Color32 {
        Color32::from_rgba_unmultiplied(
            colour.r(), colour.g(), colour.b(),
            (alpha.clamp(0.0, 1.0) * 255.0) as u8)
    }
}

/// A timestamp, in whatever unit reads best at that magnitude.
///
/// One function so the timeline, the table, the inspector and the overview
/// cannot each pick a different unit and leave the reader converting.
pub fn time_label(t: Picos) -> String {
    if t == 0 {
        return "0".into();
    }
    if t < 1_000 {
        format!("{t} ps")
    } else if t < 1_000_000 {
        format!("{:.3} ns", t as f64 / 1_000.0)
    } else if t < 1_000_000_000 {
        format!("{:.3} us", t as f64 / 1_000_000.0)
    } else if t < 1_000_000_000_000 {
        format!("{:.4} ms", t as f64 / 1_000_000_000.0)
    } else {
        format!("{:.4} s", t as f64 / 1_000_000_000_000.0)
    }
}

/// A duration, which reads differently from a timestamp: "12.5 us across"
/// rather than "at 12.5 us".
pub fn duration_label(d: Picos) -> String {
    time_label(d)
}

/// Set up the window's look once.
pub fn install(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = egui::vec2(8.0, 6.0);
        style.spacing.button_padding = egui::vec2(9.0, 4.0);
        style.spacing.interact_size.y = 22.0;
        for widget in [
            &mut style.visuals.widgets.noninteractive,
            &mut style.visuals.widgets.inactive,
            &mut style.visuals.widgets.hovered,
            &mut style.visuals.widgets.active,
            &mut style.visuals.widgets.open,
        ] {
            widget.corner_radius = egui::CornerRadius::same(5);
            widget.expansion = 0.0;
        }
    });

    let mut dark = (*ctx.style_of(egui::Theme::Dark)).clone();
    let p = Palette::dark();
    dark.visuals.panel_fill = p.panel;
    dark.visuals.window_fill = Color32::from_rgb(0x1D, 0x23, 0x2A);
    dark.visuals.faint_bg_color = Color32::from_rgb(0x21, 0x28, 0x30);
    dark.visuals.extreme_bg_color = p.plot_bg;
    dark.visuals.override_text_color = Some(p.text);
    dark.visuals.widgets.noninteractive.bg_stroke =
        egui::Stroke::new(1.0, Color32::from_rgb(0x2C, 0x35, 0x3E));
    dark.visuals.widgets.inactive.bg_fill = Color32::from_rgb(0x27, 0x2F, 0x38);
    dark.visuals.widgets.hovered.bg_fill = Color32::from_rgb(0x31, 0x3B, 0x46);
    dark.visuals.widgets.active.bg_fill = Color32::from_rgb(0x3A, 0x46, 0x53);
    ctx.set_style_of(egui::Theme::Dark, dark);
    ctx.set_theme(egui::ThemePreference::Dark);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_written_in_a_readable_unit() {
        assert_eq!(time_label(0), "0");
        assert_eq!(time_label(500), "500 ps");
        assert!(time_label(1_500).ends_with("ns"));
        assert!(time_label(1_500_000).ends_with("us"));
        assert!(time_label(1_500_000_000).ends_with("ms"));
        assert!(time_label(1_500_000_000_000).ends_with("s"));
    }

    #[test]
    fn a_tint_is_translucent_and_keeps_its_hue_when_opaque() {
        let p = Palette::dark();
        let c = Color32::from_rgb(0x40, 0x80, 0xC0);
        assert!(p.tint(c, 0.5).a() < 255);
        let solid = p.tint(c, 1.0);
        assert_eq!((solid.r(), solid.g(), solid.b()), (0x40, 0x80, 0xC0));
    }

    /// A bookmark, the measurement cursors and the pointer are three
    /// different things on the same timeline; drawing two of them the same
    /// colour makes one of them a lie.
    #[test]
    fn the_marks_on_the_timeline_are_told_apart_by_colour() {
        let p = Palette::dark();
        let marks = [("bookmark", p.bookmark), ("cursor", p.cursor),
                     ("A and B", p.accent), ("trace", p.trace),
                     ("gap", p.bad), ("trigger", p.trigger)];
        for i in 0..marks.len() {
            for j in i + 1..marks.len() {
                assert_ne!(marks[i].1, marks[j].1,
                           "{} and {} are drawn the same colour",
                           marks[i].0, marks[j].0);
            }
        }
    }

    #[test]
    fn every_severity_has_its_own_colour() {
        let p = Palette::dark();
        let colours = [
            p.severity(Severity::Info),
            p.severity(Severity::Notice),
            p.severity(Severity::Warning),
            p.severity(Severity::Error),
        ];
        for i in 0..colours.len() {
            for j in i + 1..colours.len() {
                assert_ne!(colours[i], colours[j],
                           "two severities share a colour, so the overview strip \
                            cannot tell them apart");
            }
        }
    }
}
