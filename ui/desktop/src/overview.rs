//! The overview strip: the whole capture at a glance, with the visible window
//! marked on it.
//!
//! Section 2.3 asks for activity density and error markers when zoomed out far
//! enough that individual edges mean nothing. That view is most useful as a
//! permanent strip rather than a zoom level, because the question it answers -
//! "where in these two hundred milliseconds is the problem, and where am I
//! looking now?" - is the one being asked while zoomed *in*.

use eframe::egui;
use egui::{CornerRadius, Pos2, Rect, Sense, Stroke, StrokeKind, Ui, Vec2};

use schema::{Decoded, Picos, Severity};

use crate::style::Palette;
use crate::timeline::View;

pub struct Overview<'a> {
    pub capture: &'a file::Capture,
    pub decoded: &'a Decoded,
    /// Where a trigger condition matched.
    pub triggers: &'a [Picos],
    pub view: &'a mut View,
    pub palette: &'a Palette,
}

impl Overview<'_> {
    /// Draws the strip. Returns true when the view moved.
    pub fn show(&mut self, ui: &mut Ui) -> bool {
        let (rect, response) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), 42.0), Sense::click_and_drag());
        if !ui.is_rect_visible(rect) {
            return false;
        }

        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, CornerRadius::same(5), self.palette.plot_bg);

        let (first, last) = self.capture.span();
        let whole = last.saturating_sub(first).max(1);
        let to_x = |t: Picos| -> f32 {
            let f = (t.saturating_sub(first)) as f64 / whole as f64;
            rect.left() + (f.clamp(0.0, 1.0) as f32) * rect.width()
        };
        let to_time = |x: f32| -> Picos {
            let f = ((x - rect.left()) / rect.width()).clamp(0.0, 1.0) as f64;
            first + (f * whole as f64) as Picos
        };

        // ---- activity density -------------------------------------------------
        // One bar per pixel column, height by how many transitions landed in it.
        // This is the honest low-zoom picture: not a waveform pretending to be
        // legible, but where the bus was busy.
        let columns = rect.width().max(1.0) as usize;
        let mut counts = vec![0u32; columns];
        for chunk in &self.capture.chunks {
            for &t in &chunk.times {
                let x = to_x(t) - rect.left();
                let c = (x as usize).min(columns - 1);
                counts[c] += 1;
            }
        }
        let peak = counts.iter().copied().max().unwrap_or(1).max(1) as f32;
        let base = rect.bottom() - 12.0;
        for (c, &n) in counts.iter().enumerate() {
            if n == 0 {
                continue;
            }
            let h = (n as f32 / peak) * (base - rect.top() - 4.0);
            let x = rect.left() + c as f32;
            painter.line_segment(
                [Pos2::new(x, base), Pos2::new(x, base - h.max(1.0))],
                Stroke::new(1.0, self.palette.tint(self.palette.trace, 0.7)));
        }

        // ---- gaps ------------------------------------------------------------
        for gap in &self.capture.gaps {
            let x0 = to_x(gap.start);
            let x1 = to_x(gap.end).max(x0 + 1.5);
            painter.rect_filled(
                Rect::from_min_max(Pos2::new(x0, rect.top()),
                                   Pos2::new(x1, base)),
                CornerRadius::ZERO, self.palette.tint(self.palette.bad, 0.35));
        }

        // ---- error and warning markers ---------------------------------------
        // Drawn last of the data so they are never hidden behind the density
        // bars: finding these is what the strip is for.
        for t in &self.decoded.transactions {
            if t.severity < Severity::Warning {
                continue;
            }
            let x = to_x(t.start);
            painter.line_segment(
                [Pos2::new(x, rect.top() + 2.0), Pos2::new(x, base)],
                Stroke::new(1.5, self.palette.severity(t.severity)));
        }

        // ---- bookmarks --------------------------------------------------------
        // Section 7 asks for these on the overview strip specifically, and the
        // reason is plain once you have one: the strip is where you look to
        // find your way back to somewhere you have already been.
        for mark in &self.capture.annotations {
            let x = to_x(mark.start);
            painter.line_segment(
                [Pos2::new(x, rect.top()), Pos2::new(x, base)],
                Stroke::new(1.0, self.palette.bookmark));
            painter.circle_filled(Pos2::new(x, rect.top() + 3.0), 2.5,
                                  self.palette.bookmark);
        }

        // ---- trigger matches --------------------------------------------------
        for at in self.triggers {
            let x = to_x(*at);
            painter.circle_filled(Pos2::new(x, base - 2.0), 2.5,
                                  self.palette.trigger);
        }

        // ---- where we are looking ---------------------------------------------
        let vx0 = to_x(self.view.start);
        let vx1 = to_x(self.view.end).max(vx0 + 2.0);
        let window = Rect::from_min_max(Pos2::new(vx0, rect.top() + 1.0),
                                        Pos2::new(vx1, base));
        painter.rect_filled(window, CornerRadius::same(3),
                            self.palette.tint(self.palette.cursor, 0.14));
        painter.rect_stroke(window, CornerRadius::same(3),
                            Stroke::new(1.0, self.palette.cursor),
                            StrokeKind::Inside);

        painter.text(
            Pos2::new(rect.left() + 4.0, rect.bottom() - 1.0),
            egui::Align2::LEFT_BOTTOM,
            format!("whole capture: {}", crate::style::duration_label(whole)),
            egui::TextStyle::Small.resolve(ui.style()),
            self.palette.dim);

        // ---- clicking and dragging move the window ----------------------------
        let mut moved = false;
        if response.clicked() || response.dragged() {
            if let Some(pos) = response.interact_pointer_pos() {
                // Centre the view on the click, keeping its width: this strip
                // navigates, it does not zoom.
                let want = to_time(pos.x);
                let half = self.view.span() / 2;
                let start = want.saturating_sub(half);
                self.view.end = start + self.view.span();
                self.view.start = start;
                moved = true;
            }
        }
        moved
    }
}

#[cfg(test)]
mod tests {
    use crate::timeline::View;

    /// Centring must not change how much is on screen - the strip navigates,
    /// and a click that also zoomed would lose the user's place.
    #[test]
    fn centring_keeps_the_span() {
        let mut view = View { start: 1_000, end: 3_000 };
        let span = view.span();
        let want: schema::Picos = 10_000;
        let half = view.span() / 2;
        let start = want.saturating_sub(half);
        view.end = start + view.span();
        view.start = start;
        assert_eq!(view.span(), span);
        assert_eq!((view.start + view.end) / 2, want);
    }
}
