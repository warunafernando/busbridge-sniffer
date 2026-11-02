//! The timeline: raw waveforms, decode bubbles, and moving around them.
//!
//! Section 2.1 calls this the primary debugging surface, and section 2.3 says
//! what it must show at each zoom: individual edges when close in, protocol
//! fields at medium, activity bands and error markers when far out. That is
//! level of detail, and it is not only cosmetic - a capture with a hundred
//! thousand transitions cannot draw one line segment each and stay interactive.
//!
//! # How the levels are drawn
//!
//! A chunk holds transitions, so the level between two of them is whatever the
//! earlier one said. Drawing only the recorded points would show a dotted line;
//! what has to be drawn is the *hold*, which is why every segment runs from one
//! transition to the next rather than from sample to sample.
//!
//! When more than one transition falls in a pixel column there is nothing
//! useful to draw as a line, so the column becomes a band - the specification's
//! "activity density" at low zoom. The switch is automatic and per column, so a
//! quiet stretch beside a busy one shows both properly.
//!
//! # Zoom anchors under the pointer
//!
//! Section 2.2: "Zoom should preserve the cursor location under the pointer
//! whenever possible." Anything else makes finding a feature a game of
//! zoom-and-chase, and it costs one line of arithmetic to get right.

use eframe::egui;
use egui::{CornerRadius, Pos2, Rect, Sense, Stroke, StrokeKind, Ui, Vec2};

use measure::Cursors;
use schema::{Decoded, Picos, Transaction};

use crate::style::Palette;

/// What part of the capture is on screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct View {
    pub start: Picos,
    pub end: Picos,
}

impl View {
    pub fn span(&self) -> Picos {
        self.end.saturating_sub(self.start).max(1)
    }

    /// Zoom by `factor` about a point, keeping that point where it is.
    pub fn zoom_about(&mut self, factor: f64, at: Picos, limits: (Picos, Picos)) {
        let left = (at.saturating_sub(self.start)) as f64 * factor;
        let right = (self.end.saturating_sub(at)) as f64 * factor;

        let mut start = at as f64 - left;
        let mut end = at as f64 + right;

        // A span of less than a nanosecond is closer than any capture here
        // resolves, and one wider than the capture is empty screen.
        let whole = (limits.1.saturating_sub(limits.0)).max(1) as f64;
        if end - start < 1_000.0 {
            let mid = (start + end) / 2.0;
            start = mid - 500.0;
            end = mid + 500.0;
        }
        if end - start > whole * 4.0 {
            return;
        }
        self.start = start.max(0.0) as Picos;
        self.end = (end.max(start + 1.0)) as Picos;
    }

    pub fn pan(&mut self, by: i64) {
        if by < 0 {
            let by = (-by) as u64;
            let by = by.min(self.start);
            self.start -= by;
            self.end -= by;
        } else {
            self.start += by as u64;
            self.end += by as u64;
        }
    }

    /// Fit an interval with a little room either side.
    pub fn fit(start: Picos, end: Picos) -> Self {
        let span = end.saturating_sub(start).max(1_000);
        let pad = span / 10;
        View { start: start.saturating_sub(pad), end: end + pad }
    }
}

/// Where a time falls on screen.
fn x_of(view: View, plot: Rect, t: Picos) -> f32 {
    let f = (t.saturating_sub(view.start)) as f64 / view.span() as f64;
    plot.left() + (f as f32) * plot.width()
}

/// What time a screen position is over.
fn time_at(view: View, plot: Rect, x: f32) -> Picos {
    let f = ((x - plot.left()) / plot.width()).clamp(0.0, 1.0) as f64;
    view.start + (f * view.span() as f64) as Picos
}

/// One channel's levels across the visible window, as line segments.
///
/// Pure, so the part that is easy to get wrong can be tested without a window.
///
/// # What is drawn
///
/// A chunk entry is a moment when *some* channel moved, so this channel's
/// level between two entries is whatever the earlier one said - the segments
/// are the holds, not the samples. A vertical is drawn only where this
/// channel's own level changed: drawing one at every entry made every SCL edge
/// look like an SDA transition, and both traces came out looking like the
/// clock.
///
/// When more than one transition falls inside a pixel column there is nothing
/// useful to draw as a hold, so the column becomes a band from the lowest to
/// the highest level seen in it - the specification's activity density, decided
/// per column so a quiet stretch beside a busy one still shows its edges.
fn channel_segments(
    chunk: &file::SampleChunk,
    channel: u8,
    view: View,
    plot: Rect,
    high: f32,
    low: f32,
) -> Vec<[Pos2; 2]> {
    let mut segments: Vec<[Pos2; 2]> = Vec::new();
    if chunk.times.is_empty() {
        return segments;
    }

    // The entry at or before the left edge sets the level the window opens at;
    // without it the first partial hold is missing and the trace starts in mid
    // air.
    let first = match chunk.times.binary_search(&view.start) {
        Ok(i) => i,
        Err(0) => 0,
        Err(i) => i - 1,
    };

    let mut i = first;
    let mut previous: Option<bool> = None;
    let mut column_high = false;
    let mut column_low = false;
    let mut column_x = f32::NAN;

    let flush_column = |segments: &mut Vec<[Pos2; 2]>,
                        column_x: f32, column_high: bool, column_low: bool| {
        if column_x.is_nan() || !(column_high || column_low) {
            return;
        }
        let top = if column_high { high } else { low };
        let bottom = if column_low { low } else { high };
        segments.push([Pos2::new(column_x, top), Pos2::new(column_x, bottom)]);
    };

    while i < chunk.len() {
        let t = chunk.times[i];
        if t > view.end {
            break;
        }
        let next = chunk.times.get(i + 1).copied()
            .unwrap_or(chunk.end.max(view.end));
        let level = chunk.channel(i, channel);
        let y = if level { high } else { low };

        let x0 = x_of(view, plot, t.max(view.start)).max(plot.left());
        let x1 = x_of(view, plot, next.min(view.end)).min(plot.right());

        if x1 - x0 < 1.0 {
            if column_x.is_nan() || (x0 - column_x).abs() >= 1.0 {
                flush_column(&mut segments, column_x, column_high, column_low);
                column_x = x0;
                column_high = false;
                column_low = false;
            }
            if level { column_high = true } else { column_low = true }
            // A column stands for whatever fell inside it, so what came before
            // it is no longer a level to draw an edge from.
            previous = Some(level);
        } else {
            flush_column(&mut segments, column_x, column_high, column_low);
            column_x = f32::NAN;
            column_high = false;
            column_low = false;

            // The vertical, only where this channel's own level changed.
            if previous.is_some_and(|was| was != level) {
                segments.push([Pos2::new(x0, high), Pos2::new(x0, low)]);
            }
            segments.push([Pos2::new(x0, y), Pos2::new(x1, y)]);
            previous = Some(level);
        }

        i += 1;
        // A window showing a hundred thousand transitions has nothing more to
        // say after a few thousand segments, and drawing them costs the frame
        // rate that makes panning usable.
        if segments.len() > 20_000 {
            break;
        }
    }
    flush_column(&mut segments, column_x, column_high, column_low);
    segments
}

/// What the user did on the timeline this frame.
#[derive(Debug, Default)]
pub struct Interaction {
    /// A transaction whose bubble was clicked.
    pub selected: Option<u64>,
    /// Where the pointer is, in capture time, for the readout.
    pub hover_time: Option<Picos>,
    /// A measurement cursor was dropped here.
    pub place_cursor: Option<Picos>,
}

pub struct Timeline<'a> {
    pub capture: &'a file::Capture,
    pub decoded: &'a Decoded,
    /// Bookmarks, drawn over everything: they mark a place someone chose to
    /// come back to, so they have to be findable at any zoom.
    pub bookmarks: &'a [file::Annotation],
    /// The measurement cursors, drawn with the interval between them shaded.
    pub cursors: Cursors,
    /// Where a trigger condition matched.
    pub triggers: &'a [Picos],
    pub view: &'a mut View,
    pub visible: &'a [bool],
    pub selected: Option<u64>,
    pub palette: &'a Palette,
}

impl Timeline<'_> {
    pub fn show(&mut self, ui: &mut Ui) -> Interaction {
        let mut out = Interaction::default();

        let channels: Vec<usize> = (0..self.capture.session.channels.len())
            .filter(|i| self.visible.get(*i).copied().unwrap_or(true))
            .collect();

        let bubble_h = 22.0;
        let gutter = 58.0;
        let furniture = bubble_h + 26.0;

        // The rows share the panel rather than taking a fixed height: two
        // channels in a tall window were leaving most of it empty, and a
        // waveform is easier to read the more room it has. Bounded at both
        // ends: too flat and a glitch is invisible, too tall and one CAN
        // channel fills the window with a single stretched trace. Space left
        // over sits under the plot, where the table's drag handle is.
        let rows = channels.len().max(1) as f32;
        let offered = (ui.available_height() - furniture) / rows;
        let row_h = offered.clamp(30.0, 180.0);
        let height = rows * row_h + furniture;

        let (rect, response) = ui.allocate_exact_size(
            Vec2::new(ui.available_width(), height.max(120.0)),
            Sense::click_and_drag(),
        );
        if !ui.is_rect_visible(rect) {
            return out;
        }

        let plot = Rect::from_min_max(
            Pos2::new(rect.left() + gutter, rect.top()),
            Pos2::new(rect.right() - 4.0, rect.bottom()),
        );
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, CornerRadius::same(6), self.palette.plot_bg);

        let limits = self.capture.span();

        // ---- interaction, before anything is drawn ---------------------------
        // The view moves first and everything below is drawn from the result,
        // so a drag shows this frame rather than the last one.
        if let Some(pos) = response.hover_pos() {
            out.hover_time = Some(time_at(*self.view, plot, pos.x));
            let scroll = ui.input(|i| i.smooth_scroll_delta.y);
            if scroll.abs() > 0.1 {
                // Anchored on the pointer, which is what stops zooming from
                // becoming a game of chase.
                let factor = if scroll > 0.0 { 0.85 } else { 1.0 / 0.85 };
                let at = time_at(*self.view, plot, pos.x);
                self.view.zoom_about(factor as f64, at, limits);
                out.hover_time = Some(at);
            }
        }
        if response.secondary_clicked() {
            if let Some(pos) = response.interact_pointer_pos() {
                out.place_cursor = Some(time_at(*self.view, plot, pos.x));
            }
        }
        if response.dragged() {
            let dx = response.drag_delta().x;
            let per_pixel = self.view.span() as f64 / plot.width() as f64;
            self.view.pan(-(dx as f64 * per_pixel) as i64);
        }

        // A snapshot to draw from: Copy, so the closures below borrow nothing.
        let view = *self.view;
        let to_x = |t: Picos| -> f32 { x_of(view, plot, t) };

        // ---- gaps, behind everything else ----------------------------------
        // Drawn first and across the full height: a hole in the capture changes
        // how every row above it should be read, so it is not a footnote.
        for gap in &self.capture.gaps {
            if gap.end < view.start || gap.start > view.end {
                continue;
            }
            let r = Rect::from_min_max(
                Pos2::new(to_x(gap.start).max(plot.left()), plot.top()),
                Pos2::new(to_x(gap.end).min(plot.right()), plot.bottom()),
            );
            painter.rect_filled(r.expand2(Vec2::new(0.5, 0.0)), 0,
                                self.palette.gap_fill);
            painter.rect_stroke(r, 0, Stroke::new(1.0, self.palette.bad),
                                StrokeKind::Inside);
        }

        // ---- waveforms -------------------------------------------------------
        for (row, &channel) in channels.iter().enumerate() {
            let top = plot.top() + row as f32 * row_h;
            // A fixed inset, so a tall row gives a taller trace rather than a
            // taller gap between rows.
            let high = top + 8.0;
            let low = top + row_h - 10.0;

            let name = &self.capture.session.channels[channel];
            painter.text(
                Pos2::new(rect.left() + gutter - 8.0, (high + low) / 2.0),
                egui::Align2::RIGHT_CENTER,
                name,
                egui::TextStyle::Small.resolve(ui.style()),
                self.palette.dim,
            );

            self.draw_channel(&painter, plot, view, channel as u8, high, low);
        }

        // ---- decode bubbles ---------------------------------------------------
        let bubble_top = plot.top() + channels.len() as f32 * row_h + 4.0;
        let mut clicked = None;
        for t in &self.decoded.transactions {
            if t.end < view.start || t.start > view.end {
                continue;
            }
            let x0 = to_x(t.start).max(plot.left());
            let x1 = to_x(t.end).min(plot.right());
            let r = Rect::from_min_max(
                Pos2::new(x0, bubble_top),
                Pos2::new((x1).max(x0 + 2.0), bubble_top + bubble_h),
            );

            let colour = self.palette.severity(t.severity);
            let chosen = self.selected == Some(t.id);
            painter.rect_filled(r, CornerRadius::same(4),
                                self.palette.tint(colour, if chosen { 0.55 } else { 0.28 }));
            painter.rect_stroke(r, CornerRadius::same(4),
                                Stroke::new(if chosen { 1.6 } else { 1.0 }, colour),
                                StrokeKind::Inside);

            // The label only if it fits. A bubble too narrow for text is still
            // a bubble, and clipping the text into an unreadable stub would be
            // worse than leaving it out.
            if r.width() > 46.0 {
                let label = self.bubble_label(t, r.width());
                painter.text(
                    Pos2::new(r.left() + 5.0, r.center().y),
                    egui::Align2::LEFT_CENTER,
                    label,
                    egui::TextStyle::Small.resolve(ui.style()),
                    self.palette.text,
                );
            }

            if response.clicked() {
                if let Some(pos) = response.interact_pointer_pos() {
                    if r.expand2(Vec2::new(1.0, 3.0)).contains(pos) {
                        clicked = Some(t.id);
                    }
                }
            }
        }
        out.selected = clicked;

        // ---- bookmarks --------------------------------------------------------
        for mark in self.bookmarks {
            if mark.start < view.start || mark.start > view.end {
                continue;
            }
            let x = to_x(mark.start);
            painter.line_segment(
                [Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom() - 14.0)],
                Stroke::new(1.0, self.palette.bookmark));
            painter.text(
                Pos2::new(x + 3.0, plot.top() + 2.0),
                egui::Align2::LEFT_TOP,
                &mark.label,
                egui::TextStyle::Small.resolve(ui.style()),
                self.palette.bookmark);
        }

        // ---- trigger matches --------------------------------------------------
        // Under the cursors and over the waveform: a match is a place the
        // capture is being examined for, so it has to be findable, but it is
        // not something the user placed by hand.
        for at in self.triggers {
            if *at < view.start || *at > view.end {
                continue;
            }
            let x = to_x(*at);
            painter.line_segment(
                [Pos2::new(x, plot.top() + 10.0),
                 Pos2::new(x, plot.bottom() - 14.0)],
                Stroke::new(1.0, self.palette.trigger));
            painter.circle_filled(Pos2::new(x, plot.top() + 8.0), 3.0,
                                  self.palette.trigger);
        }

        // ---- measurement cursors ---------------------------------------------
        // The shaded interval first, so both cursor lines stay legible on top
        // of it.
        if let Some((from, to)) = self.cursors.interval() {
            let r = Rect::from_min_max(
                Pos2::new(to_x(from).max(plot.left()), plot.top()),
                Pos2::new(to_x(to).min(plot.right()), plot.bottom() - 14.0));
            if r.width() > 0.0 {
                painter.rect_filled(r, CornerRadius::ZERO,
                                    self.palette.tint(self.palette.accent, 0.16));
            }
        }
        for (label, at) in [("A", self.cursors.a), ("B", self.cursors.b)] {
            let Some(at) = at else { continue };
            if at < view.start || at > view.end {
                continue;
            }
            let x = to_x(at);
            painter.line_segment(
                [Pos2::new(x, plot.top()), Pos2::new(x, plot.bottom() - 14.0)],
                Stroke::new(1.2, self.palette.accent));
            // At the top, away from the pointer's own readout and the scale
            // along the bottom, where B's label was unreadable underneath.
            painter.text(
                Pos2::new(x + 3.0, plot.top() + 2.0),
                egui::Align2::LEFT_TOP, label,
                egui::TextStyle::Small.resolve(ui.style()),
                self.palette.accent);
        }

        // ---- the pointer, and what time it is over ---------------------------
        if let (Some(pos), Some(t)) = (response.hover_pos(), out.hover_time) {
            if plot.x_range().contains(pos.x) {
                painter.line_segment(
                    [Pos2::new(pos.x, plot.top()), Pos2::new(pos.x, plot.bottom())],
                    Stroke::new(1.0, self.palette.cursor),
                );
                painter.text(
                    Pos2::new(pos.x + 4.0, plot.bottom() - 12.0),
                    egui::Align2::LEFT_BOTTOM,
                    crate::style::time_label(t),
                    egui::TextStyle::Small.resolve(ui.style()),
                    self.palette.cursor,
                );
            }
        }

        // ---- the scale --------------------------------------------------------
        painter.text(
            Pos2::new(plot.left(), plot.bottom() - 2.0),
            egui::Align2::LEFT_BOTTOM,
            crate::style::time_label(view.start),
            egui::TextStyle::Small.resolve(ui.style()),
            self.palette.dim,
        );
        painter.text(
            Pos2::new(plot.right(), plot.bottom() - 2.0),
            egui::Align2::RIGHT_BOTTOM,
            format!("{}  ({} across)",
                    crate::style::time_label(view.end),
                    crate::style::duration_label(view.span())),
            egui::TextStyle::Small.resolve(ui.style()),
            self.palette.dim,
        );

        out
    }

    /// One channel's levels across the visible window.
    fn draw_channel(
        &self,
        painter: &egui::Painter,
        plot: Rect,
        view: View,
        channel: u8,
        high: f32,
        low: f32,
    ) {
        let stroke = Stroke::new(1.4, self.palette.trace);
        for chunk in &self.capture.chunks {
            for s in channel_segments(chunk, channel, view, plot, high, low) {
                painter.line_segment(s, stroke);
            }
        }
    }

    /// As much of a transaction as fits in its bubble.
    fn bubble_label(&self, t: &Transaction, width: f32) -> String {
        let full = format!("{} {}", t.kind, t.summary);
        // Roughly six pixels a character at the small text size; measuring
        // properly per bubble costs a layout per frame per transaction.
        let fits = ((width - 10.0) / 5.6) as usize;
        if full.chars().count() <= fits {
            full
        } else if t.kind.chars().count() + 1 <= fits {
            t.kind.clone()
        } else {
            full.chars().take(fits.max(1)).collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A clock running while a data line holds still: two channels, one chunk.
    fn clock_and_still_line() -> file::SampleChunk {
        // Channel 0 toggles every 100 ns; channel 1 is high throughout. The
        // first entry is the initial state, as the format requires.
        let mut times = vec![0u64];
        let mut lines = vec![0b10u8];
        let mut level = false;
        for n in 1..=20u64 {
            level = !level;
            times.push(n * 100_000);
            lines.push(if level { 0b11 } else { 0b10 });
        }
        file::SampleChunk {
            id: 0,
            start: 0,
            end: 21 * 100_000,
            times,
            lines,
        }
    }

    fn plot() -> Rect {
        Rect::from_min_max(Pos2::new(0.0, 0.0), Pos2::new(800.0, 100.0))
    }

    /// The bug this file shipped with: every chunk entry drew a vertical, so
    /// the data line was drawn with the clock's edges and both traces looked
    /// identical.
    #[test]
    fn a_channel_that_never_moves_is_drawn_without_edges() {
        let chunk = clock_and_still_line();
        let view = View { start: 0, end: 21 * 100_000 };
        let segments = channel_segments(&chunk, 1, view, plot(), 10.0, 90.0);

        assert!(!segments.is_empty(), "the level has to be drawn");
        for [a, b] in &segments {
            assert!((a.y - b.y).abs() < 0.01,
                    "channel 1 never changes, so nothing vertical belongs in \
                     its trace - this is SDA being drawn with SCL's edges");
            assert!((a.y - 10.0).abs() < 0.01, "it is high throughout");
        }
    }

    #[test]
    fn a_channel_that_moves_is_drawn_with_an_edge_at_every_change() {
        let chunk = clock_and_still_line();
        let view = View { start: 0, end: 21 * 100_000 };
        let segments = channel_segments(&chunk, 0, view, plot(), 10.0, 90.0);

        let verticals = segments.iter()
            .filter(|[a, b]| (a.y - b.y).abs() > 0.01).count();
        let holds = segments.iter()
            .filter(|[a, b]| (a.y - b.y).abs() < 0.01).count();
        assert_eq!(holds, 21, "one hold per entry, initial state included");
        assert_eq!(verticals, 20, "one edge per change, and none before the first");
    }

    /// The initial state is what makes the trace start at a level rather than
    /// in mid air, so a window that opens after it must still find it.
    #[test]
    fn a_window_that_starts_late_still_knows_the_level() {
        let chunk = clock_and_still_line();
        let view = View { start: 1_050_000, end: 1_250_000 };
        let segments = channel_segments(&chunk, 1, view, plot(), 10.0, 90.0);
        assert!(!segments.is_empty());
        let leftmost = segments.iter()
            .map(|[a, _]| a.x).fold(f32::INFINITY, f32::min);
        assert!(leftmost <= plot().left() + 0.01,
                "the hold in force when the window opened must be drawn from \
                 its left edge");
    }

    /// Far enough out that transitions fall inside one pixel, the trace becomes
    /// a band per column rather than a line nobody can read.
    #[test]
    fn transitions_inside_one_pixel_become_a_band() {
        let chunk = clock_and_still_line();
        // Twenty transitions across eight hundred pixels is legible; the same
        // twenty across a window a thousand times wider is not.
        let view = View { start: 0, end: 21 * 100_000 * 1_000 };
        let segments = channel_segments(&chunk, 0, view, plot(), 10.0, 90.0);
        assert!(!segments.is_empty());
        assert!(segments.iter().any(|[a, b]| (a.y - b.y).abs() > 1.0),
                "a busy column has to show that both levels were in it");
        assert!(segments.len() < 30,
                "one segment per column, not per transition: got {}",
                segments.len());
    }

    #[test]
    fn zooming_keeps_the_anchor_where_it_was() {
        let mut view = View { start: 0, end: 1_000_000 };
        let anchor = 250_000;
        let before = (anchor - view.start) as f64 / view.span() as f64;
        view.zoom_about(0.5, anchor, (0, 1_000_000));
        let after = (anchor - view.start) as f64 / view.span() as f64;
        assert!((before - after).abs() < 0.01,
                "the anchor moved from {before} to {after}");
    }

    #[test]
    fn zooming_in_narrows_and_out_widens() {
        let mut view = View { start: 0, end: 1_000_000 };
        view.zoom_about(0.5, 500_000, (0, 1_000_000));
        assert!(view.span() < 1_000_000);
        let narrow = view.span();
        view.zoom_about(2.0, 500_000, (0, 1_000_000));
        assert!(view.span() > narrow);
    }

    /// Zooming without limits ends with a view a picosecond wide or one wider
    /// than the universe, and both look like the program has frozen.
    #[test]
    fn zoom_is_bounded_at_both_ends() {
        let mut view = View { start: 0, end: 1_000_000 };
        for _ in 0..200 {
            view.zoom_about(0.5, 500_000, (0, 1_000_000));
        }
        assert!(view.span() >= 1_000, "zoomed in past a nanosecond");

        for _ in 0..200 {
            view.zoom_about(2.0, 500_000, (0, 1_000_000));
        }
        assert!(view.span() <= 4_000_000,
                "zoomed out to {}, far past the capture", view.span());
    }

    #[test]
    fn panning_left_at_the_start_stops_rather_than_wrapping() {
        let mut view = View { start: 100, end: 1_100 };
        view.pan(-10_000);
        assert_eq!(view.start, 0, "an unsigned subtraction would have wrapped");
        assert_eq!(view.span(), 1_000, "the span must not change while panning");
    }

    #[test]
    fn fitting_an_interval_leaves_room_around_it() {
        let view = View::fit(1_000, 2_000);
        assert!(view.start < 1_000);
        assert!(view.end > 2_000);
    }
}
