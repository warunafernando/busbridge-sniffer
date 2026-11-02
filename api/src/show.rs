//! The waveform, in a terminal.
//!
//! Appendix D's third step is to display raw SDA/SCL with inline decode. The
//! GUI that eventually does that properly is phase 4; this is the same
//! information now, and it is worth having on its own terms - a terminal
//! waveform goes in a bug report, a screenshot does not diff.
//!
//! It renders from the same capture and the same decoded transactions the GUI
//! will, so if this shows the wrong thing the fault is in the data and not in
//! the drawing. That is most of why it exists before the renderer does.

use schema::{Decoded, Picos};

/// Draw the interval `from..to` across `width` columns.
pub fn waveform(
    cap: &file::Capture,
    decoded: &Decoded,
    from: Picos,
    to: Picos,
    width: usize,
) {
    let width = width.clamp(20, 400);
    if to <= from {
        println!("(nothing to show: the interval is empty)");
        return;
    }
    let span = (to - from) as f64;

    // On stdout, above the picture, and not only on stderr where open() says
    // it. A waveform is the one view whose whole purpose is reading time off an
    // axis, and the one most likely to be redirected to a file or pasted into a
    // report - at which point a warning that went to stderr is no longer
    // attached to the thing it was warning about.
    if let Some(warning) = cap.session.timing.warning() {
        println!("!! {warning}");
        println!();
    }

    // One row per channel, filled by walking the transitions and holding each
    // level until the next one - which is what a transition-encoded capture
    // means and the reason a renderer must not just plot the edges.
    let channels = cap.session.channels.len().max(2);
    let mut rows: Vec<Vec<Option<bool>>> = vec![vec![None; width]; channels];

    for chunk in &cap.chunks {
        for i in 0..chunk.len() {
            let t = chunk.times[i];
            let next = chunk.times.get(i + 1).copied().unwrap_or(cap.index.last_time);
            if next < from || t > to {
                continue;
            }
            let a = column(t.max(from), from, span, width);
            let b = column(next.min(to), from, span, width);
            for (c, row) in rows.iter_mut().enumerate() {
                let level = chunk.lines[i] & (1 << c) != 0;
                for col in row.iter_mut().take(b.max(a) + 1).skip(a) {
                    *col = Some(level);
                }
            }
        }
    }

    println!();
    for (c, row) in rows.iter().enumerate() {
        let name = cap.session.channels.get(c)
            .cloned()
            .unwrap_or_else(|| format!("ch{c}"));
        // Two lines per channel: the high level and the low one, so a square
        // wave looks like a square wave rather than a row of dashes.
        let top: String = row.iter().map(|v| match v {
            Some(true) => '─',
            Some(false) => ' ',
            None => '·',
        }).collect();
        let bottom: String = row.iter().map(|v| match v {
            Some(true) => ' ',
            Some(false) => '─',
            None => '·',
        }).collect();
        println!("{:>5} ┤{top}", name);
        println!("{:>5} ┤{bottom}", "");
    }

    // Gaps first: a hole in the capture changes how everything above it should
    // be read, so it is not a footnote.
    for gap in &cap.gaps {
        if gap.end < from || gap.start > to {
            continue;
        }
        let a = column(gap.start.max(from), from, span, width);
        let b = column(gap.end.min(to), from, span, width);
        let mut bar = vec![' '; width];
        for col in bar.iter_mut().take((b + 1).min(width)).skip(a) {
            *col = '#';
        }
        println!("{:>5} ┤{}", "GAP", bar.into_iter().collect::<String>());
        println!("        {} ({})", gap.reason,
                 match gap.lost {
                     Some(n) => format!("{n} lost"),
                     None => "amount unknown".into(),
                 });
    }

    // The decode, underneath, positioned where it happened.
    let mut any = false;
    for t in &decoded.transactions {
        if t.end < from || t.start > to {
            continue;
        }
        any = true;
        let a = column(t.start.max(from), from, span, width);
        let b = column(t.end.min(to), from, span, width);
        let mut bar = vec![' '; width];
        if a < width {
            bar[a] = '├';
        }
        for col in bar.iter_mut().take(b.min(width.saturating_sub(1))).skip(a + 1) {
            *col = '─';
        }
        if b < width && b > a {
            bar[b] = '┤';
        }
        println!("{:>5} ┤{}", "", bar.into_iter().collect::<String>());

        let label = format!("#{} {} {}{}", t.id, t.kind, t.summary,
                            if t.complete { "" } else { "  [incomplete]" });
        let indent = " ".repeat(7 + a.min(width.saturating_sub(1)));
        println!("{indent}{label}");
    }
    if !any {
        println!("      (no decoded transaction in this interval)");
    }

    println!();
    println!("      {:.3} us {:>width$.3} us",
             from as f64 / 1_000_000.0, to as f64 / 1_000_000.0,
             width = width.saturating_sub(12));
}

fn column(t: Picos, from: Picos, span: f64, width: usize) -> usize {
    let x = ((t.saturating_sub(from)) as f64 / span * (width - 1) as f64).round();
    (x as usize).min(width - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn columns_stay_inside_the_width() {
        let width = 50;
        for t in [0u64, 1, 999, 1_000, 5_000] {
            let c = column(t, 0, 1_000.0, width);
            assert!(c < width, "t={t} produced column {c}");
        }
    }

    #[test]
    fn the_first_and_last_columns_are_the_ends_of_the_interval() {
        assert_eq!(column(100, 100, 900.0, 40), 0);
        assert_eq!(column(1_000, 100, 900.0, 40), 39);
    }

    /// A time before the interval must clamp rather than wrap, which an
    /// unsigned subtraction would do loudly in debug and silently in release.
    #[test]
    fn a_time_before_the_interval_clamps_to_the_start() {
        assert_eq!(column(50, 100, 900.0, 40), 0);
    }
}
