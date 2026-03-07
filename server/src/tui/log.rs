use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, LogEntry, LogLevel};
use super::make_block;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == 3;
    let t = &app.theme;
    let block = make_block(" Log ", focused, t);

    let inner_height = area.height.saturating_sub(2) as usize;
    if inner_height == 0 || app.log.is_empty() {
        let text = Paragraph::new("(no log entries)")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    // Auto-scroll to bottom, or use manual scroll
    let total = app.log.len();
    let scroll = if app.log_auto_scroll {
        total.saturating_sub(inner_height)
    } else {
        app.log_scroll
    };

    // Normalize selection to (r0, c0, r1, c1): r0 <= r1; if r0==r1 then c0 <= c1.
    // c1 == usize::MAX means "selection extends to end of line" (middle rows).
    let sel_full: Option<(usize, usize, usize, usize)> = match (app.log_sel_anchor, app.log_sel_head) {
        (Some(a), Some(h)) if a != h => {
            if a.0 < h.0 || (a.0 == h.0 && a.1 <= h.1) {
                Some((a.0, a.1, h.0, h.1))
            } else {
                Some((h.0, h.1, a.0, a.1))
            }
        }
        _ => None,
    };
    let sel_bg = t.ui_highlight_bg;

    let lines: Vec<Line> = app
        .log
        .iter()
        .enumerate()
        .skip(scroll)
        .take(inner_height)
        .map(|(abs_i, entry)| {
            // Compute the column range selected within this row.
            //   None         → row not selected
            //   Some((s, e)) → highlight cols [s, e); e==usize::MAX means "to end of line"
            let sel_cols = sel_full.and_then(|(r0, c0, r1, c1)| {
                if abs_i < r0 || abs_i > r1 {
                    None
                } else {
                    let start = if abs_i == r0 { c0 } else { 0 };
                    let end   = if abs_i == r1 { c1 } else { usize::MAX };
                    Some((start, end))
                }
            });
            format_entry(entry, t.ui_text, sel_cols, sel_bg)
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

/// Rendered line layout (display columns):
///   [0, 7)  → prefix span, e.g. "[INFO] " (always 7 chars for every level)
///   [7, 8)  → separator space
///   [8, …)  → entry text
fn format_entry(
    entry: &LogEntry,
    text_color: Color,
    sel_cols: Option<(usize, usize)>,  // (start_col, end_col); usize::MAX = end of line
    sel_bg: Color,
) -> Line<'static> {
    let (prefix, prefix_color) = match entry.level {
        LogLevel::Info      => ("[INFO] ", Color::Rgb(100, 160, 220)),
        LogLevel::Error     => ("[ERR]  ", Color::Rgb(210, 90, 80)),
        LogLevel::Crypto    => ("[CRYPT]", Color::Magenta),
        LogLevel::Exception => ("[EXCP] ", Color::Rgb(210, 90, 80)),
        LogLevel::Debug     => ("[DBG]  ", Color::Green),
        LogLevel::Agent     => ("[AGNT] ", Color::Cyan),
        LogLevel::Call      => ("[CALL] ", Color::Yellow),
    };

    let prefix_normal = Style::default().fg(prefix_color);
    let space_normal  = Style::default();
    let text_normal   = Style::default().fg(text_color);

    let Some((sel_start, sel_end)) = sel_cols else {
        // Fast path: no selection for this row
        return Line::from(vec![
            Span::styled(prefix, prefix_normal),
            Span::styled(" ", space_normal),
            Span::styled(entry.text.clone(), text_normal),
        ]);
    };

    let prefix_sel = prefix_normal.bg(sel_bg);
    let space_sel  = space_normal.bg(sel_bg);
    let text_sel   = text_normal.bg(sel_bg);

    let mut spans: Vec<Span<'static>> = Vec::new();
    // prefix at display cols [0, 7)
    spans.extend(split_at_sel(prefix,       0, sel_start, sel_end, prefix_normal, prefix_sel));
    // separator at display col  [7, 8)
    spans.extend(split_at_sel(" ",          7, sel_start, sel_end, space_normal,  space_sel));
    // entry text at display cols [8, …)
    spans.extend(split_at_sel(&entry.text,  8, sel_start, sel_end, text_normal,   text_sel));

    Line::from(spans)
}

/// Split a span string into up to 3 sub-spans: before selection, inside, after.
///
/// `span_col`  – display column where this span starts.
/// `sel_start` / `sel_end` – absolute selection columns; `sel_end == usize::MAX` means
///              the selection runs to the end of the span.
fn split_at_sel(
    s: &str,
    span_col: usize,
    sel_start: usize,
    sel_end: usize,
    normal: Style,
    selected: Style,
) -> Vec<Span<'static>> {
    let chars: Vec<char> = s.chars().collect();
    let span_len = chars.len();

    // No overlap: entire span is outside the selection
    if sel_end != usize::MAX && sel_end <= span_col || sel_start >= span_col + span_len {
        if span_len == 0 { return vec![]; }
        return vec![Span::styled(chars.iter().collect::<String>(), normal)];
    }

    let rel_start = sel_start.saturating_sub(span_col).min(span_len);
    let rel_end   = if sel_end == usize::MAX {
        span_len
    } else {
        sel_end.saturating_sub(span_col).min(span_len)
    };

    let mut spans = Vec::new();
    if rel_start > 0 {
        spans.push(Span::styled(chars[..rel_start].iter().collect::<String>(), normal));
    }
    if rel_start < rel_end {
        spans.push(Span::styled(chars[rel_start..rel_end].iter().collect::<String>(), selected));
    }
    if rel_end < span_len {
        spans.push(Span::styled(chars[rel_end..].iter().collect::<String>(), normal));
    }
    spans
}
