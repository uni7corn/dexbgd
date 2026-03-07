use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, AppState, Bookmark, HeapRow, RightTab};
use crate::commands::{short_class, short_type};
use super::make_block;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == 2;
    let t = &app.theme;

    let tabs = [
        ("Stack", RightTab::Stack),
        ("BP", RightTab::Breakpoints),
        ("Thd", RightTab::Threads),
        ("Watch", RightTab::Watch),
        ("Heap", RightTab::Heap),
        ("Bookmarks", RightTab::Bookmarks),
    ];

    let mut title_parts = String::from(" ");
    for (name, tab) in &tabs {
        if *tab == app.right_tab {
            title_parts.push_str(&format!("[{}]", name));
        } else {
            title_parts.push_str(name);
        }
        title_parts.push(' ');
    }

    let block = make_block(title_parts.as_str(), focused, t);
    let inner_height = area.height.saturating_sub(2) as usize;

    match app.right_tab {
        RightTab::Stack => draw_stack(f, app, area, block, inner_height),
        RightTab::Breakpoints => draw_breakpoints(f, app, area, block, inner_height),
        RightTab::Threads => draw_threads(f, app, area, block, inner_height),
        RightTab::Watch => draw_watch(f, app, area, block, inner_height),
        RightTab::Heap => draw_heap(f, app, area, block, inner_height),
        RightTab::Bookmarks => draw_bookmarks(f, app, area, block, inner_height),
    }
}

fn draw_stack(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>, inner_height: usize) {
    let t = &app.theme;
    if app.stack.is_empty() {
        let text = Paragraph::new("(no stack)")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let scroll = app.tabbed_scroll;
    let lines: Vec<Line> = app
        .stack
        .iter()
        .skip(scroll)
        .take(inner_height)
        .map(|frame| {
            let cls = short_class(&frame.class);
            let line_info = if frame.line >= 0 {
                format!(":{}", frame.line)
            } else {
                String::new()
            };
            Line::from(vec![
                Span::styled(
                    format!("#{} ", frame.depth),
                    Style::default().fg(t.ui_dim),
                ),
                Span::styled(
                    format!("{}.{}", cls, frame.method),
                    Style::default().fg(t.ui_text),
                ),
                Span::styled(line_info, Style::default().fg(t.ui_value)),
            ])
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_breakpoints(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>, inner_height: usize) {
    let t = &app.theme;
    if app.bp_manager.breakpoints.is_empty() {
        let text = Paragraph::new("(no breakpoints)")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let scroll = app.tabbed_scroll;
    let lines: Vec<Line> = app
        .bp_manager
        .breakpoints
        .iter()
        .skip(scroll)
        .take(inner_height)
        .map(|bp| {
            let cls = short_class(&bp.class);
            let pending = app.bp_manager.is_pending(bp.id);
            let mut spans = vec![
                Span::styled(
                    format!("#{} ", bp.id),
                    Style::default().fg(t.ui_accent).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{}.{}", cls, bp.method),
                    Style::default().fg(if pending { t.ui_dim } else { t.ui_text }),
                ),
            ];
            if pending {
                spans.push(Span::styled(
                    " [pending]",
                    Style::default().fg(Color::Yellow),
                ));
            } else {
                spans.push(Span::styled(
                    format!(" @{:04x}", bp.location),
                    Style::default().fg(t.ui_dim),
                ));
            }
            // Show condition and hit count if present
            if let Some(cond) = app.bp_manager.get_condition(bp.id) {
                let mut cond_parts = Vec::new();
                if let Some(ref hit) = cond.hit_condition {
                    cond_parts.push(format!("{}", hit));
                }
                if let Some(ref expr) = cond.var_condition {
                    cond_parts.push(format!("when {}", expr));
                }
                if !cond_parts.is_empty() {
                    spans.push(Span::styled(
                        format!(" [{}]", cond_parts.join(", ")),
                        Style::default().fg(t.ui_value),
                    ));
                }
                if cond.hit_count > 0 {
                    spans.push(Span::styled(
                        format!(" ({}x)", cond.hit_count),
                        Style::default().fg(t.ui_dim),
                    ));
                }
            }
            Line::from(spans)
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_threads(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>, inner_height: usize) {
    let t = &app.theme;
    if app.threads.is_empty() {
        let text = Paragraph::new("(no thread data)")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let scroll = app.tabbed_scroll;
    let lines: Vec<Line> = app
        .threads
        .iter()
        .skip(scroll)
        .take(inner_height)
        .map(|thd| {
            let daemon = if thd.daemon { " (daemon)" } else { "" };
            Line::from(vec![
                Span::styled(&thd.name, Style::default().fg(t.ui_text)),
                Span::styled(
                    format!(" pri={}{}", thd.priority, daemon),
                    Style::default().fg(t.ui_dim),
                ),
            ])
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_watch(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>, inner_height: usize) {
    let t = &app.theme;
    if app.watches.is_empty() {
        let text = Paragraph::new("(no watches)  Enter to add  |  watch <expr>")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let focused = app.focus == 2;
    let cursor = app.watch_selected.min(app.watches.len().saturating_sub(1));
    let scroll = if cursor >= inner_height { cursor.saturating_sub(inner_height - 1) } else { 0 };
    // Values are "stale" (shown dimmed) while the app is running
    let stale = !matches!(app.state, AppState::Suspended | AppState::Stepping);

    let lines: Vec<Line> = app
        .watches
        .iter()
        .enumerate()
        .skip(scroll)
        .take(inner_height)
        .map(|(i, watch)| {
            let selected = focused && i == cursor;

            let (expr_style, sep_style, ty_style, val_style) = if selected {
                let s = Style::default().fg(t.ui_bg).bg(t.ui_accent);
                (s, s, s, s)
            } else if stale {
                let dim = Style::default().fg(t.ui_dim);
                (dim, dim, dim, dim)
            } else {
                (
                    Style::default().fg(t.ui_text),
                    Style::default().fg(t.ui_dim),
                    Style::default().fg(t.ui_dim),
                    Style::default().fg(t.ui_value),
                )
            };

            match (&watch.last_value, &watch.last_type) {
                (Some(val), Some(ty)) => {
                    let short_ty = short_type(ty);
                    Line::from(vec![
                        Span::styled(watch.expr.clone(), expr_style),
                        Span::styled(" = ", sep_style),
                        Span::styled(format!("({}) ", short_ty), ty_style),
                        Span::styled(val.clone(), val_style),
                    ])
                }
                _ => Line::from(vec![
                    Span::styled(watch.expr.clone(), expr_style),
                    Span::styled("  —", sep_style),
                ]),
            }
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_bookmarks(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>, inner_height: usize) {
    let t = &app.theme;
    if app.bookmarks.is_empty() {
        let text = Paragraph::new("(no bookmarks)  Ctrl+B to add")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let focused = app.focus == 2;
    let cursor = app.bookmarks_cursor.min(app.bookmarks.len().saturating_sub(1));

    // Auto-scroll to keep cursor visible (same pattern as Heap)
    let scroll = if cursor >= inner_height {
        cursor.saturating_sub(inner_height - 1)
    } else {
        0
    };

    let lines: Vec<Line> = app
        .bookmarks
        .iter()
        .enumerate()
        .skip(scroll)
        .take(inner_height)
        .map(|(i, bm): (usize, &Bookmark)| {
            let cls = short_class(&bm.class);
            let selected = focused && i == cursor;
            if selected {
                Line::from(vec![
                    Span::styled(
                        format!("{}.{}", cls, bm.method),
                        Style::default().fg(t.ui_bg).bg(t.ui_accent),
                    ),
                    Span::styled(
                        format!("+{:#x} ", bm.offset),
                        Style::default().fg(t.ui_bg).bg(t.ui_accent),
                    ),
                    Span::styled(
                        bm.label.clone(),
                        Style::default().fg(t.ui_bg).bg(t.ui_accent),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(
                        format!("{}.{}", cls, bm.method),
                        Style::default().fg(t.ui_text),
                    ),
                    Span::styled(
                        format!("+{:#x} ", bm.offset),
                        Style::default().fg(t.ui_dim),
                    ),
                    Span::styled(
                        bm.label.clone(),
                        Style::default().fg(t.ui_value),
                    ),
                ])
            }
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_heap(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>, inner_height: usize) {
    let t = &app.theme;
    if app.heap_rows.is_empty() {
        let text = Paragraph::new("Use: heap <class> or heapstr <pattern>")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let focused = app.focus == 2;

    // Auto-scroll to keep selection visible
    let scroll = if app.heap_selected >= inner_height {
        app.heap_selected.saturating_sub(inner_height - 1)
    } else {
        0
    };

    let lines: Vec<Line> = app.heap_rows.iter().enumerate()
        .skip(scroll)
        .take(inner_height)
        .map(|(i, row)| {
            let selected = focused && i == app.heap_selected;
            match row {
                HeapRow::Header(text) => {
                    Line::from(Span::styled(
                        text.clone(),
                        Style::default().fg(t.ui_value).add_modifier(Modifier::BOLD),
                    ))
                }
                HeapRow::Object { index, value } => {
                    let sel = if selected {
                        Style::default().fg(Color::Black).bg(t.ui_accent)
                    } else {
                        Style::default()
                    };
                    Line::from(vec![
                        Span::styled(
                            format!("[{}] ", index),
                            if selected { sel } else { Style::default().fg(t.ui_dim) },
                        ),
                        Span::styled(value.clone(), sel),
                    ])
                }
                HeapRow::StringMatch { index, value } => {
                    let sel = if selected {
                        Style::default().fg(Color::Black).bg(t.ui_accent)
                    } else {
                        Style::default()
                    };
                    Line::from(vec![
                        Span::styled(
                            format!("[{}] ", index),
                            if selected { sel } else { Style::default().fg(t.ui_dim) },
                        ),
                        Span::styled(
                            format!("\"{}\"", value),
                            if selected { sel } else { Style::default().fg(Color::Green) },
                        ),
                    ])
                }
            }
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}
