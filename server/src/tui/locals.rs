use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;

use crate::app::{App, LocalsTab};
use crate::commands::short_type;
use super::make_block;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let focused = app.focus == 1;
    let t = &app.theme;

    let tabs = [
        ("Locals", LocalsTab::Locals),
        ("Registers", LocalsTab::Registers),
    ];

    let mut title = String::from(" ");
    for (name, tab) in &tabs {
        if *tab == app.locals_tab {
            title.push_str(&format!("[{}]", name));
        } else {
            title.push_str(name);
        }
        title.push(' ');
    }

    let block = make_block(title.as_str(), focused, t);
    let inner_height = area.height.saturating_sub(2) as usize;

    match app.locals_tab {
        LocalsTab::Locals => draw_locals(f, app, area, block, inner_height),
        LocalsTab::Registers => draw_registers(f, app, area, block, inner_height),
    }
}

fn draw_locals(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>, inner_height: usize) {
    let t = &app.theme;
    if app.locals.is_empty() {
        let text = Paragraph::new("(no locals)")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let scroll = app.locals_scroll;

    let lines: Vec<Line> = app
        .locals
        .iter()
        .skip(scroll)
        .take(inner_height)
        .map(|var| {
            let type_str = short_type(&var.var_type);
            if var.stale {
                Line::from(vec![
                    Span::styled(
                        format!("{}: {} ", var.name, type_str),
                        Style::default().fg(t.ui_dim),
                    ),
                    Span::styled(
                        "(out of scope)",
                        Style::default().fg(t.ui_dim).add_modifier(Modifier::ITALIC),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(
                        format!("{}", var.name),
                        Style::default().fg(t.ui_text).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!(": {} = ", type_str),
                        Style::default().fg(t.ui_dim),
                    ),
                    Span::styled(
                        truncate(&var.value, 60),
                        Style::default().fg(t.ui_value),
                    ),
                ])
            }
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn draw_registers(f: &mut Frame, app: &App, area: Rect, block: ratatui::widgets::Block<'_>, inner_height: usize) {
    let t = &app.theme;
    if app.locals.is_empty() {
        let text = Paragraph::new("(no register data)")
            .block(block)
            .style(Style::default().fg(t.ui_dim));
        f.render_widget(text, area);
        return;
    }

    let scroll = app.locals_scroll;

    // Sort by slot number for register view
    let mut sorted: Vec<_> = app.locals.iter().collect();
    sorted.sort_by_key(|v| v.slot);

    let lines: Vec<Line> = sorted
        .iter()
        .skip(scroll)
        .take(inner_height)
        .map(|var| {
            let type_str = short_type(&var.var_type);
            let name_hint = if var.name.is_empty() || var.name == "?" {
                String::new()
            } else {
                format!(" ({})", var.name)
            };
            if var.stale {
                Line::from(vec![
                    Span::styled(
                        format!("v{:<3}", var.slot),
                        Style::default().fg(t.ui_dim),
                    ),
                    Span::styled(
                        format!("{}{} (out of scope)", type_str, name_hint),
                        Style::default().fg(t.ui_dim).add_modifier(Modifier::ITALIC),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(
                        format!("v{:<3}", var.slot),
                        Style::default().fg(t.ui_accent).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("{}", type_str),
                        Style::default().fg(t.ui_dim),
                    ),
                    Span::styled(
                        format!(" = {}", truncate(&var.value, 50)),
                        Style::default().fg(t.ui_value),
                    ),
                    Span::styled(
                        name_hint,
                        Style::default().fg(t.ui_dim),
                    ),
                ])
            }
        })
        .collect();

    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max - 3])
    }
}
