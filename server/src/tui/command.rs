use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;
    let block = Block::default()
        .title(" Command ")
        .borders(Borders::ALL)
        .border_style(if app.command_focused {
            Style::default().fg(t.ui_accent)
        } else {
            Style::default().fg(t.ui_dim)
        });

    if app.command_focused {
        let text = &app.command_input;
        let cursor = app.command_cursor;

        // Cursor character (or a space block at end-of-input)
        let (cursor_ch, cursor_end) = if cursor < text.len() {
            let c_len = text[cursor..].chars().next().map(|c| c.len_utf8()).unwrap_or(0);
            (&text[cursor..cursor + c_len], cursor + c_len)
        } else {
            (" ", cursor)
        };

        let normal = Style::default().fg(t.ui_text).bg(t.ui_current_bg);
        let sel    = Style::default().fg(t.ui_text).bg(t.ui_highlight_bg);
        let cur    = Style::default().fg(t.ui_bg).bg(t.ui_text);
        let prefix = Span::styled(
            " > ",
            Style::default().fg(t.ui_bg).bg(t.ui_accent).add_modifier(Modifier::BOLD),
        );

        let spans: Vec<Span> = if let Some(anchor) = app.command_sel_anchor {
            let sel_min = cursor.min(anchor);
            let sel_max = cursor.max(anchor);

            if sel_min == sel_max {
                // Degenerate: anchor == cursor, no visible selection
                vec![
                    prefix,
                    Span::styled(&text[..cursor], normal),
                    Span::styled(cursor_ch, cur),
                    Span::styled(&text[cursor_end..], normal),
                ]
            } else if cursor <= anchor {
                // Cursor is at the LEFT edge of the selection
                // [normal before][cursor][selected rest][normal after]
                vec![
                    prefix,
                    Span::styled(&text[..cursor], normal),
                    Span::styled(cursor_ch, cur),
                    Span::styled(&text[cursor_end..sel_max], sel),
                    Span::styled(&text[sel_max..], normal),
                ]
            } else {
                // Cursor is at the RIGHT edge of the selection
                // [normal before][selected][cursor][normal after]
                vec![
                    prefix,
                    Span::styled(&text[..sel_min], normal),
                    Span::styled(&text[sel_min..cursor], sel),
                    Span::styled(cursor_ch, cur),
                    Span::styled(&text[cursor_end..], normal),
                ]
            }
        } else {
            // No selection: standard cursor rendering
            vec![
                prefix,
                Span::styled(&text[..cursor], normal),
                Span::styled(cursor_ch, cur),
                Span::styled(&text[cursor_end..], normal),
            ]
        };

        let line = Line::from(spans);
        let para = Paragraph::new(line)
            .block(block)
            .style(Style::default().bg(t.ui_current_bg));
        f.render_widget(para, area);
    } else {
        let line = Line::from(vec![
            Span::styled(
                " : ",
                Style::default().fg(t.ui_dim),
            ),
            Span::styled(
                "type to enter command...",
                Style::default().fg(t.ui_dim),
            ),
        ]);

        let para = Paragraph::new(line)
            .block(block)
            .style(Style::default().bg(t.ui_bg));
        f.render_widget(para, area);
    }
}
