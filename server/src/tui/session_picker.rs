use ratatui::{
    layout::Rect,
    style::{Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    text::Line,
    Frame,
};

use crate::app::App;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;

    let list_height = (app.session_picker_list.len().max(1) as u16 + 2).min(20);
    let popup_h = list_height + 4; // list box + help line + padding
    let popup_w = 60u16;

    let popup_area = centered_rect_fixed(popup_w, popup_h, area);
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Line::from(" Launch Session "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.ui_accent))
        .style(Style::default().bg(t.ui_current_bg));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    if app.session_picker_list.is_empty() {
        let msg = Paragraph::new("No sessions saved yet")
            .style(Style::default().fg(t.ui_dim))
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(msg, Rect { x: inner.x, y: inner.y + 1, width: inner.width, height: 1 });
    } else {
        // List area (all but last line)
        let list_area = Rect {
            x: inner.x,
            y: inner.y,
            width: inner.width,
            height: inner.height.saturating_sub(2),
        };

        let items: Vec<ListItem> = app.session_picker_list
            .iter()
            .map(|pkg| ListItem::new(pkg.as_str()))
            .collect();

        let list = List::new(items)
            .style(Style::default().fg(t.ui_text))
            .highlight_style(
                Style::default()
                    .fg(t.ui_bg)
                    .bg(t.ui_accent)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("> ");

        let mut state = ListState::default();
        state.select(Some(app.session_picker_sel));
        frame.render_stateful_widget(list, list_area, &mut state);
    }

    // Help line at the bottom
    let help_text = if app.session_picker_list.is_empty() {
        "Esc to cancel"
    } else {
        "Enter=attach  Esc=cancel"
    };
    let help = Paragraph::new(help_text)
        .style(Style::default().fg(t.ui_dim))
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(
        help,
        Rect { x: inner.x, y: inner.y + inner.height - 1, width: inner.width, height: 1 },
    );
}

fn centered_rect_fixed(width: u16, height: u16, r: Rect) -> Rect {
    let x = r.x + r.width.saturating_sub(width) / 2;
    let y = r.y + r.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width: width.min(r.width),
        height: height.min(r.height),
    }
}
