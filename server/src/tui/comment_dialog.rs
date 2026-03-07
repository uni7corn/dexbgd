use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Clear, Paragraph},
    text::Line,
    Frame,
};

use crate::app::App;

pub fn render(frame: &mut Frame, area: Rect, app: &App) {
    let t = &app.theme;

    let popup_area = centered_rect(60, 30, area);
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title(Line::from(" Add Comment "))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.ui_accent))
        .style(Style::default().bg(t.ui_current_bg));

    let inner = block.inner(popup_area);
    frame.render_widget(block, popup_area);

    // Address line
    let addr_str = match app.comment_address {
        Some(bci) => format!("Comment for @{:04x}", bci),
        None      => "Comment for @????".to_string(),
    };
    let addr = Paragraph::new(addr_str)
        .style(Style::default().fg(t.ui_text))
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(addr, Rect { x: inner.x, y: inner.y, width: inner.width, height: 1 });

    // Input box
    let cursor = app.comment_cursor.min(app.comment_input.len());
    let input_text = format!("{}\u{2502}{}", &app.comment_input[..cursor], &app.comment_input[cursor..]);
    let input_area = Rect { x: inner.x, y: inner.y + 2, width: inner.width, height: 3 };

    let input_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(t.ui_accent));
    frame.render_widget(input_block, input_area);

    let text_area = Rect {
        x: input_area.x + 1,
        y: input_area.y + 1,
        width: input_area.width.saturating_sub(2),
        height: 1,
    };
    let input = Paragraph::new(input_text)
        .style(Style::default().fg(t.ui_text));
    frame.render_widget(input, text_area);

    // Character count
    let len = app.comment_input.len();
    let count_color = if len > 256 {
        Color::Red
    } else if len > 220 {
        Color::Yellow
    } else {
        t.ui_dim
    };
    let count = Paragraph::new(format!("{}/256 chars", len))
        .style(Style::default().fg(count_color))
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(
        count,
        Rect { x: inner.x, y: inner.y + inner.height - 3, width: inner.width, height: 1 },
    );

    // Help line
    let help = Paragraph::new("Enter to save  Esc to cancel  empty = delete comment")
        .style(Style::default().fg(t.ui_dim))
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(
        help,
        Rect { x: inner.x, y: inner.y + inner.height - 2, width: inner.width, height: 1 },
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
