use ratatui::{
    prelude::*,
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::Color,
    widgets::{Block, Widget, Borders, Cell, Row, Table},
};

use super::app::App;

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024; const MIB: u64 = 1024 * KIB; const GIB: u64 = 1024 * MIB; const TIB: u64 = 1024 * GIB;
    if bytes >= TIB { format!("{:.2} TiB", bytes as f64 / TIB as f64) }
    else if bytes >= GIB { format!("{:.2} GiB", bytes as f64 / GIB as f64) }
    else if bytes >= MIB { format!("{:.2} MiB", bytes as f64 / MIB as f64) }
    else if bytes >= KIB { format!("{:.2} KiB", bytes as f64 / KIB as f64) }
    else { format!("{} B", bytes) }
}

fn render_top_alloc_table(app: &App, layout: Rect, buf: &mut Buffer) {
    let top_tids_data = app.get_top_allocating_tids(10);

    let header_cells = ["Thread ID (TID)", "Total Allocated"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::DarkGray))
        .height(1) 
        .bottom_margin(1);

    let rows = top_tids_data.iter().map(|(tid, total_size)| {
        let tid_str = tid.to_string();
        let size_str = format_bytes(*total_size);

        let cells = vec![
            Cell::from(tid_str), 
            Cell::from(size_str), 
        ];
        Row::new(cells).height(1)
    });

    let widths = [
        Constraint::Length(20),
        Constraint::Length(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Top Allocating Threads ")
                .title_alignment(Alignment::Center)
                .border_type(ratatui::widgets::BorderType::Rounded),
        );
    Widget::render(table, layout, buf);
}

fn render_alloc_events_table(app: &App, layout: Rect, buf: &mut Buffer) {
    let header_cells = ["Timestamp", "Thread ID (TID)", "Address", "Size"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::DarkGray))
        .height(1) 
        .bottom_margin(1);

    let events_to_display = &app.mem_events[app.mem_events.len().saturating_sub(50)..];
    let rows = events_to_display
        .iter()
        .map(|event| {
            let cells = vec![
                Cell::from(event.timestamp.to_string()),
                Cell::from(event.tid.to_string()),
                Cell::from(format!("{:#010x}", event.address)),
                Cell::from(format_bytes(event.size as u64)),
            ];
            Row::new(cells).height(1)
    });

    let widths = [
        Constraint::Length(20),
        Constraint::Length(10),
        Constraint::Length(20),
        Constraint::Length(20),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Malloc events ")
                .title_alignment(Alignment::Center)
                .border_type(ratatui::widgets::BorderType::Rounded),
        );
    Widget::render(table, layout, buf);
}

fn render_file_events_table(app: &App, layout: Rect, buf: &mut Buffer) {
    let header_cells = ["Timestamp", "Thread ID (TID)", "Filename"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)));
    let header = Row::new(header_cells)
        .style(Style::default().bg(Color::DarkGray))
        .height(1) 
        .bottom_margin(1);

    let events_to_display = &app.file_events[app.file_events.len().saturating_sub(50)..];
    let rows = events_to_display
        .iter()
        .map(|event| {
            let cells = vec![
                Cell::from(event.timestamp.to_string()),
                Cell::from(event.tid.to_string()),
                Cell::from(core::str::from_utf8(&event.filename).unwrap()),
            ];
            Row::new(cells).height(1)
    });

    let widths = [
        Constraint::Length(20),
        Constraint::Length(10),
        Constraint::Length(64),
    ];

    let table = Table::new(rows, widths)
        .header(header)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" File events ")
                .title_alignment(Alignment::Center)
                .border_type(ratatui::widgets::BorderType::Rounded),
        );
    Widget::render(table, layout, buf);
}

impl Widget for &App {
    /// Renders the user interface widgets.
    ///
    // This is where you add new widgets.
    // See the following resources:
    // - https://docs.rs/ratatui/latest/ratatui/widgets/index.html
    // - https://github.com/ratatui/ratatui/tree/master/examples
    fn render(self, area: Rect, buf: &mut Buffer) {
        let main_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        let left_sub_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(main_layout[0]);

        render_alloc_events_table(&self, left_sub_layout[0], buf);
        render_top_alloc_table(&self, left_sub_layout[1], buf);
        render_file_events_table(&self, main_layout[1], buf);
    }
}
