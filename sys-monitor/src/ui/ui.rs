use std::io::{self, stdout};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use anyhow::Result;
use chrono::{DateTime, Local};
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Tabs},
    Frame, Terminal,
};
use tokio::sync::Mutex;

use sys_monitor_common::{FileDescriptorEvent, MemoryEvent, FD_OP_OPEN, FD_OP_CLOSE, FD_OP_READ, FD_OP_WRITE};
use super::{App, event::Event, EventHandler, app::TabState};
use super::event::handle_key_events;

pub fn run(app: Arc<Mutex<App>>) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    
    // Create event handler
    let event_handler = EventHandler::new(Duration::from_millis(100));
    
    loop {
        // Draw UI
        let app_lock = app.blocking_lock();

        terminal.draw(|f| render_ui::<CrosstermBackend<io::Stdout>>(f, &app_lock))?;

        // Check if we should quit
        if app_lock.should_quit {
            drop(app_lock);
            break;
        }
        
        // Handle input
        match event_handler.next()? {
            Event::Key(key) => {
                // Need to drop the lock before acquiring a mutable one
                drop(app_lock);
                
                let mut app_lock = app.blocking_lock();
                handle_key_events(key, &mut app_lock)?;
            },
            Event::Tick => {
                // Just a tick, nothing to do
            }
        }
    }
    
    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    
    Ok(())
}

fn render_ui<B: Backend>(f: &mut Frame, app: &App) {
    // Create main layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());
    
    // Render title bar
    render_tabs::<B>(f, app, chunks[0]);
    
    // Render content based on current tab
    match app.tab_state {
        TabState::Memory => render_memory_tab::<B>(f, app, chunks[1]),
        TabState::FileDescriptors => render_fd_tab::<B>(f, app, chunks[1]),
        TabState::Help => render_help_tab::<B>(f, app, chunks[1]),
    }
    
    // Render bottom bar with controls
    render_controls::<B>(f, app, chunks[2]);
}

fn render_tabs<B: Backend>(f: &mut Frame, app: &App, area: Rect) {
    let titles = vec!["Memory", "File Descriptors", "Help"];
    
    let tabs = Tabs::new(
        titles
            .iter()
            .map(|t| Line::from(vec![Span::styled(*t, Style::default().fg(Color::White))]))
            .collect::<Vec<_>>(),
    )
    .block(Block::default().borders(Borders::ALL).title("System Monitor"))
    .select(match app.tab_state {
        TabState::Memory => 0,
        TabState::FileDescriptors => 1,
        TabState::Help => 2,
    })
    .style(Style::default().fg(Color::Cyan))
    .highlight_style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );
    
    f.render_widget(tabs, area);
}

fn render_memory_tab<B: Backend>(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);
    
    // Render memory events list
    let events = app.get_memory_events();
    let items: Vec<ListItem> = events
        .iter()
        .rev()
        .map(|(time, event)| {
            let time_str = format_time(*time);
            let event_str = if event.is_alloc {
                format!("{}: PID {} allocated {:#x} bytes @ {:#x}", 
                    time_str, event.pid, event.size, event.address)
            } else {
                format!("{}: PID {} freed memory @ {:#x}", 
                    time_str, event.pid, event.address)
            };
            
            let color = if event.is_alloc { Color::Green } else { Color::Red };
            ListItem::new(Line::from(Span::styled(event_str, Style::default().fg(color))))
        })
        .collect();
    
    let events_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Memory Events"))
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_widget(events_list, chunks[0]);
    
    // Render top processes by memory usage
    let processes = app.get_top_memory_processes(10);
    
    let header_cells = ["PID", "Current Bytes", "Peak Bytes", "Total Allocs"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
    
    let header = Row::new(header_cells)
        .style(Style::default())
        .height(1);
    
    let rows = processes.iter().map(|(pid, stats)| {
        let pid_cell = Cell::from(pid.to_string());
        let current = Cell::from(format!("{} KB", stats.current_allocated_bytes / 1024));
        let peak = Cell::from(format!("{} KB", stats.peak_allocated_bytes / 1024));
        let allocs = Cell::from(stats.total_allocations.to_string());
        
        Row::new(vec![pid_cell, current, peak, allocs])
    });
    
    let table = Table::new(rows,
        [
            Constraint::Percentage(20),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(30),
        ])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Top Memory Usage"));
    
    f.render_widget(table, chunks[1]);
}

fn render_fd_tab<B: Backend>(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
        .split(area);
    
    // Render FD events list
    let events = app.get_fd_events();
    let items: Vec<ListItem> = events
        .iter()
        .rev()
        .map(|(time, event)| {
            let time_str = format_time(*time);
            
            let (op_str, color) = match event.op_type {
                FD_OP_OPEN => (format!("opened fd {}", event.fd), Color::Green),
                FD_OP_CLOSE => (format!("closed fd {}", event.fd), Color::Red),
                FD_OP_READ => (format!("read {} bytes from fd {}", event.count, event.fd), Color::Blue),
                FD_OP_WRITE => (format!("wrote {} bytes to fd {}", event.count, event.fd), Color::Yellow),
                _ => (format!("unknown op on fd {}", event.fd), Color::Gray),
            };
            
            let event_str = format!("{}: PID {} {}", time_str, event.pid, op_str);
            ListItem::new(Line::from(Span::styled(event_str, Style::default().fg(color))))
        })
        .collect();
    
    let events_list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("File Descriptor Events"))
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_widget(events_list, chunks[0]);
    
    // Render top processes by FD usage
    let processes = app.get_top_fd_processes(10);
    
    let header_cells = ["PID", "Open FDs", "Total Opens", "Read Bytes", "Write Bytes"]
        .iter()
        .map(|h| Cell::from(*h).style(Style::default().fg(Color::Yellow)));
    
    let header = Row::new(header_cells)
        .style(Style::default())
        .height(1);
    
    let rows = processes.iter().map(|(pid, stats)| {
        let pid_cell = Cell::from(pid.to_string());
        let open_fds = Cell::from(stats.open_fds.to_string());
        let total_opens = Cell::from(stats.total_opened.to_string());
        let read_bytes = Cell::from(format!("{} KB", stats.total_read_bytes / 1024));
        let write_bytes = Cell::from(format!("{} KB", stats.total_write_bytes / 1024));
        
        Row::new(vec![pid_cell, open_fds, total_opens, read_bytes, write_bytes])
    });
    
    let table = Table::new(rows,
        [
            Constraint::Percentage(15),
            Constraint::Percentage(15),
            Constraint::Percentage(20),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .header(header)
        .block(Block::default().borders(Borders::ALL).title("Top FD Usage"));
    
    f.render_widget(table, chunks[1]);
}

fn render_help_tab<B: Backend>(f: &mut Frame, app: &App, area: Rect) {
    let text = vec![
        Line::from("System Monitor Help"),
        Line::from(""),
        Line::from("This application monitors system memory allocations and file descriptor activity using eBPF."),
        Line::from(""),
        Line::from("Key bindings:"),
        Line::from("  q, Esc: Quit"),
        Line::from("  Tab: Next tab"),
        Line::from("  Shift+Tab: Previous tab"),
        Line::from("  j, Down: Scroll down"),
        Line::from("  k, Up: Scroll up"),
    ];
    
    let help = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Help"))
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Left);
    
    f.render_widget(help, area);
}

fn render_controls<B: Backend>(f: &mut Frame, app: &App, area: Rect) {
    let text = vec![
        Line::from(vec![
            Span::styled("q", Style::default().fg(Color::Yellow)),
            Span::raw(" quit | "),
            Span::styled("Tab", Style::default().fg(Color::Yellow)),
            Span::raw(" next tab | "),
            Span::styled("Shift+Tab", Style::default().fg(Color::Yellow)),
            Span::raw(" prev tab | "),
            Span::styled("↑/↓", Style::default().fg(Color::Yellow)),
            Span::raw(" scroll"),
        ]),
    ];
    
    let controls = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL))
        .style(Style::default().fg(Color::White))
        .alignment(Alignment::Center);
    
    f.render_widget(controls, area);
}

fn format_time(time: SystemTime) -> String {
    let datetime: DateTime<Local> = time.into();
    datetime.format("%H:%M:%S%.3f").to_string()
}