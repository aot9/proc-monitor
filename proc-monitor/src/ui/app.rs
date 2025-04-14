use super::event::{AppEvent, Event, EventHandler};
use ratatui::{
    crossterm::event::{KeyCode, KeyEvent, KeyModifiers},
    DefaultTerminal,
};
use proc_monitor_common::{FileEvent, MemoryEvent};
use std::collections::{BinaryHeap,HashMap};

/// Application.
#[derive(Debug)]
pub struct App {
    pub running: bool,
    pub events: EventHandler,
    pub file_events: Vec<FileEvent>,
    pub mem_events: Vec<MemoryEvent>,
    pub mem_events_by_tid: HashMap<u32,u64>
}

impl Default for App {
    fn default() -> Self {
        Self {
            running: true,
            events: EventHandler::new(),
            file_events: Vec::new(),
            mem_events: Vec::new(),
            mem_events_by_tid: HashMap::new()
        }
    }
}

impl App {
    /// Constructs a new instance of [`App`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Run the application's main loop.
    pub async fn run(mut self, mut terminal: DefaultTerminal) -> color_eyre::Result<()> {
        while self.running {
            terminal.draw(|frame| frame.render_widget(&self, frame.area()))?;
            match self.events.next().await? {
                Event::Tick => self.tick(),
                Event::Crossterm(event) => match event {
                    crossterm::event::Event::Key(key_event) => self.handle_key_events(key_event)?,
                    _ => {}
                },
                Event::App(app_event) => match app_event {
                    AppEvent::Quit => self.quit(),
                },
                Event::FileOpen(ev) => self.on_file_event(ev),
                Event::MemAlloc(ev) => self.on_mem_event(ev),
            }
        }
        Ok(())
    }

    /// Handles the key events and updates the state of [`App`].
    pub fn handle_key_events(&mut self, key_event: KeyEvent) -> color_eyre::Result<()> {
        match key_event.code {
            KeyCode::Esc | KeyCode::Char('q') => self.events.send(AppEvent::Quit),
            KeyCode::Char('c' | 'C') if key_event.modifiers == KeyModifiers::CONTROL => {
                self.events.send(AppEvent::Quit)
            },
            _ => {}
        }
        Ok(())
    }

    /// Handles the tick event of the terminal.
    ///
    /// The tick event is where you can update the state of your application with any logic that
    /// needs to be updated at a fixed frame rate. E.g. polling a server, updating an animation.
    pub fn tick(&self) {}

    /// Set running to false to quit the application.
    pub fn quit(&mut self) {
        self.running = false;
    }

    fn on_file_event(&mut self, ev: FileEvent) {
        self.file_events.push(ev);
    }

    fn on_mem_event(&mut self, ev: MemoryEvent) {
        *self.mem_events_by_tid.entry(ev.tid).or_insert(0) += ev.size as u64;
        self.mem_events.push(ev);
    }

    pub fn get_top_allocating_tids(&self, n: usize) -> Vec<(u32, u64)> {
        self.mem_events_by_tid
            .iter()
            .map(|(&tid, &count)| (count, tid))
            .collect::<BinaryHeap<_>>()
            .into_iter()
            .take(n)
            .map(|(count, tid)| (tid, count))
            .collect()
    }
}
