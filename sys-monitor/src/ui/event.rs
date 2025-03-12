use std::sync::Arc;
use std::time::{Duration, Instant};
use anyhow::Result;
use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyCode, KeyModifiers};
use tokio::sync::Mutex;

use super::App;

pub enum Event {
    Key(KeyEvent),
    Tick,
}

pub struct EventHandler {
    tick_rate: Duration,
}

impl EventHandler {
    pub fn new(tick_rate: Duration) -> Self {
        Self { tick_rate }
    }
    
    pub fn next(&self) -> Result<Event> {
        // Poll for key events but timeout after tick_rate
        if event::poll(self.tick_rate)? {
            if let CrosstermEvent::Key(key) = event::read()? {
                return Ok(Event::Key(key));
            }
        }
        
        // If no events were available, return a tick event
        Ok(Event::Tick)
    }
}

pub fn handle_key_events(key_event: KeyEvent, app: &mut App) -> Result<()> {
    match key_event.code {
        // Quit
        KeyCode::Char('q') | KeyCode::Esc => {
            app.quit();
        },
        // Tab navigation
        KeyCode::Tab => {
            app.next_tab();
        },
        KeyCode::BackTab => {
            app.prev_tab();
        },
        // Scrolling
        KeyCode::Down | KeyCode::Char('j') => {
            app.scroll_down();
        },
        KeyCode::Up | KeyCode::Char('k') => {
            app.scroll_up();
        },
        _ => {}
    }
    
    Ok(())
}