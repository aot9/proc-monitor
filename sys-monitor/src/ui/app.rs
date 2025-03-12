use std::time::{Duration, SystemTime};
use std::collections::VecDeque;
use sys_monitor_common::{MemoryEvent, FileDescriptorEvent};
use crate::trackers::{memory::{MemoryTracker, ProcessMemoryStats}, fd::{FdTracker, ProcessFdStats}};

// Available UI tabs
#[derive(Copy, Clone, PartialEq)]
pub enum TabState {
    Memory,
    FileDescriptors,
    Help,
}

// Application state
pub struct App {
    // Current UI state
    pub should_quit: bool,
    pub tab_state: TabState,
    pub scroll_state: usize,
    
    // Monitoring data
    memory_tracker: MemoryTracker,
    fd_tracker: FdTracker,
    
    // Recent events for display
    memory_events: VecDeque<(SystemTime, MemoryEvent)>,
    fd_events: VecDeque<(SystemTime, FileDescriptorEvent)>,
}

impl App {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            tab_state: TabState::Memory,
            scroll_state: 0,
            memory_tracker: MemoryTracker::new(),
            fd_tracker: FdTracker::new(),
            memory_events: VecDeque::with_capacity(100),
            fd_events: VecDeque::with_capacity(100),
        }
    }
    
    pub fn record_memory_event(&mut self, event: MemoryEvent) {
        let now = SystemTime::now();
        
        // Add to recent events queue
        self.memory_events.push_back((now, event));
        if self.memory_events.len() > 100 {
            self.memory_events.pop_front();
        }
        
        // Update memory tracker
        self.memory_tracker.record_event(event);
    }
    
    pub fn record_fd_event(&mut self, event: FileDescriptorEvent) {
        let now = SystemTime::now();
        
        // Add to recent events queue
        self.fd_events.push_back((now, event));
        if self.fd_events.len() > 100 {
            self.fd_events.pop_front();
        }
        
        // Update FD tracker
        self.fd_tracker.record_event(event);
    }
    
    pub fn get_memory_events(&self) -> Vec<(SystemTime, MemoryEvent)> {
        self.memory_events.iter().cloned().collect()
    }
    
    pub fn get_fd_events(&self) -> Vec<(SystemTime, FileDescriptorEvent)> {
        self.fd_events.iter().cloned().collect()
    }
    
    pub fn get_top_memory_processes(&self, limit: usize) -> Vec<(u32, &ProcessMemoryStats)> {
        self.memory_tracker.get_top_processes(limit)
    }
    
    pub fn get_top_fd_processes(&self, limit: usize) -> Vec<(u32, ProcessFdStats)> {
        self.fd_tracker.get_top_processes_by_fds(limit)
    }
    
    pub fn next_tab(&mut self) {
        self.tab_state = match self.tab_state {
            TabState::Memory => TabState::FileDescriptors,
            TabState::FileDescriptors => TabState::Help,
            TabState::Help => TabState::Memory,
        };
        self.scroll_state = 0;
    }
    
    pub fn prev_tab(&mut self) {
        self.tab_state = match self.tab_state {
            TabState::Memory => TabState::Help,
            TabState::FileDescriptors => TabState::Memory,
            TabState::Help => TabState::FileDescriptors,
        };
        self.scroll_state = 0;
    }
    
    pub fn scroll_down(&mut self) {
        self.scroll_state = self.scroll_state.saturating_add(1);
    }
    
    pub fn scroll_up(&mut self) {
        self.scroll_state = self.scroll_state.saturating_sub(1);
    }
    
    pub fn quit(&mut self) {
        self.should_quit = true;
    }
}