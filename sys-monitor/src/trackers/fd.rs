use std::collections::{HashMap, BTreeMap};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::path::PathBuf;
use sys_monitor_common::{FileDescriptorEvent, FD_OP_OPEN, FD_OP_CLOSE, FD_OP_READ, FD_OP_WRITE};
use std::fs;

// A more detailed FileDescriptor structure for tracking
pub struct FileDescriptor {
    pub pid: u32,
    pub fd: i32,
    pub path: Option<String>,
    pub open_time: SystemTime,
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub last_operation: SystemTime,
}

// Statistics for file descriptor activity per process
#[derive(Default, Clone)]
pub struct ProcessFdStats {
    pub open_fds: u32,
    pub total_opened: u64,
    pub total_closed: u64,
    pub total_read_bytes: u64,
    pub total_write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
    pub peak_fds: u32,
}

// Main tracker for file descriptor operations
pub struct FdTracker {
    // Track active file descriptors per process (key: (pid << 32) | fd)
    active_fds: HashMap<u64, FileDescriptor>,
    
    // Track FD stats per process
    process_stats: HashMap<u32, ProcessFdStats>,
    
    // Recent events for UI display, with timestamp
    recent_events: Vec<(SystemTime, FileDescriptorEvent)>,
    
    // Number of events to keep in history
    history_limit: usize,
    
    // Path cache to resolve FDs to paths when possible
    path_cache: HashMap<u64, String>,
    
    // Last time we attempted to resolve paths
    last_path_resolve: SystemTime,
}

impl FdTracker {
    pub fn new() -> Self {
        Self {
            active_fds: HashMap::new(),
            process_stats: HashMap::new(),
            recent_events: Vec::with_capacity(1000),
            history_limit: 1000,
            path_cache: HashMap::new(),
            last_path_resolve: SystemTime::now(),
        }
    }
    
    // Create a 64-bit key from PID and FD for HashMap lookup
    fn make_fd_key(pid: u32, fd: i32) -> u64 {
        ((pid as u64) << 32) | (fd as u32 as u64)
    }
    
    // Record a file descriptor event from eBPF
    pub fn record_event(&mut self, event: FileDescriptorEvent) {
        // Add to recent events with current timestamp
        let timestamp = SystemTime::now();
        self.recent_events.push((timestamp, event));
        
        // Limit recent events buffer
        if self.recent_events.len() > self.history_limit {
            let to_remove = self.recent_events.len() - self.history_limit;
            self.recent_events.drain(0..to_remove);
        }
        
        // Process based on operation type
        match event.op_type {
            FD_OP_OPEN => self.handle_open(event, timestamp),
            FD_OP_CLOSE => self.handle_close(event, timestamp),
            FD_OP_READ => self.handle_read(event, timestamp),
            FD_OP_WRITE => self.handle_write(event, timestamp),
            _ => {}
        }
        
        // Try to resolve paths periodically
        self.maybe_resolve_paths(timestamp);
    }
    
    // Handle file open events
    fn handle_open(&mut self, event: FileDescriptorEvent, timestamp: SystemTime) {
        if event.fd < 0 {
            // Failed open, ignore
            return;
        }
        
        let key = Self::make_fd_key(event.pid, event.fd);
        
        // Try to get the file path
        let path = self.resolve_fd_path(event.pid, event.fd);
        
        // Create new FD tracking entry
        self.active_fds.insert(key, FileDescriptor {
            pid: event.pid,
            fd: event.fd,
            path,
            open_time: timestamp,
            read_bytes: 0,
            write_bytes: 0,
            read_ops: 0,
            write_ops: 0,
            last_operation: timestamp,
        });
        
        // Update process stats
        let stats = self.process_stats.entry(event.pid).or_default();
        stats.open_fds += 1;
        stats.total_opened += 1;
        if stats.open_fds > stats.peak_fds {
            stats.peak_fds = stats.open_fds;
        }
    }
    
    // Handle file close events
    fn handle_close(&mut self, event: FileDescriptorEvent, timestamp: SystemTime) {
        let key = Self::make_fd_key(event.pid, event.fd);
        
        // Remove from active FDs
        if self.active_fds.remove(&key).is_some() {
            // Update process stats
            if let Some(stats) = self.process_stats.get_mut(&event.pid) {
                stats.open_fds = stats.open_fds.saturating_sub(1);
                stats.total_closed += 1;
            }
        }
    }
    
    // Handle file read events
    fn handle_read(&mut self, event: FileDescriptorEvent, timestamp: SystemTime) {
        let key = Self::make_fd_key(event.pid, event.fd);
        
        // Update FD stats if we know about this FD
        if let Some(fd) = self.active_fds.get_mut(&key) {
            fd.read_bytes += event.count;
            fd.read_ops += 1;
            fd.last_operation = timestamp;
        }
        
        // Update process stats
        if let Some(stats) = self.process_stats.get_mut(&event.pid) {
            stats.total_read_bytes += event.count;
            stats.read_ops += 1;
        }
    }
    
    // Handle file write events
    fn handle_write(&mut self, event: FileDescriptorEvent, timestamp: SystemTime) {
        let key = Self::make_fd_key(event.pid, event.fd);
        
        // Update FD stats if we know about this FD
        if let Some(fd) = self.active_fds.get_mut(&key) {
            fd.write_bytes += event.count;
            fd.write_ops += 1;
            fd.last_operation = timestamp;
        }
        
        // Update process stats
        if let Some(stats) = self.process_stats.get_mut(&event.pid) {
            stats.total_write_bytes += event.count;
            stats.write_ops += 1;
        }
    }
    
    // Try to resolve an FD to a path
    fn resolve_fd_path(&mut self, pid: u32, fd: i32) -> Option<String> {
        let key = Self::make_fd_key(pid, fd);
        
        // Check cache first
        if let Some(path) = self.path_cache.get(&key) {
            return Some(path.clone());
        }
        
        // Try to read the symlink in /proc
        let proc_path = format!("/proc/{}/fd/{}", pid, fd);
        let path_result = fs::read_link(proc_path);
        
        if let Ok(path_buf) = path_result {
            let path_str = path_buf.to_string_lossy().to_string();
            self.path_cache.insert(key, path_str.clone());
            Some(path_str)
        } else {
            None
        }
    }
    
    // Periodically clean stale path cache entries and resolve new paths
    fn maybe_resolve_paths(&mut self, now: SystemTime) {
        // Only resolve paths every 5 seconds to avoid overhead
        let should_resolve = match now.duration_since(self.last_path_resolve) {
            Ok(duration) => duration.as_secs() >= 5,
            Err(_) => true, // Clock skew, resolve anyway
        };
        
        if !should_resolve {
            return;
        }
        
        self.last_path_resolve = now;
        
        // Clean stale cache entries (paths for FDs we no longer track)
        let active_keys: Vec<u64> = self.active_fds.keys().cloned().collect();
        self.path_cache.retain(|key, _| active_keys.contains(key));
        
        // Try to resolve missing paths
        /*
        for (key, fd) in &self.active_fds {
            if fd.path.is_none() {
                let pid = fd.pid;
                let fd_num = fd.fd;
                if let Some(path) = self.resolve_fd_path(pid, fd_num) {
                    // Update the path in the active_fds map
                    if let Some(fd_entry) = self.active_fds.get_mut(key) {
                        fd_entry.path = Some(path);
                    }
                }
            }
        }
        */
    }
    
    // Get recent FD events for display
    pub fn get_recent_events(&self, limit: usize) -> Vec<(SystemTime, FileDescriptorEvent)> {
        let start = if self.recent_events.len() > limit {
            self.recent_events.len() - limit
        } else {
            0
        };
        
        self.recent_events[start..].to_vec()
    }
    
    // Get top processes by number of open file descriptors
    pub fn get_top_processes_by_fds(&self, limit: usize) -> Vec<(u32, ProcessFdStats)> {
        let mut procs: Vec<_> = self.process_stats
            .iter()
            .map(|(pid, stats)| (*pid, stats.clone()))
            .collect();
        
        procs.sort_by(|a, b| b.1.open_fds.cmp(&a.1.open_fds));
        procs.truncate(limit);
        procs
    }
    
    // Get top processes by total I/O (read + write bytes)
    pub fn get_top_processes_by_io(&self, limit: usize) -> Vec<(u32, ProcessFdStats)> {
        let mut procs: Vec<_> = self.process_stats
            .iter()
            .map(|(pid, stats)| (*pid, stats.clone()))
            .collect();
        
        procs.sort_by(|a, b| {
            let a_total = a.1.total_read_bytes + a.1.total_write_bytes;
            let b_total = b.1.total_read_bytes + b.1.total_write_bytes;
            b_total.cmp(&a_total)
        });
        
        procs.truncate(limit);
        procs
    }
    
    // Get a list of all active file descriptors
    pub fn get_active_fds(&self) -> Vec<&FileDescriptor> {
        self.active_fds.values().collect()
    }
    
    // Get a list of most active file descriptors (by recent I/O)
    pub fn get_most_active_fds(&self, limit: usize) -> Vec<&FileDescriptor> {
        let mut fds: Vec<_> = self.active_fds.values().collect();
        
        // Sort by total I/O (read + write)
        fds.sort_by(|a, b| {
            let a_total = a.read_bytes + a.write_bytes;
            let b_total = b.read_bytes + b.write_bytes;
            b_total.cmp(&a_total)
        });
        
        fds.truncate(limit);
        fds
    }
    
    // Get stats for a specific process
    pub fn get_process_stats(&self, pid: u32) -> Option<&ProcessFdStats> {
        self.process_stats.get(&pid)
    }
    
    // Get file descriptor info for a specific process and fd
    pub fn get_fd_info(&self, pid: u32, fd: i32) -> Option<&FileDescriptor> {
        let key = Self::make_fd_key(pid, fd);
        self.active_fds.get(&key)
    }
    
    // Get total stats across all processes
    pub fn get_total_stats(&self) -> ProcessFdStats {
        let mut total = ProcessFdStats::default();
        
        for stats in self.process_stats.values() {
            total.open_fds += stats.open_fds;
            total.total_opened += stats.total_opened;
            total.total_closed += stats.total_closed;
            total.total_read_bytes += stats.total_read_bytes;
            total.total_write_bytes += stats.total_write_bytes;
            total.read_ops += stats.read_ops;
            total.write_ops += stats.write_ops;
            total.peak_fds = total.peak_fds.max(stats.peak_fds);
        }
        
        total
    }
    
    // Scan /proc to find processes we might have missed
    pub fn scan_proc(&mut self) {
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let file_name = entry.file_name();
                let pid_str = file_name.to_string_lossy();
                
                // Only look at numeric directories (PIDs)
                if let Ok(pid) = pid_str.parse::<u32>() {
                    // Skip if we already track this process
                    if self.process_stats.contains_key(&pid) {
                        continue;
                    }
                    
                    // Check if this process has any fd entries
                    let fd_path = format!("/proc/{}/fd", pid);
                    if let Ok(fd_entries) = fs::read_dir(&fd_path) {
                        let mut has_fds = false;
                        for _ in fd_entries.flatten() {
                            has_fds = true;
                            break;
                        }
                        
                        if has_fds {
                            // Add a zero-initialized stats entry for this process
                            self.process_stats.insert(pid, ProcessFdStats::default());
                        }
                    }
                }
            }
        }
    }
}