use std::collections::HashMap;
use sys_monitor_common::MemoryEvent;

#[derive(Default)]
pub struct MemoryTracker {
    // Track current allocations
    allocations: HashMap<u64, MemoryAllocation>,
    // Track allocation statistics per process
    process_stats: HashMap<u32, ProcessMemoryStats>,
}

pub struct MemoryAllocation {
    pub pid: u32,
    pub timestamp: u64,
    pub size: u64,
}

#[derive(Default)]
pub struct ProcessMemoryStats {
    pub total_allocations: u64,
    pub current_allocated_bytes: u64,
    pub peak_allocated_bytes: u64,
    pub total_allocated_bytes: u64,
}

impl MemoryTracker {
    pub fn new() -> Self {
        Self {
            allocations: HashMap::new(),
            process_stats: HashMap::new(),
        }
    }
    
    pub fn record_event(&mut self, event: MemoryEvent) {
        if event.is_alloc {
            self.record_allocation(event);
        } else {
            self.record_free(event);
        }
    }
    
    fn record_allocation(&mut self, event: MemoryEvent) {
        // Store allocation 
        self.allocations.insert(event.address, MemoryAllocation {
            pid: event.pid,
            timestamp: event.timestamp,
            size: event.size,
        });
        
        // Update process stats
        let stats = self.process_stats.entry(event.pid).or_default();
        stats.total_allocations += 1;
        stats.current_allocated_bytes += event.size;
        stats.total_allocated_bytes += event.size;
        if stats.current_allocated_bytes > stats.peak_allocated_bytes {
            stats.peak_allocated_bytes = stats.current_allocated_bytes;
        }
    }
    
    fn record_free(&mut self, event: MemoryEvent) {
        if let Some(alloc) = self.allocations.remove(&event.address) {
            // Update process stats
            if let Some(stats) = self.process_stats.get_mut(&alloc.pid) {
                stats.current_allocated_bytes = stats.current_allocated_bytes.saturating_sub(alloc.size);
            }
        }
    }
    
    pub fn get_top_processes(&self, limit: usize) -> Vec<(u32, &ProcessMemoryStats)> {
        let mut procs: Vec<_> = self.process_stats
            .iter()
            .map(|(pid, stats)| (*pid, stats))
            .collect();
        
        procs.sort_by(|a, b| b.1.current_allocated_bytes.cmp(&a.1.current_allocated_bytes));
        procs.truncate(limit);
        procs
    }
}