use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_get_current_pid_tgid},
    maps::{PerfEventArray, HashMap},
    programs::{ProbeContext, RetProbeContext},
};
use sys_monitor_common::MemoryEvent;

/// Generate a 64-bit key from PID and TID for tracking allocations
#[inline(always)]
fn make_alloc_key(pid: u32, tid: u32) -> u64 {
    ((pid as u64) << 32) | (tid as u32 as u64)
}

/// Get PID and TID using the correct BPF helper
#[inline(always)]
fn get_pid_tid() -> (u32, u32) {
    let pid_tgid = unsafe { bpf_get_current_pid_tgid() };
    let tgid = (pid_tgid >> 32) as u32;  // PID (process ID) is in the upper 32 bits
    let pid = (pid_tgid & 0xFFFFFFFF) as u32;  // TID (thread ID) is in the lower 32 bits
    
    (tgid, pid)
}

/// Track kmalloc entry - captures and stores size of the allocation
/// This function captures the size argument and stores it in a map
/// to be used by the exit handler
#[inline(always)]
pub fn track_kmalloc_enter(ctx: ProbeContext, sizes: &mut HashMap<u64, u64>) -> Result<(), u64> {
    // Read the size argument (for x86_64 it's the first argument - RDI)
    let size = match ctx.arg(1) {
        Some(size) => size,
        None => 0, // Handle the error case
    };

    // Get PID and TID
    let (pid, tid) = get_pid_tid();
    
    // Create a key for this thread
    let key = make_alloc_key(pid, tid);
    
    // Store the size in the map for the exit handler to use
    sizes.insert(&key, &size, 0).unwrap_or(());
    
    Ok(())
}

/// Track kmalloc exit - captures the returned memory address
/// Combines with the stored size from entry handler to create a complete event
#[inline(always)]
pub fn track_kmalloc_exit(
    ctx: RetProbeContext, 
    events: &mut PerfEventArray<MemoryEvent>,
    sizes: &mut HashMap<u64, u64>
) -> Result<(), u64> {
    // Get PID and TID
    let (pid, tid) = get_pid_tid();
    
    // Get the allocated address from return value (RAX register on x86_64)
    let addr = ctx.ret().ok_or(0u64)?;

    if addr == 0 {
        // Allocation failed, nothing to track
        // We should clean up the entry in the sizes map
        let key = make_alloc_key(pid, tid);
        sizes.remove(&key).unwrap_or(());
        return Ok(());
    }
    
    // Look up the size from the map using the same key
    let key = make_alloc_key(pid, tid);
    let size = match unsafe { sizes.get(&key) } {
        Some(size) => *size,
        None => 0, // If we can't find the size, use 0 as a fallback
    };
    
    // Create and send the memory allocation event
    let event = MemoryEvent {
        pid,
        tid,
        timestamp: unsafe { bpf_ktime_get_ns() },
        address: addr,
        size,
        is_alloc: true,
    };
    
    // Send event to userspace
    events.output(&ctx, &event, 0);
    
    // Clean up the entry in the sizes map
    sizes.remove(&key).unwrap_or(());
    
    Ok(())
}

/// Track kfree call - captures memory being freed
#[inline(always)]
pub fn track_kfree(ctx: ProbeContext, events: &mut PerfEventArray<MemoryEvent>) -> Result<(), u64> {
    // Get PID and TID
    let (pid, tid) = get_pid_tid();
    
    // Get the pointer being freed - on x86_64 this is the first parameter (RDI register)
    let addr = unsafe { (*ctx.regs).rdi } as u64;

    if addr == 0 {
        // Null pointer, nothing to track
        return Ok(());
    }
    
    // Create and send the memory free event
    let event = MemoryEvent {
        pid,
        tid,
        timestamp: unsafe { bpf_ktime_get_ns() },
        address: addr,
        size: 0, // We don't know the size when freeing
        is_alloc: false,
    };
    
    // Send event to userspace
    events.output(&ctx, &event, 0);
    
    Ok(())
}