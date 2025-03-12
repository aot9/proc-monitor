#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, kprobe, kretprobe, tracepoint},
    maps::{PerfEventArray, HashMap},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
};
use sys_monitor_common::{MemoryEvent, FileDescriptorEvent, MAX_ENTRIES};

mod memory;
mod fd;

// Define perf event arrays for sending events to userspace
#[map(name = "MEMORY_EVENTS")]
static mut MEMORY_EVENTS: PerfEventArray<MemoryEvent> = PerfEventArray::new(0);

#[map(name = "FD_EVENTS")]
static mut FD_EVENTS: PerfEventArray<FileDescriptorEvent> = PerfEventArray::new(0);

// Track active file descriptors per process
#[map(name = "ACTIVE_FDS")]
static mut ACTIVE_FDS: HashMap<u64, u32> = HashMap::with_max_entries(10, 0);

#[map(name = "MEM_ALLOC")]
static mut MEM_ALLOC: HashMap<u64, u64> = HashMap::with_max_entries(10, 0);

#[kprobe]
pub fn kmalloc_enter(ctx: ProbeContext) -> u32 {
    unsafe {
        match memory::track_kmalloc_enter(ctx, &mut MEM_ALLOC) {
            Ok(_) => 0,
            Err(err) => err as u32,
        }
    }
}

#[kretprobe]
pub fn kmalloc_exit(ctx: RetProbeContext) -> u32 {
    unsafe {
        match memory::track_kmalloc_exit(ctx, &mut MEMORY_EVENTS, &mut MEM_ALLOC) {
            Ok(_) => 0,
            Err(err) => err as u32,
        }
    }
}
/* 
#[kprobe]
pub fn kfree_enter(ctx: ProbeContext) -> u32 {
    unsafe {
        match memory::track_kfree(ctx, &mut MEMORY_EVENTS) {
            Ok(_) => 0,
            Err(err) => err as u32,
        }
    }
}

// File descriptor tracking
#[tracepoint(name = "sys_enter_open", category = "syscalls")]
pub fn trace_open(ctx: TracePointContext) -> u32 {
    unsafe {
        match fd::track_open(ctx, &mut FD_EVENTS, &mut ACTIVE_FDS) {
            Ok(_) => 0,
            Err(err) => err as u32,
        }
    }
}

#[tracepoint(name = "sys_enter_close", category = "syscalls")]
pub fn trace_close(ctx: TracePointContext) -> u32 {
    unsafe {
        match fd::track_close(ctx, &mut FD_EVENTS, &mut ACTIVE_FDS) {
            Ok(_) => 0,
            Err(err) => err as u32,
        }
    }
}

#[tracepoint(name = "sys_enter_read", category = "syscalls")]
pub fn trace_read(ctx: TracePointContext) -> u32 {
    unsafe {
        match fd::track_read(ctx, &mut FD_EVENTS) {
            Ok(_) => 0,
            Err(err) => err as u32,
        }
    }
}

#[tracepoint(name = "sys_enter_write", category = "syscalls")]
pub fn trace_write(ctx: TracePointContext) -> u32 {
    unsafe {
        match fd::track_write(ctx, &mut FD_EVENTS) {
            Ok(_) => 0,
            Err(err) => err as u32,
        }
    }
}
*/
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
