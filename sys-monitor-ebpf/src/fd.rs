use aya_ebpf::{
    helpers::{bpf_ktime_get_ns, bpf_get_current_pid_tgid},
    maps::{PerfEventArray, HashMap},
    programs::TracePointContext,
};
use sys_monitor_common::{FileDescriptorEvent, FD_OP_OPEN, FD_OP_CLOSE, FD_OP_READ, FD_OP_WRITE};

/// Generate a 64-bit key from PID and FD
#[inline(always)]
fn make_fd_key(pid: u32, fd: i32) -> u64 {
    ((pid as u64) << 32) | (fd as u32 as u64)
}

/// Get PID and TID using the correct BPF helper
#[inline(always)]
fn get_pid_tid() -> (u32, u32) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;  // PID (process ID) is in the upper 32 bits
    let pid = (pid_tgid & 0xFFFFFFFF) as u32;  // TID (thread ID) is in the lower 32 bits
    
    (tgid, pid)
}

/// Extract arguments from a syscall tracepoint context
/// On x86_64, syscall arguments are in registers:
/// - RDI (arg0)
/// - RSI (arg1)
/// - RDX (arg2)
/// - R10 (arg3)
/// - R8 (arg4)
/// - R9 (arg5)
#[inline(always)]
unsafe fn get_syscall_arg(ctx: &TracePointContext, arg_num: usize) -> u64 {
    // Tracepoint format for syscalls includes arguments as an array
    // The layout depends on the particular tracepoint type
    // For x86_64 syscall tracepoints:
    //   +0: syscall number (4 bytes)
    //   +8: arg0 (8 bytes)
    //   +16: arg1 (8 bytes)
    //   ...
    
    let args_offset = 8; // Offset to first argument (in bytes)
    let arg_offset = args_offset + (arg_num * 8); // Each argument is 8 bytes on x86_64
    
    // Attempt to read the argument at the calculated offset
    match ctx.read_at::<u64>(arg_offset) {
        Ok(arg) => arg,
        Err(_) => 0,
    }
}

/// Track open syscall
#[inline(always)]
pub fn track_open(ctx: TracePointContext, events: &mut PerfEventArray<FileDescriptorEvent>, active_fds: &mut HashMap<u64, u32>) -> Result<(), u64> {
    // Get PID and TID
    let (pid, tid) = get_pid_tid();
    
    // The file descriptor is actually returned by the syscall, not passed as an argument
    // We'd need to hook the exit to get it
    // For simplicity, we'll use a placeholder value
    let fd = 0i32; // Placeholder - would need to get from sys_exit hook
    
    // Simulation only for demonstration purposes
    let key = make_fd_key(pid, fd);
    active_fds.insert(&key, &1, 0).unwrap_or(());
    
    let event = FileDescriptorEvent {
        pid,
        tid,
        timestamp: unsafe { bpf_ktime_get_ns() },
        fd,
        op_type: FD_OP_OPEN,
        count: 0,
    };
    
    // Send event to userspace
    events.output(&ctx, &event, 0);
    
    Ok(())
}

/// Track openat syscall (the modern variant of open)
#[inline(always)]
pub fn track_openat(ctx: TracePointContext, events: &mut PerfEventArray<FileDescriptorEvent>, active_fds: &mut HashMap<u64, u32>) -> Result<(), u64> {
    // Get PID and TID
    let (pid, tid) = get_pid_tid();
    
    // Extract the dirfd argument (first argument)
    let _dirfd = unsafe { get_syscall_arg(&ctx, 0) } as i32;
    
    // The file descriptor is returned by the syscall, not passed as an argument
    // We'd need to hook the exit to get it
    // For simplicity, we'll use a placeholder value
    let fd = 0i32; // Placeholder - would need to get from sys_exit hook
    
    // Simulation only for demonstration purposes
    let key = make_fd_key(pid, fd);
    active_fds.insert(&key, &1, 0).unwrap_or(());
    
    let event = FileDescriptorEvent {
        pid,
        tid,
        timestamp: unsafe { bpf_ktime_get_ns() },
        fd,
        op_type: FD_OP_OPEN,
        count: 0,
    };
    
    // Send event to userspace
    events.output(&ctx, &event, 0);
    
    Ok(())
}

/// Track close syscall
#[inline(always)]
pub fn track_close(ctx: TracePointContext, events: &mut PerfEventArray<FileDescriptorEvent>, active_fds: &mut HashMap<u64, u32>) -> Result<(), u64> {
    // Get PID and TID
    let (pid, tid) = get_pid_tid();
    
    // Extract the fd argument (first argument on x86_64)
    let fd = unsafe { get_syscall_arg(&ctx, 0) } as i32;
    
    // Remove from active FDs map
    let key = make_fd_key(pid, fd);
    active_fds.remove(&key).unwrap_or(());
    
    let event = FileDescriptorEvent {
        pid,
        tid,
        timestamp: unsafe { bpf_ktime_get_ns() },
        fd,
        op_type: FD_OP_CLOSE,
        count: 0,
    };
    
    // Send event to userspace
    events.output(&ctx, &event, 0);
    
    Ok(())
}

/// Track read syscall
#[inline(always)]
pub fn track_read(ctx: TracePointContext, events: &mut PerfEventArray<FileDescriptorEvent>) -> Result<(), u64> {
    // Get PID and TID
    let (pid, tid) = get_pid_tid();
    
    // Extract arguments (on x86_64)
    let fd = unsafe { get_syscall_arg(&ctx, 0) } as i32;    // File descriptor (first arg)
    let _buf = unsafe { get_syscall_arg(&ctx, 1) };         // Buffer pointer (second arg)
    let count = unsafe { get_syscall_arg(&ctx, 2) };        // Count (third arg)
    
    let event = FileDescriptorEvent {
        pid,
        tid,
        timestamp: unsafe { bpf_ktime_get_ns() },
        fd,
        op_type: FD_OP_READ,
        count,
    };
    
    // Send event to userspace
    events.output(&ctx, &event, 0);
    
    Ok(())
}

/// Track write syscall
#[inline(always)]
pub fn track_write(ctx: TracePointContext, events: &mut PerfEventArray<FileDescriptorEvent>) -> Result<(), u64> {
    // Get PID and TID
    let (pid, tid) = get_pid_tid();
    
    // Extract arguments (on x86_64)
    let fd = unsafe { get_syscall_arg(&ctx, 0) } as i32;    // File descriptor (first arg)
    let _buf = unsafe { get_syscall_arg(&ctx, 1) };         // Buffer pointer (second arg)
    let count = unsafe { get_syscall_arg(&ctx, 2) };        // Count (third arg)
    
    let event = FileDescriptorEvent {
        pid,
        tid,
        timestamp: unsafe { bpf_ktime_get_ns() },
        fd,
        op_type: FD_OP_WRITE,
        count,
    };
    
    // Send event to userspace
    events.output(&ctx, &event, 0);
    
    Ok(())
}