#![no_std]
#![no_main]
#![allow(static_mut_refs)]

use aya_log_ebpf::error;

use aya_ebpf::{
    macros::{map, tracepoint, uprobe, uretprobe},
    maps::{HashMap, PerfEventArray},
    programs::{ProbeContext, RetProbeContext, TracePointContext},
    EbpfContext,
    helpers::{bpf_ktime_get_ns, bpf_get_current_pid_tgid as pid_tgid},
};

use proc_monitor_common::{MemoryEvent, FileEvent, MAX_ENTRIES};

#[no_mangle]
static PID: u32 = 0;
fn target_pid()-> u32 {
    unsafe { core::ptr::read_volatile(&PID) }
}

#[repr(C)]
struct SysEnterOpenAtArgs {
    dirfd: i32,
    pathname: *const u8,
    flags: i32,
    mode: u32,
}

#[map(name = "MEMORY_EVENTS")]
static mut MEMORY_EVENTS: PerfEventArray<MemoryEvent> = PerfEventArray::new(0);

#[map(name = "FILE_EVENTS")]
static mut FILE_EVENTS: PerfEventArray<FileEvent> = PerfEventArray::new(0);

#[map(name = "MEM_ALLOC")]
static mut MEM_ALLOC: HashMap<u64, u32> = HashMap::with_max_entries(MAX_ENTRIES, 0);

#[uprobe]
fn malloc(ctx: ProbeContext) {
    
    if ctx.tgid() != target_pid() {
        return
    }

    let size = ctx.arg(0).unwrap_or(0);
    if size == 0 {
        return
    }

    let key = &pid_tgid();
    //info!(&ctx,"malloc pid: {}, tid: {}, size: {}", ctx.tgid(), ctx.pid(), size);
    let _ = unsafe { MEM_ALLOC.insert(key, &size, 0) };
}

#[uretprobe]
fn malloc_ret(ctx: RetProbeContext) {
    if ctx.tgid() != target_pid() {
        return;
    }

    let addr = ctx.ret().unwrap_or(0);
    let key = &pid_tgid();

    if addr == 0 {
        let _ = unsafe { MEM_ALLOC.remove(key) };
        return;
    }

    let size = *unsafe { MEM_ALLOC.get(key) }.unwrap_or(&0);
    if size == 0 {
        return;
    }

    let event = MemoryEvent {
        pid: ctx.tgid(),
        tid: ctx.pid(),
        timestamp: unsafe { bpf_ktime_get_ns() },
        address: addr,
        size,
        is_alloc: true,
    };
    //info!(&ctx,"kmalloc pid: {}, tid: {}, size: {}", ctx.tgid(), ctx.pid(), size);
    unsafe { 
        MEMORY_EVENTS.output(&ctx, &event, 0);
        let _ = MEM_ALLOC.remove(&key);
    }
}

#[tracepoint(name = "sys_enter_openat",category = "syscalls")]
pub fn trace_open(ctx: TracePointContext) {
    if ctx.tgid() != target_pid() {
        return
    }

   let args: SysEnterOpenAtArgs = match unsafe { ctx.read_at::<SysEnterOpenAtArgs>(16) } {
        Ok(args) => args,
        Err(_) => return
   };

   if args.pathname.is_null() {
       return;
   }

   let mut filename = [0u8; 128];
   unsafe {
       let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(
           args.pathname,
           &mut filename,
       )
       .map_err(|e| {
           error!(&ctx, "str read error: {}", e);
       });
   };

   let event = FileEvent {
        pid: ctx.tgid(),
        tid: ctx.pid(),
        timestamp: unsafe { bpf_ktime_get_ns() },
        filename,
    };

   //info!(&ctx,"openat: pid: {}, path={}",target_pid(), unsafe{core::str::from_utf8_unchecked(&filename)});

   unsafe { FILE_EVENTS.output(&ctx, &event, 0) };
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
