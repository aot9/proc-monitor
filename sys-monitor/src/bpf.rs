use aya::maps::perf::AsyncPerfEventArray;
use aya::programs::{KProbe, TracePoint};
use aya::{include_bytes_aligned, Ebpf};
use aya_log::EbpfLogger;
use log::{info, warn};
use tokio::sync::Mutex;
use tokio::task;
use std::sync::Arc;
use bytes::BytesMut;
use aya::util::online_cpus;

use sys_monitor_common::{MemoryEvent, FileDescriptorEvent};
use crate::ui::app::App;
use crate::trackers::{memory::MemoryTracker, fd::FdTracker};

pub async fn load_and_attach(
    bpf: &mut Ebpf,
    app: Arc<Mutex<App>>,
    memory_tracker: MemoryTracker,
    fd_tracker: FdTracker,
) -> Result<(), anyhow::Error> {
    // Load and attach memory tracking programs
    let kmalloc_enter: &mut KProbe = bpf.program_mut("kmalloc_enter")
        .expect("kmalloc_enter program not found")
        .try_into()?;
    kmalloc_enter.load()?;
    kmalloc_enter.attach("__kmalloc", 0)?;
    info!("Attached to __kmalloc entry point");

    let kmalloc_exit: &mut KProbe = bpf.program_mut("kmalloc_exit")
        .expect("kmalloc_exit program not found")
        .try_into()?;
    kmalloc_exit.load()?;
    kmalloc_exit.attach("__kmalloc", 0)?;
    info!("Attached to __kmalloc exit point");
    /* 
    let kfree_enter: &mut KProbe = bpf.program_mut("kfree_enter")
        .expect("kfree_enter program not found")
        .try_into()?;
    kfree_enter.load()?;
    kfree_enter.attach("kfree", 0)?;
    info!("Attached to kfree entry point");

    // Load and attach file descriptor tracking programs
    let open_tp: &mut TracePoint = bpf.program_mut("trace_open")
        .expect("trace_open program not found")
        .try_into()?;
    open_tp.load()?;
    open_tp.attach("syscalls", "sys_enter_open")?;
    info!("Attached to sys_enter_open tracepoint");
    
    let openat_tp: &mut TracePoint = bpf.program_mut("trace_openat")
        .expect("trace_openat program not found")
        .try_into()?;
    openat_tp.load()?;
    openat_tp.attach("syscalls", "sys_enter_openat")?;
    info!("Attached to sys_enter_openat tracepoint");
    
    let close_tp: &mut TracePoint = bpf.program_mut("trace_close")
        .expect("trace_close program not found")
        .try_into()?;
    close_tp.load()?;
    close_tp.attach("syscalls", "sys_enter_close")?;
    info!("Attached to sys_enter_close tracepoint");
    
    let read_tp: &mut TracePoint = bpf.program_mut("trace_read")
        .expect("trace_read program not found")
        .try_into()?;
    read_tp.load()?;
    read_tp.attach("syscalls", "sys_enter_read")?;
    info!("Attached to sys_enter_read tracepoint");
    
    let write_tp: &mut TracePoint = bpf.program_mut("trace_write")
        .expect("trace_write program not found")
        .try_into()?;
    write_tp.load()?;
    write_tp.attach("syscalls", "sys_enter_write")?;
    info!("Attached to sys_enter_write tracepoint");
*/
    // Set up perfbuf for memory events
    let mut memory_events = AsyncPerfEventArray::try_from(bpf.take_map("MEMORY_EVENTS").unwrap())?;
    info!("Set up memory events perf buffer");
    
    // Set up perfbuf for file descriptor events
    //let mut fd_events = AsyncPerfEventArray::try_from(bpf.map_mut("FD_EVENTS").unwrap())?;
    //info!("Set up FD events perf buffer");


    
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        // open a separate perf buffer for each cpu
        let mut buf = memory_events.open(cpu_id, None)?;
        let app_clone = app.clone();
        // process each perf buffer in a separate task
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();
    
            loop {
                // wait for events
                let events = buf.read_events(&mut buffers).await.unwrap();
    
                // events.read contains the number of events that have been read,
                // and is always <= buffers.len()
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let event = unsafe {
                        // Create a pointer to the bytes at the offset
                        let event_ptr = buf.as_ptr() as *const MemoryEvent;
                        
                        // Dereference the pointer to get the event
                        &*event_ptr
                    };
                    app_clone.lock().await.record_memory_event(*event);
                }
            }
        });
    }

    info!("Successfully loaded and attached all BPF programs for x86_64");

    Ok(())
}