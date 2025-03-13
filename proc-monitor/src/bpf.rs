use anyhow::Context;
use aya::{
    maps::perf::AsyncPerfEventArray,
    programs::{TracePoint,UProbe},
    util::online_cpus,
    Ebpf
};

use log::info;
use tokio::task;
use bytes::BytesMut;
use tokio::sync::mpsc::UnboundedSender;

use proc_monitor_common::{MemoryEvent, FileEvent};

use crate::ui::event::Event;

pub async fn load_and_attach(
    bpf: &mut Ebpf,
    send_channel: UnboundedSender<Event>,
) -> Result<(), anyhow::Error> {

    let kmalloc_exit: &mut UProbe = bpf.program_mut("malloc_ret")
        .expect("kmalloc_exit program not found")
        .try_into()?;
    kmalloc_exit.load()?;
    kmalloc_exit.attach("malloc", "libc", None, None).with_context(|| "malloc_ret")?;
    info!("Attached to __kmalloc exit point");

    // Load and attach memory tracking programs
    let kmalloc_enter: &mut UProbe = bpf.program_mut("malloc")
        .expect("kmalloc_enter program not found")
        .try_into()?;
    kmalloc_enter.load()?;
    kmalloc_enter.attach("malloc", "libc", None, None)?;
    info!("Attached to __kmalloc entry point");

    // Load and attach file descriptor tracking programs
    let open_tp: &mut TracePoint = bpf.program_mut("trace_open")
        .expect("trace_open program not found")
        .try_into()?;
    open_tp.load()?;
    open_tp.attach("syscalls", "sys_enter_openat")?;
    info!("Attached to sys_enter_open tracepoint");

    let mut memory_events = AsyncPerfEventArray::try_from(bpf.take_map("MEMORY_EVENTS").unwrap())?;
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let mut buf = memory_events.open(cpu_id, None)?;
        let chan = send_channel.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<MemoryEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let event = unsafe {
                        let event_ptr = buf.as_ptr() as *const MemoryEvent;
                        &*event_ptr
                    };

                    let _ = chan.send(Event::MemAlloc(*event));
                }
            }
        });
    }

    let mut fd_events = AsyncPerfEventArray::try_from(bpf.take_map("FILE_EVENTS").unwrap())?;
    for cpu_id in online_cpus().map_err(|(_, error)| error)? {
        let mut buf = fd_events.open(cpu_id, None)?;
        let chan = send_channel.clone();
        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(core::mem::size_of::<FileEvent>()))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();

                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let event = unsafe {
                        let event_ptr = buf.as_ptr() as *const FileEvent;

                        &*event_ptr
                    };

                    let _ = chan.send(Event::FileOpen(*event));
                }
            }
        });
    }

    info!("Successfully loaded and attached all BPF programs for x86_64");

    Ok(())
}