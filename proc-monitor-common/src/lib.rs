#![no_std]

pub const MAX_ENTRIES: u32 = 1024;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct MemoryEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub address: u64,
    pub size: u32,
    pub is_alloc: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FileEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub filename: [u8; 128],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MemoryEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileEvent {}
