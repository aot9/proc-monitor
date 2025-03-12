#![no_std]

/// Maximum number of entries to track in our maps
pub const MAX_ENTRIES: u32 = 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub address: u64,
    pub size: u64,
    pub is_alloc: bool,  // true for allocation, false for free
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FileDescriptorEvent {
    pub pid: u32,
    pub tid: u32,
    pub timestamp: u64,
    pub fd: i32,
    pub op_type: u8,  // 0=open, 1=close, 2=read, 3=write
    pub count: u64,   // bytes read/written if applicable
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for MemoryEvent {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FileDescriptorEvent {}

// Op types for file descriptor operations
pub const FD_OP_OPEN: u8 = 0;
pub const FD_OP_CLOSE: u8 = 1;
pub const FD_OP_READ: u8 = 2;
pub const FD_OP_WRITE: u8 = 3;