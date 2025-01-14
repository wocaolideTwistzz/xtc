#![no_std]
#![no_main]

mod classifier;
mod kprobe;

#[allow(warnings)]
mod vmlinux;

use aya_ebpf::{
    macros::map,
    maps::{HashMap, LruHashMap},
};

#[map]
static PROCESS_FINGERPRINT: HashMap<u32, u8> = HashMap::with_max_entries(512, 0);

#[map]
static SRC_ADDR_PORT_FINGERPRINT: LruHashMap<u64, u8> = LruHashMap::with_max_entries(1024, 0);

#[inline(always)]
pub fn addr_port_key(addr: u32, port: u16) -> u64 {
    ((addr as u64) << 32) | (port as u64)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
