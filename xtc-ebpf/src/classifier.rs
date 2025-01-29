use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_PIPE},
    cty::c_long,
    helpers::{bpf_ktime_get_ns, bpf_skb_change_tail, bpf_skb_load_bytes},
    macros::classifier,
    programs::TcContext,
};
use xtc_common::{FINGERPRINT_MACOS, FINGERPRINT_WINDOWS};

use crate::{addr_port_key, PROCESS_FINGERPRINT, SRC_ADDR_PORT_FINGERPRINT};

#[classifier]
pub fn xtc(ctx: TcContext) -> i32 {
    unsafe { try_xtc(ctx).unwrap_or(TC_ACT_PIPE) }
}

const ETHER_TYPE_IPV4: u16 = 0x0800_u16.to_be();
const IP_PROTOCOL_TCP: u8 = 0x06;
const ETH_HEADER_LEN: usize = 14;
const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;
const FLAG_SYN: u16 = 0b0000_0000_0000_0010_u16.to_be();
const PROCESS_ALL: u32 = 0;

#[inline(always)]
unsafe fn try_xtc(ctx: TcContext) -> Result<i32, c_long> {
    if ctx.data_end() - ctx.data() < ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN {
        return Ok(TC_ACT_PIPE);
    }
    // IPv4 only
    if ctx.load::<u16>(12)? != ETHER_TYPE_IPV4 {
        return Ok(TC_ACT_PIPE);
    }
    // TCP only
    if ctx.load::<u8>(ETH_HEADER_LEN + 9)? != IP_PROTOCOL_TCP {
        return Ok(TC_ACT_PIPE);
    }
    // Syn Only
    if ctx.load::<u16>(ETH_HEADER_LEN + IPV4_HEADER_LEN + 12)? & FLAG_SYN != FLAG_SYN {
        return Ok(TC_ACT_PIPE);
    }

    let addr = ctx.load::<u32>(ETH_HEADER_LEN + 12)?;
    let port = ctx.load::<u16>(ETH_HEADER_LEN + IPV4_HEADER_LEN)?.to_be();
    if let Some(fingerprint) = SRC_ADDR_PORT_FINGERPRINT
        .get_ptr(&addr_port_key(addr, port))
        .or_else(|| PROCESS_FINGERPRINT.get_ptr(&PROCESS_ALL))
    {
        match *fingerprint {
            FINGERPRINT_WINDOWS => rewrite_windows_tcp_syn(ctx)?,
            FINGERPRINT_MACOS => rewrite_macos_tcp_syn(ctx)?,
            _ => {
                return Ok(TC_ACT_PIPE);
            }
        }
    }
    Ok(TC_ACT_OK)
}

#[inline(always)]
unsafe fn rewrite_macos_tcp_syn(mut ctx: TcContext) -> Result<(), c_long> {
    const MACOS_HEADER_LEN: usize = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 24;
    if bpf_skb_change_tail(ctx.skb.skb, MACOS_HEADER_LEN as u32, 0) != 0 {
        return Err(1);
    }
    // Set IP len = 64
    ctx.store(ETH_HEADER_LEN + 2, &64_u16.to_be(), 2)?;

    // Set TTL = 64
    ctx.store(ETH_HEADER_LEN + 8, &64_u8, 2)?;

    // Set TCP len = 44
    ctx.store(ETH_HEADER_LEN + IPV4_HEADER_LEN + 12, &0xb0_u8, 2)?;

    // Set Window: 65535
    ctx.store(ETH_HEADER_LEN + IPV4_HEADER_LEN + 14, &65535_u16.to_be(), 2)?;

    // ms timestamp
    let ts = bpf_ktime_get_ns() / 1000000;
    // Set Options:
    let options: [u8; 24] = [
        0x02,
        0x04,
        0x05,
        0xb4,
        0x01,
        0x03,
        0x03,
        0x06,
        0x01,
        0x01,
        0x08,
        0x0a,
        (ts << 32 & 0xFF) as u8,
        (ts << 16 & 0xFF) as u8,
        (ts << 8 & 0xFF) as u8,
        (ts & 0xFF) as u8,
        0x00,
        0x00,
        0x00,
        0x00,
        0x04,
        0x02,
        0x00,
        0x00,
    ];
    ctx.store(
        ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN,
        &options,
        2,
    )?;

    tcp_update_checksum(&mut ctx, 44, &options)?;
    ip_update_checksum(&mut ctx)
}

#[inline(always)]
unsafe fn rewrite_windows_tcp_syn(mut ctx: TcContext) -> Result<(), c_long> {
    const WINDOWS_HEADER_LEN: usize = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + 12;
    if bpf_skb_change_tail(ctx.skb.skb, WINDOWS_HEADER_LEN as u32, 0) != 0 {
        return Err(1);
    }

    // Set IP len = 52
    ctx.store(ETH_HEADER_LEN + 2, &52_u16.to_be(), 2)?;

    // Set TTL = 64
    ctx.store(ETH_HEADER_LEN + 8, &64_u8, 2)?;

    // Set TCP len = 32
    ctx.store(ETH_HEADER_LEN + IPV4_HEADER_LEN + 12, &0x80_u8, 2)?;

    // Set Window: 64240
    ctx.store(ETH_HEADER_LEN + IPV4_HEADER_LEN + 14, &64240_u16.to_be(), 2)?;

    // Set Options:
    const OPTIONS: [u8; 12] = [
        0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02,
    ];
    ctx.store(
        ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN,
        &OPTIONS,
        2,
    )?;

    tcp_update_checksum(&mut ctx, 32, &OPTIONS)?;
    ip_update_checksum(&mut ctx)
}

#[inline(always)]
unsafe fn tcp_update_checksum(
    ctx: &mut TcContext,
    tcp_len: u16,
    tcp_options: &[u8],
) -> Result<(), c_long> {
    // tcp_set_checksum(ctx, 0)?;

    let mut sum = tcp_pseudo_header_sum(ctx, tcp_len)? + tcp_common_header_sum(ctx)?;

    for chunk in tcp_options.chunks(2) {
        if chunk.len() == 1 {
            sum += (chunk[0] as u32) << 8;
        } else {
            sum += (chunk[0] as u32) << 8 | chunk[1] as u32;
        }
    }
    tcp_set_checksum(ctx, fold_checksum(sum))
}

#[inline(always)]
unsafe fn tcp_pseudo_header_sum(ctx: &mut TcContext, tcp_len: u16) -> Result<u32, c_long> {
    let mut sum = 0_u32;

    // Hard-coded to minimize performance loss
    let mut src_dst_ip = [0_u8; 8];

    // ctx.load_bytes(ETH_HEADER_LEN + 12, &mut src_dst_ip)?;
    if bpf_skb_load_bytes(
        ctx.skb.skb as *const _,
        (ETH_HEADER_LEN + 12) as u32,
        &mut src_dst_ip as *mut _ as *mut _,
        8,
    ) != 0
    {
        return Err(1);
    }
    sum += (src_dst_ip[0] as u32) << 8 | src_dst_ip[1] as u32;
    sum += (src_dst_ip[2] as u32) << 8 | src_dst_ip[3] as u32;
    sum += (src_dst_ip[4] as u32) << 8 | src_dst_ip[5] as u32;
    sum += (src_dst_ip[6] as u32) << 8 | src_dst_ip[7] as u32;
    // Protocol TCP
    sum += 0x06_u32;
    // TCP len
    Ok(sum + tcp_len as u32)
}

#[inline(always)]
unsafe fn tcp_common_header_sum(ctx: &mut TcContext) -> Result<u32, c_long> {
    let mut sum = 0_u32;

    let mut tcp_header = [0_u8; TCP_HEADER_LEN];

    // ctx.load_bytes(ETH_HEADER_LEN + IPV4_HEADER_LEN, &mut tcp_header)?;
    if bpf_skb_load_bytes(
        ctx.skb.skb as *const _,
        (ETH_HEADER_LEN + IPV4_HEADER_LEN) as u32,
        &mut tcp_header as *mut _ as *mut _,
        IPV4_HEADER_LEN as u32,
    ) != 0
    {
        return Err(1);
    }

    // Hard-coded to minimize performance loss
    sum += (tcp_header[0] as u32) << 8 | tcp_header[1] as u32;
    sum += (tcp_header[2] as u32) << 8 | tcp_header[3] as u32;
    sum += (tcp_header[4] as u32) << 8 | tcp_header[5] as u32;
    sum += (tcp_header[6] as u32) << 8 | tcp_header[7] as u32;
    sum += (tcp_header[8] as u32) << 8 | tcp_header[9] as u32;
    sum += (tcp_header[10] as u32) << 8 | tcp_header[11] as u32;
    sum += (tcp_header[12] as u32) << 8 | tcp_header[13] as u32;
    sum += (tcp_header[14] as u32) << 8 | tcp_header[15] as u32;
    // ignore checksum
    // sum += (tcp_header[16] as u32) << 8 | tcp_header[17] as u32;
    sum += (tcp_header[18] as u32) << 8 | tcp_header[19] as u32;

    // TCP len
    Ok(sum)
}

#[inline(always)]
unsafe fn tcp_set_checksum(ctx: &mut TcContext, value: u16) -> Result<(), c_long> {
    ctx.store(ETH_HEADER_LEN + IPV4_HEADER_LEN + 16, &value.to_be(), 2)
}

#[inline(always)]
unsafe fn ip_update_checksum(ctx: &mut TcContext) -> Result<(), c_long> {
    // ip_set_checksum(ctx, 0)?;

    let mut ip_header = [0_u8; IPV4_HEADER_LEN];

    // ctx.load_bytes(ETH_HEADER_LEN, &mut ip_header)?;
    if bpf_skb_load_bytes(
        ctx.skb.skb as *const _,
        ETH_HEADER_LEN as u32,
        &mut ip_header as *mut _ as *mut _,
        IPV4_HEADER_LEN as u32,
    ) != 0
    {
        return Err(1);
    }

    let mut sum = (ip_header[0] as u32) << 8 | ip_header[1] as u32;
    sum += (ip_header[2] as u32) << 8 | ip_header[3] as u32;
    sum += (ip_header[4] as u32) << 8 | ip_header[5] as u32;
    sum += (ip_header[6] as u32) << 8 | ip_header[7] as u32;
    sum += (ip_header[8] as u32) << 8 | ip_header[9] as u32;
    // sum += (ip_header[10] as u32) << 8 | ip_header[11] as u32;
    sum += (ip_header[12] as u32) << 8 | ip_header[13] as u32;
    sum += (ip_header[14] as u32) << 8 | ip_header[15] as u32;
    sum += (ip_header[16] as u32) << 8 | ip_header[17] as u32;
    sum += (ip_header[18] as u32) << 8 | ip_header[19] as u32;

    ip_set_checksum(ctx, fold_checksum(sum))
}

#[inline(always)]
unsafe fn ip_set_checksum(ctx: &mut TcContext, value: u16) -> Result<(), c_long> {
    ctx.store(ETH_HEADER_LEN + 10, &value.to_be(), 2)
}

#[inline(always)]
fn fold_checksum(mut sum: u32) -> u16 {
    // u32 -> u16 up to two times
    if sum >> 16 > 0 {
        sum = (sum >> 16) + (sum & 0xffff);
        if sum >> 16 > 0 {
            sum = (sum >> 16) + (sum & 0xffff);
        }
    }
    (!sum & 0xffff) as u16
}
