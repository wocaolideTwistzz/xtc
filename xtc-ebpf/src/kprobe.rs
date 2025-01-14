use aya_ebpf::{
    cty::c_long, helpers::bpf_probe_read_kernel, macros::kprobe, programs::ProbeContext,
    EbpfContext,
};

use crate::{addr_port_key, vmlinux::sock, PROCESS_FINGERPRINT, SRC_ADDR_PORT_FINGERPRINT};

const AF_INET: u16 = 2;

#[kprobe]
pub fn tcp_connect(ctx: ProbeContext) -> u32 {
    unsafe { try_tcp_connect(&ctx).unwrap_or_default() }
}

#[inline(always)]
unsafe fn try_tcp_connect(ctx: &ProbeContext) -> Result<u32, c_long> {
    let pid = ctx.tgid();

    if let Some(fingerprint) = PROCESS_FINGERPRINT.get_ptr(&pid) {
        let sk = bpf_probe_read_kernel(&ctx.arg::<*const sock>(0).ok_or(1)?)?;
        let family = bpf_probe_read_kernel(&(*sk).__sk_common.skc_family)?;

        if family != AF_INET {
            return Ok(0);
        }

        let src_addr = bpf_probe_read_kernel(
            &(*sk)
                .__sk_common
                .__bindgen_anon_1
                .__bindgen_anon_1
                .skc_rcv_saddr,
        )?;
        let src_port =
            bpf_probe_read_kernel(&(*sk).__sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num)?;

        SRC_ADDR_PORT_FINGERPRINT.insert(&addr_port_key(src_addr, src_port), &(*fingerprint), 0)?;
    }
    Ok(0)
}
