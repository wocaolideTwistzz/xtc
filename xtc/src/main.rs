use aya::{
    maps::HashMap,
    programs::{tc, KProbe, SchedClassifier, TcAttachType},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;
use xtc_common::{FINGERPRINT_MACOS, FINGERPRINT_WINDOWS};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Opt {
    #[arg(short, long, default_value = "eth0")]
    iface: String,

    #[arg(long)]
    windows: Vec<u32>,

    #[arg(long)]
    macos: Vec<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xtc"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let Opt {
        iface,
        windows,
        macos,
    } = opt;

    let mut process_fingerprint = HashMap::try_from(ebpf.map_mut("PROCESS_FINGERPRINT").unwrap())?;

    for pid in windows {
        process_fingerprint.insert(pid, FINGERPRINT_WINDOWS, 0)?;
    }

    for pid in macos {
        process_fingerprint.insert(pid, FINGERPRINT_MACOS, 0)?;
    }

    let tcp_connect_program: &mut KProbe = ebpf.program_mut("tcp_connect").unwrap().try_into()?;
    tcp_connect_program.load()?;
    tcp_connect_program.attach("tcp_connect", 0)?;

    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("xtc").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Egress)?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
