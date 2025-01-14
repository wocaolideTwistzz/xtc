use std::{fs::File, io::Write, path::PathBuf};

use aya_tool::InputFile;
use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker` binary. This would be
/// better expressed by [artifact-dependencies][bindeps] but issues such as
/// https://github.com/rust-lang/cargo/issues/12385 make their use impractical for the time being.
///
/// This file implements an imperfect solution: it causes cargo to rebuild the crate whenever the
/// mtime of `which bpf-linker` changes. Note that possibility that a new bpf-linker is added to
/// $PATH ahead of the one used as the cache key still exists. Solving this in the general case
/// would require rebuild-if-changed-env=PATH *and* rebuild-if-changed={every-directory-in-PATH}
/// which would likely mean far too much cache invalidation.
///
/// [bindeps]: https://doc.rust-lang.org/nightly/cargo/reference/unstable.html?highlight=feature#artifact-dependencies
fn main() {
    build_vmlinux();
    println!("build vmlinux.rs success.");

    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}

fn build_vmlinux() {
    let names = vec![
        "task_struct",
        "sockaddr_in",
        "sockaddr_in6",
        "inet_sock",
        "ipv6hdr",
        "tcphdr",
        "udphdr",
        "icmphdr",
        "icmp6hdr",
    ];

    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )
    .expect("generate failed");

    let dest_path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/vmlinux.rs");

    let mut vmlinux = File::create(dest_path).unwrap();

    vmlinux.write_all(bindings.as_bytes()).unwrap();
    vmlinux.flush().unwrap();
}
