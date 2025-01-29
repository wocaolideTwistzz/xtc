# xtc

## Overview

`xtc` is a tool to disguise [`TCP/IP fingerprints`](https://browserleaks.com/tcp) on linux using [`aya-ebpf`](https://github.com/aya-rs/aya) (ipv4 only)

## What is TCP Fingerprint

Different operating systems assemble TCP/IP header in different ways, which generates different `TTL`, `window size`, and `tcp options` with different order and values.

So website can determine our operating system by analyzing our `TCP syn packet`.

When we use a proxy to access a website, the website can rate us based on our `User-Agent` and `TCP Fingerprints`, and when it is different, it can assume that we are using a proxy, lowering our credibility.

Check your TCP Fingerprint on [`browserleaks`](https://browserleaks.com/tcp).

## Usage

```
Usage: xtc [OPTIONS]

Options:
  -i, --iface <IFACE>      [default: eth0]
      --windows <WINDOWS>  Process IDs to fingerprint as Windows (use 0 to fingerprint all processes)
      --macos <MACOS>      Process IDs to fingerprint as macOS (use 0 to fingerprint all processes)
  -h, --help               Print help
  -V, --version            Print version
```

Disguise all tcp traffics as mac

```shell
./xtc -i eth0 --macos=0
```

Disguise all tcp traffics as windows

```shell
./xtc -i eth0 --windows=0
```

Disguise the tcp traffics of the specified process

```shell
# use with proxies, specify different proxy processIDs as different TCP fingerprints
./xtc -i eth0 --windows=1234 --macos=1235,1236
```

## Prerequisites

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package xtc --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```

The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/xtc` can be
copied to a Linux server or VM and run there.
