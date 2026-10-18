![Language](https://img.shields.io/badge/language-Rust-orange.svg)

`rs-wgobfs` is a cross-platform WireGuard obfuscator written in Rust. It is
fully compatible with [xt_wgobfs](https://github.com/infinet/xt_wgobfs).

- `rs-wgobfs`: Cross-platform CLI tool. Runs on Windows, OpenBSD, FreeBSD, and
   pfSense. It should work on macOS (untested).
   Iperf3 reaches 820 Mbits/sec in a Windows VM with 8th gen Intel CPU.

- `xt_wgobfs`: High-performance Linux kernel module. Works on Linux, including
  embedded devices with very limited resources (e.g. routers).


## Building

Run `cargo build --release` from inside the `rs-wgobfs` directory.


## Usage

```
rs-wgobfs -h

USAGE:
  rs-wgobfs [OPTIONS]

OPTIONS:
  -h, --help                          Print help information
  -l or --listen <IP:Port>            Listen address:port
  -f or --forward <IP|Hostname:Port>  Peer's address:port
  -6                                  (Optional) Prefer IPv6 when connecting
                                      to the forward Peer

  -k or --key                         Shared secret (will be repeated or
                                      truncated to 32 characters)

  -m or --mode <obfs|unobfs>          Mode, either obfs or unobfs
```

To obfuscate WG to a remote peer, first update the WG configuration, replace the
ip/hostname and port of the remote peer with `listen_ip:listen_port` of
`rs-wgobfs`. Then run:

```
rs-wgobfs -l listen_ip:listen_port -f wg_server:port -k mysecretkey -m obfs
```

To accept obfucated WG traffic from clients on a WG server:

```
rs-wgobfs -l listen_ip:listen_port -f wg_server:port -k mysecretkey -m unobfs
```

## Performance and validation

The forwarding path reuses initialized packet buffers and handles bursts of up to
64 datagrams in each direction. It keeps one response task per client, with no
per-packet task allocation, registry locks, or atomic reference counting. ChaCha6
produces the first block directly instead of buffering four blocks; valid packet
output remains compatible with the original implementation.

Each client uses roughly 64 KiB for its response buffer, allowing UDP packets
larger than the former 1500-byte limit. Socket send/receive buffers request 1 MiB
in both directions; the effective sizes depend on the operating system. If a
peer's socket is not writable, the main loop waits with a 1 ms timeout, then
drops the outgoing datagram so other clients and cleanup can continue.
Incoming keepalives refresh existing client activity even when obfuscation
intentionally drops them.
Send errors and forwarding timeouts are reported with the destination and packet
size, with at most one report per second per response task or forwarding loop.

The larger packet buffers do not increase the network path MTU. When WireGuard
uses a loopback endpoint for this proxy, configure its interface MTU for the
external path, including WireGuard, UDP/IP, and obfuscation overhead. If small
pings work but HTTPS stalls, compare larger pings with the Don't Fragment flag
and retry with a lower WireGuard MTU. An MTU of 1380 is a starting point for
testing on a 1500-byte IPv4 path; other paths may require a different value.

Run the correctness checks and the packet transformation benchmark:

```sh
cargo test --locked --all-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --release --locked benchmark_packets -- --ignored --nocapture
```

Run the local UDP benchmark against a release executable:

```sh
cargo build --release --locked
rustc --edition=2021 -O tools/benchmark.rs -o /tmp/wgobfs-bench
/tmp/wgobfs-bench target/release/rs-wgobfs
```

The UDP benchmark starts an obfs/unobfs pair and a local echo server, checks
returned payloads, and reports three one-second samples at each packet size with
a window of 32 packets. Its rate includes the client, echo server, two proxy
processes, and host scheduling; it is not a WAN or WireGuard throughput estimate.

For a binary used only on the build machine, CPU-specific compilation is also
available with `RUSTFLAGS="-C target-cpu=native" cargo build --release --locked`.
That executable may require CPU features absent on other machines.

Measurements on Linux x86_64, AMD Ryzen 5 PRO 3500U, Rust 1.95.0,
with the default release profile (baseline: commit `c5e6279`):

| Obfs + unobfs, payload bytes | Before, ns/pair | After, ns/pair | Less time per pair |
| --- | ---: | ---: | ---: |
| 64 | 459.5 | 223.4 | 51.4% |
| 148 | 474.0 | 235.0 | 50.4% |
| 1400 | 639.4 | 307.8 | 51.9% |

| Local UDP payload bytes | Before, round trips/s | After, round trips/s | Throughput increase |
| --- | ---: | ---: | ---: |
| 64 | 25,009.5 | 29,466.0 | 17.8% |
| 1400 | 24,076.0 | 27,091.5 | 12.5% |

Transformation results are medians of three runs per build. UDP results are
medians of six samples per size per build, collected in baseline/candidate/
candidate/baseline order. Every UDP sample received as many packets as it sent.
The stripped release executable decreased from 585,912 to 472,608 bytes (19.3%).
These are local measurements, not guarantees for other hardware or networks.
See [benchmark methodology and raw results](docs/benchmarks/README.md).
