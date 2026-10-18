# Performance comparison

Baseline: `c5e62796d3a8a063c71e4eb5ada6768eae45e7ae`.
Candidate: the production Rust code in this PR.

Both builds used Linux x86_64, an AMD Ryzen 5 PRO 3500U, Rust 1.95.0, and the
repository's default release profile, without `target-cpu=native`.
Measurements were collected sequentially on the same host.

## Results

| Payload | Baseline obfs + unobfs | Candidate obfs + unobfs | Time reduction | Processing rate increase |
| --- | ---: | ---: | ---: | ---: |
| 64 bytes | 459.5 ns | 223.4 ns | 51.4% | 105.7% |
| 148 bytes | 474.0 ns | 235.0 ns | 50.4% | 101.7% |
| 1400 bytes | 639.4 ns | 307.8 ns | 51.9% | 107.7% |

| Payload | Baseline local UDP round trips/s | Candidate local UDP round trips/s | Increase |
| --- | ---: | ---: | ---: |
| 64 bytes | 25,009.5 | 29,466.0 | 17.8% |
| 1400 bytes | 24,076.0 | 27,091.5 | 12.5% |

The stripped release binary decreased from 585,912 to 472,608 bytes, a 19.3%
reduction.

Time reduction is `100 * (1 - candidate_ns / baseline_ns)`. Processing rate
increase is `100 * (baseline_ns / candidate_ns - 1)`. UDP throughput increase is
`100 * (candidate_roundtrips / baseline_roundtrips - 1)`.

## Method

The transformation benchmark runs 1,000,000 obfs/unobfs pairs per payload size,
with changing packet contents and `black_box`. Results are medians of three runs
per build. The baseline was built from an archive of the baseline commit with
only the candidate's ignored `benchmark_packets` function added as a test module.
Its production implementation and dependencies were unchanged.

The UDP benchmark starts two proxy processes and a local UDP echo server. It
sends windows of 32 packets, verifies returned payloads, and records three
one-second samples for each of 64-byte and 1400-byte payloads. The binary order
was baseline, candidate, candidate, baseline, giving six samples per payload size
per build. The table reports the median of those six samples. Every sample had
equal sent and received counts.

The UDP rate includes both proxies, the echo server, the benchmark client, and
host scheduling. It measures completed local round trips, not one-way tunnel
capacity. These measurements do not establish WAN or real WireGuard VPN speedup,
packet loss under congestion, or performance on other operating systems. They
are descriptive samples without confidence intervals.

## Reproduction

Build the candidate and the baseline with their respective lockfiles:

```sh
cargo build --release --locked
git worktree add --detach /tmp/rs-wgobfs-baseline c5e62796d3a8a063c71e4eb5ada6768eae45e7ae
cargo build --release --locked --manifest-path /tmp/rs-wgobfs-baseline/Cargo.toml
rustc --edition=2021 -O tools/benchmark.rs -o /tmp/wgobfs-bench
/tmp/wgobfs-bench /tmp/rs-wgobfs-baseline/target/release/rs-wgobfs
/tmp/wgobfs-bench target/release/rs-wgobfs
/tmp/wgobfs-bench target/release/rs-wgobfs
/tmp/wgobfs-bench /tmp/rs-wgobfs-baseline/target/release/rs-wgobfs
```

For the transformation comparison, add the same test harness to the baseline
without changing its production code. Run this from the candidate checkout:

```sh
python3 - <<'PY'
from pathlib import Path
source = Path('src/wgobfs.rs').read_text()
benchmark = source[source.index('    #[test]\n    #[ignore = "manual performance'):].rsplit('\n}', 1)[0]
baseline = Path('/tmp/rs-wgobfs-baseline/src/wgobfs.rs')
with baseline.open('a') as f:
    f.write('\n#[cfg(test)]\nmod performance_comparison {\n'
            '    use super::*;\n    use std::hint::black_box;\n'
            '    use std::time::Instant;\n' + benchmark + '\n}\n')
PY
```

Repeat the following pair three times, collecting the printed ns/pair values:

```sh
cargo test --release --locked --manifest-path /tmp/rs-wgobfs-baseline/Cargo.toml benchmark_packets -- --ignored --nocapture
cargo test --release --locked benchmark_packets -- --ignored --nocapture
```

[Raw output](optimization-results.txt) and [samples in JSON](optimization-results.json)
are included so the medians and percentages can be recalculated.
