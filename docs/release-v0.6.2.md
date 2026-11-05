WireGuard UDP obfuscator with faster forwarding and optional fragmentation.

- Adds `obfs-frag` / `unobfs-frag` and `--max-datagram` (default 1200 bytes) to split and reassemble large WireGuard messages.
- Improves UDP forwarding and ChaCha6 packet processing; keeps the legacy `xt_wgobfs` wire format available.
- Expands CLI documentation and validates fragment limits.

Downloads: Linux x86_64 / ARM64 / ARMv7, Windows x86_64, macOS Intel / Apple Silicon. Archives include usage documentation; `SHA256SUMS` lists archive checksums. macOS and Windows binaries are unsigned. ARMv7 is cross-compiled; its tests are compiled but not executed on hardware. Linux binaries are built on Ubuntu 22.04 (glibc).

Fragment mode requires rs-wgobfs on both ends and is incompatible with legacy modes / xt_wgobfs. It does not provide path MTU discovery or independent framing authentication.
