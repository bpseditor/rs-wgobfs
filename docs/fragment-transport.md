# Fragment transport v1

This is an opt-in rs-wgobfs-to-rs-wgobfs transport. There is no negotiation,
legacy fallback, retransmission, or path MTU discovery. Both endpoints must use
fragment modes and the same shared obfuscation key.

The sender splits an original WireGuard UDP payload into chunks. Each chunk
gets a 32-byte header and is then independently passed through the existing
wgobfs obfuscation, which masks bytes 0..15 and appends padding. This framing
applies to all messages, including messages fitting in a single fragment.

All multibyte integers in the plaintext header use network byte order:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 1 | 3 (avoids WG handshake rewriting and keepalive suppression) |
| 1 | 1 | Version 1 |
| 2 | 2 | Original WireGuard UDP payload length, 32..=65527 |
| 4 | 2 | Zero-based fragment index |
| 6 | 2 | Chunk size; all chunks except the last have exactly this size |
| 8 | 8 | Message ID |
| 16 | 16 | Input for the existing obfuscation mask generation |
| 32 | variable | Original payload chunk |

The chunk size is `max_datagram - 32 - 32`, reserving the maximum obfuscation
padding even for a short last fragment. Valid chunk sizes are 64..=65443.
There are `ceil(total_length / chunk_size)` fragments. The receiver validates
the index and exact fragment payload length before allocating assembly state.
It accepts valid chunk sizes independently of its own outgoing datagram limit.

Message IDs are derived from a wrapping 64-bit counter using a per-codec
randomly seeded standard-library hasher. The mask input is the first 16 output bytes of the existing keyed ChaCha6
function. Its input is original WireGuard payload bytes 16..31, XORed with
the big-endian message ID in input bytes 0..7 and the big-endian fragment index
in input bytes 8..9. This avoids exposing a counter relationship between
fragments in the unmasked input bytes. Neither the mask nor
framing provides cryptographic authentication. Completed messages go to
WireGuard, which performs its own authentication.

Reassembly is keyed by UDP source address and message ID. For responses on a
connected per-client socket, that socket provides additional peer isolation.
A receiver stores at most 64 incomplete messages, each at most 65527 bytes,
plus a received-chunk bitmap and metadata. New assemblies are dropped when
full. Conflicting length/chunk metadata and duplicate indices are ignored;
already accepted chunk bytes cannot be overwritten. Assemblies expire five
seconds after their first fragment, without extending the deadline for later
fragments or duplicates. Expiration runs on packet reception and on a
one-second timer while idle.

On completion, state is removed and the original message is forwarded once.
There is no completed-ID replay cache: a complete replay may deliver another
copy, as ordinary UDP can. WireGuard handles authenticated transport replay
protection. Partial late duplicates consume bounded state until expiration.
