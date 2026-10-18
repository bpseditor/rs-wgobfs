use crate::chacha_glue::chacha_hash;

const WG_HANDSHAKE_INIT: u8 = 1;
const WG_HANDSHAKE_RESP: u8 = 2;
const OBFS_WG_HANDSHAKE_INIT: u8 = 0x11;
const OBFS_WG_HANDSHAKE_RESP: u8 = 0x12;
const WG_DATA: u8 = 4;
const WG_MIN_LEN: usize = 32;
const MIN_RND_LEN: usize = 4;
const CHACHA_INPUT_SIZE: usize = 16;
pub const MAX_RND_LEN: usize = 32;
const WG_COOKIE_WORDS: usize = 4;
const MAX_RND_WORDS: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub enum ForwardState {
    NFDrop,
    XTContinue,
}

struct ObfsBuf {
    chacha_in: [u8; CHACHA_INPUT_SIZE],
    chacha_out: [u8; MAX_RND_LEN],
    rnd: [u8; MAX_RND_LEN],
}

fn random_drop_wg_keepalive(
    buf: &mut [u8],
    buf_len: usize,
    ob: &mut ObfsBuf,
    key: &[u8; 32],
) -> bool {
    if buf[0] != WG_DATA || buf_len != 32 {
        return false;
    }

    ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(1);
    chacha_hash(&ob.chacha_in, key, &mut ob.chacha_out, 1);
    // assume the probability of a 1 byte PRN > 50 is 0.8
    ob.chacha_out[0] > 50
}

fn get_prn_insert(
    ob: &mut ObfsBuf,
    key: &[u8; 32],
    min_len: usize,
    max_len: usize,
) -> Option<usize> {
    // The one-byte counter repeats after 256 attempts. Never loop forever if
    // an input exhausts every possible counter value without a suitable byte.
    for _ in 0..=u8::MAX {
        ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(1);
        chacha_hash(&ob.chacha_in, key, &mut ob.rnd, MAX_RND_WORDS);
        if let Some(&len) = ob
            .rnd
            .iter()
            .find(|&&b| (min_len..=max_len).contains(&(b as usize)))
        {
            return Some(len as usize);
        }
    }
    None
}

fn obfs_mac2(buf: &mut [u8], data_len: usize, ob: &mut ObfsBuf, key: &[u8; 32]) {
    let msg_type: u8 = buf[0];
    if msg_type == WG_HANDSHAKE_INIT && data_len == 148 {
        let mac2 = &mut buf[132..148];
        // highly unlikely the first 4 bytes of cookie are all zeros
        let np = u32::from_ne_bytes(mac2[0..4].try_into().unwrap());
        if np == 0 {
            ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(1);
            chacha_hash(&ob.chacha_in, key, mac2, WG_COOKIE_WORDS);
            // mark the packet as need restore mac2 upon receiving
            buf[0] |= 0x10;
        }
    } else if msg_type == WG_HANDSHAKE_RESP && data_len == 92 {
        let mac2 = &mut buf[76..92];
        let np = u32::from_ne_bytes(mac2[0..4].try_into().unwrap());
        if np == 0 {
            ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(1);
            chacha_hash(&ob.chacha_in, key, mac2, WG_COOKIE_WORDS);
            buf[0] |= 0x10;
        }
    }
}

fn restore_mac2(buf: &mut [u8]) {
    let zero_mac2: [u8; 16] = [0u8; 16];
    match buf[0] {
        OBFS_WG_HANDSHAKE_INIT => {
            let mac2 = &mut buf[132..148];
            mac2[..16].copy_from_slice(&zero_mac2[..16]);
        }
        OBFS_WG_HANDSHAKE_RESP => {
            let mac2 = &mut buf[76..92];
            mac2[..16].copy_from_slice(&zero_mac2[..16]);
        }
        _ => (),
    }

    buf[0] &= 0x0F;
}

pub(crate) fn obfs_udp_payload(
    buf: &mut [u8],
    wg_data_len: usize,
    key: &[u8; 32],
    rnd_len_out: &mut usize,
) -> ForwardState {
    *rnd_len_out = 0;
    let max_rnd_len = if wg_data_len > 200 { 8 } else { MAX_RND_LEN };
    if wg_data_len < WG_MIN_LEN || wg_data_len > buf.len() || buf.len() - wg_data_len < max_rnd_len
    {
        return ForwardState::NFDrop;
    }
    let mut ob = ObfsBuf {
        chacha_in: [0u8; CHACHA_INPUT_SIZE],
        chacha_out: [0u8; MAX_RND_LEN],
        rnd: [0u8; MAX_RND_LEN],
    };

    /* Use 16th to 31st bytes of WG message as input of chacha.
     *
     * The 16th to 31st bytes is:
     *  - handshake initiation unencrypted_ephemeral (32 bytes starts at 8)
     *  - handshake response unencrypted_ephemeral (32 bytes starts at 12)
     *  - cookie nonce (24 bytes starts at 8)
     *  - data encrypted packet (var length starts at 16)
     *  - keepalive random poly1305 tag (16 bytes starts at 16)
     *
     *  Increment the first byte as counter to generate different PRN
     */
    ob.chacha_in[..CHACHA_INPUT_SIZE].copy_from_slice(&buf[16..16 + CHACHA_INPUT_SIZE]);

    /* Later will use the unchange 16th to 31st bytes to gernerate a PRN,
     * which XOR with first 16 bytes of WG. Peer will need generate an
     * identical PRN to recover the original WG.
     * Other PRNs will be generated with incremented counter.
     */
    ob.chacha_in[0] = ob.chacha_in[0].wrapping_add(42);

    if random_drop_wg_keepalive(buf, wg_data_len, &mut ob, key) {
        return ForwardState::NFDrop;
    }

    obfs_mac2(buf, wg_data_len, &mut ob, key);

    let Some(rnd_len) = get_prn_insert(&mut ob, key, MIN_RND_LEN, max_rnd_len) else {
        return ForwardState::NFDrop;
    };
    // append random bytes to WG packet
    buf[wg_data_len..wg_data_len + rnd_len].copy_from_slice(&ob.rnd[..rnd_len]);

    // Use PRN to XOR with the first 16 bytes of WG message. It has message
    // type, reserved field and counter. They look distinct.
    let chacha_in: &[u8; 16] = buf[16..32].try_into().expect("Slice is not 16 bytes long");
    chacha_hash(chacha_in, key, &mut ob.chacha_out, 5);
    // set the last byte of random as its length
    buf[wg_data_len + rnd_len - 1] = rnd_len as u8 ^ ob.chacha_out[16];
    for (byte, mask) in buf[..16].iter_mut().zip(&ob.chacha_out[..16]) {
        *byte ^= mask;
    }

    *rnd_len_out = rnd_len;
    ForwardState::XTContinue
}

pub(crate) fn unobfs_udp_payload(
    buf: &mut [u8],
    wg_data_len: usize,
    key: &[u8; 32],
    rnd_len_out: &mut usize,
) -> ForwardState {
    *rnd_len_out = 0;
    if wg_data_len < (WG_MIN_LEN + MIN_RND_LEN) || wg_data_len > buf.len() {
        return ForwardState::NFDrop;
    }

    let mut buf_prn: [u8; MAX_RND_LEN] = [0u8; MAX_RND_LEN];

    // Same as obfuscate, generate the same PRN from 16th to 31st bytes of WG
    // message. Need it for restoring the first 16 bytes of WG message.
    let chacha_in: &[u8; 16] = buf[16..32].try_into().expect("Slice is not 16 bytes long");
    chacha_hash(chacha_in, key, &mut buf_prn, 5);

    // Restore the length of random padding. It is stored in the last byte of
    // obfuscated WG.
    let rnd_len = (buf[wg_data_len - 1] ^ buf_prn[16]) as usize;
    if !(MIN_RND_LEN..=MAX_RND_LEN).contains(&rnd_len) || (rnd_len + WG_MIN_LEN) > wg_data_len {
        return ForwardState::NFDrop;
    }

    let plain_len = wg_data_len - rnd_len;
    let msg_type = buf[0] ^ buf_prn[0];
    if (msg_type == OBFS_WG_HANDSHAKE_INIT && plain_len != 148)
        || (msg_type == OBFS_WG_HANDSHAKE_RESP && plain_len != 92)
    {
        return ForwardState::NFDrop;
    }

    // restore the first 16 bytes of WG packet
    for (byte, mask) in buf[..16].iter_mut().zip(&buf_prn[..16]) {
        *byte ^= mask;
    }

    *rnd_len_out = rnd_len;
    restore_mac2(&mut buf[..plain_len]);

    ForwardState::XTContinue
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::hint::black_box;
    use std::time::Instant;

    fn packet(size: usize, seed: u8, msg_type: u8) -> Vec<u8> {
        let mut buf = vec![0; size + MAX_RND_LEN];
        for (i, byte) in buf[..size].iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(17).wrapping_add(seed);
        }
        buf[..4].copy_from_slice(&[msg_type, 0, 0, 0]);
        if seed & 1 == 0 {
            match (msg_type, size) {
                (1, 148) => buf[132..148].fill(0),
                (2, 92) => buf[76..92].fill(0),
                _ => {}
            }
        }
        buf
    }

    #[test]
    fn golden_wire_compatibility_and_roundtrips() {
        let mut checksum = 0xcbf29ce484222325u64;
        let mut kept = 0;
        let mut dropped = 0;
        for (size, msg_type) in [
            (32, 4),
            (64, 3),
            (92, 2),
            (148, 1),
            (200, 4),
            (201, 4),
            (1400, 4),
            (1500, 4),
            (65_000, 4),
        ] {
            for seed in 0..=255u8 {
                let key = std::array::from_fn(|i| seed.wrapping_add(i as u8));
                let original = packet(size, seed, msg_type);
                let mut buf = original.clone();
                let mut padding = 0;
                let state = obfs_udp_payload(&mut buf, size, &key, &mut padding);
                let forwarded = state == ForwardState::XTContinue;
                for byte in [u8::from(forwarded), padding as u8]
                    .iter()
                    .chain(buf[..size + padding].iter())
                {
                    checksum = (checksum ^ u64::from(*byte)).wrapping_mul(0x100000001b3);
                }
                if forwarded {
                    kept += 1;
                    let len = size + padding;
                    let mut restored_padding = 0;
                    assert_eq!(
                        unobfs_udp_payload(&mut buf, len, &key, &mut restored_padding),
                        ForwardState::XTContinue
                    );
                    assert_eq!(restored_padding, padding);
                    assert_eq!(&buf[..size], &original[..size]);
                } else {
                    dropped += 1;
                }
            }
        }
        // Captured from the original implementation before optimization.
        assert_eq!(checksum, 0xdc2878adfd55c3f1);
        assert_eq!((kept, dropped), (2101, 203));
    }

    #[test]
    fn malformed_sizes_and_packets_do_not_panic() {
        let key = [7; 32];
        for capacity in 0..256 {
            let mut buf = vec![0; capacity];
            for len in [0, 1, 16, 31, 32, 35, capacity, capacity + 1, usize::MAX] {
                let mut padding = 99;
                // Obfuscation must reject missing input or padding capacity.
                if len < WG_MIN_LEN
                    || len > capacity
                    || capacity - len < if len > 200 { 8 } else { MAX_RND_LEN }
                {
                    assert_eq!(
                        obfs_udp_payload(&mut buf, len, &key, &mut padding),
                        ForwardState::NFDrop
                    );
                    assert_eq!(padding, 0);
                }
                let _ = unobfs_udp_payload(&mut buf, len, &key, &mut padding);
            }
        }
        // Sweep arbitrary malformed payloads, including false handshake markers.
        for size in 36..200 {
            for seed in 0..=255 {
                let mut buf = packet(size, seed, 4);
                let mut padding = 0;
                let _ = unobfs_udp_payload(&mut buf, size, &key, &mut padding);
            }
        }
    }

    #[test]
    fn invalid_padding_and_truncated_handshakes_are_dropped() {
        let key = [9; 32];
        for (msg_type, size) in [(0x11, 40), (0x12, 40), (0x11, 149), (0x12, 93)] {
            let mut buf = packet(size, 3, msg_type);
            let mut padding = 0;
            assert_eq!(
                obfs_udp_payload(&mut buf, size, &key, &mut padding),
                ForwardState::XTContinue
            );
            assert_eq!(
                unobfs_udp_payload(&mut buf, size + padding, &key, &mut padding),
                ForwardState::NFDrop
            );
        }
        for padding in [0u8, 1, 3, 33, 255] {
            let mut buf = packet(64, 3, 4);
            let mut prn = [0; 32];
            let input = buf[16..32].try_into().unwrap();
            chacha_hash(input, &key, &mut prn, 5);
            buf[63] = padding ^ prn[16];
            let mut output = 99;
            assert_eq!(
                unobfs_udp_payload(&mut buf, 64, &key, &mut output),
                ForwardState::NFDrop
            );
            assert_eq!(output, 0);
        }
    }

    #[test]
    #[ignore = "manual performance measurement; run with --release --ignored --nocapture"]
    fn benchmark_packets() {
        let key = [0x42; 32];
        for size in [64, 148, 1400] {
            let mut buf = vec![0u8; size + MAX_RND_LEN];
            let start = Instant::now();
            let iterations = 1_000_000;
            for i in 0..iterations {
                buf[0] = 4;
                buf[16..24].copy_from_slice(&(i as u64).to_le_bytes());
                let mut padding = 0;
                assert!(matches!(
                    obfs_udp_payload(black_box(&mut buf), size, black_box(&key), &mut padding),
                    ForwardState::XTContinue
                ));
                assert!(matches!(
                    unobfs_udp_payload(
                        black_box(&mut buf),
                        size + padding,
                        black_box(&key),
                        &mut padding
                    ),
                    ForwardState::XTContinue
                ));
                black_box(&buf);
            }
            println!(
                "packet_roundtrip size={size}: {:.1} ns",
                start.elapsed().as_nanos() as f64 / iterations as f64
            );
        }
    }
}
