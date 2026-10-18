use ppv_lite86::{dispatch, LaneWords4, Machine, RotateEachWord32, StoreBytes};

// Only the first 32 bytes of the first ChaCha6 block are used by wgobfs.
// Generate those rows directly, without a four-block RNG buffer or counter update.
dispatch!(m, Mach, {
    fn hash6(input: &[u8; 16], key: &[u8; 32], out: &mut [u8; 32]) {
        let initial_a = m.vec([0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
        let initial_b: Mach::u32x4 = m.read_le(&key[..16]);
        let mut a = initial_a;
        let mut b = initial_b;
        let mut c: Mach::u32x4 = m.read_le(&key[16..]);
        let mut d: Mach::u32x4 = m.read_le(input);
        for _ in 0..3 {
            a += b;
            d = (d ^ a).rotate_each_word_right16();
            c += d;
            b = (b ^ c).rotate_each_word_right20();
            a += b;
            d = (d ^ a).rotate_each_word_right24();
            c += d;
            b = (b ^ c).rotate_each_word_right25();

            b = b.shuffle_lane_words3012();
            c = c.shuffle_lane_words2301();
            d = d.shuffle_lane_words1230();

            a += b;
            d = (d ^ a).rotate_each_word_right16();
            c += d;
            b = (b ^ c).rotate_each_word_right20();
            a += b;
            d = (d ^ a).rotate_each_word_right24();
            c += d;
            b = (b ^ c).rotate_each_word_right25();

            b = b.shuffle_lane_words1230();
            c = c.shuffle_lane_words2301();
            d = d.shuffle_lane_words3012();
        }
        (a + initial_a).write_le(&mut out[..16]);
        (b + initial_b).write_le(&mut out[16..]);
    }
});

#[inline]
pub(crate) fn chacha_hash(input: &[u8; 16], key: &[u8; 32], out: &mut [u8], out_words: usize) {
    assert!(out_words <= 8 && out.len() >= out_words * 4);
    let mut block = [0; 32];
    hash6(input, key, &mut block);
    let bytes = out_words * 4;
    out[..bytes].copy_from_slice(&block[..bytes]);
}

#[test]
fn test_chacha6() {
    let key: [u8; 32] = [
        1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6,
        7, 8,
    ];

    let input: [u8; 16] = [0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0, 0, 0xff, 0, 0];

    let expected: [u8; 32] = [
        0xc5, 0x92, 0x55, 0x87, 0xca, 0x38, 0xaa, 0xc4, 0x31, 0xe7, 0x2e, 0xed, 0x19, 0x72, 0x31,
        0x93, 0x51, 0x13, 0x96, 0xee, 0x67, 0xea, 0x8, 0x43, 0xd7, 0x3c, 0x9e, 0xa3, 0x96, 0xd4,
        0x83, 0x1f,
    ];

    let mut results = [0u8; 32];

    chacha_hash(&input, &key, &mut results, 8);
    assert_eq!(results, expected);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chacha::{ChaCha6Core, ChaCha6Rng};
    use crate::guts::ChaCha;
    use rand_core::{block::BlockRng, RngCore};

    #[test]
    fn single_block_matches_original_four_block_rng() {
        for seed in 0u32..1024 {
            let key =
                std::array::from_fn(|i| seed.wrapping_mul(31).wrapping_add(i as u32 * 17) as u8);
            let input = std::array::from_fn(|i| {
                seed.rotate_left(i as u32).wrapping_add(i as u32 * 53) as u8
            });
            let mut rng = ChaCha6Rng {
                rng: BlockRng::new(ChaCha6Core {
                    state: ChaCha::new_nonce16(&key, &input),
                }),
            };
            let mut expected = [0; 32];
            for word in expected.chunks_exact_mut(4) {
                word.copy_from_slice(&rng.next_u32().to_le_bytes());
            }
            for words in 0..=8 {
                let mut actual = [0xAB; 40];
                chacha_hash(&input, &key, &mut actual, words);
                assert_eq!(&actual[..words * 4], &expected[..words * 4]);
                assert!(actual[words * 4..].iter().all(|b| *b == 0xAB));
            }
        }
    }
}
