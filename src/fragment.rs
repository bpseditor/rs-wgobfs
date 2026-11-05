//! Version 1 framing, inside the existing obfuscation envelope.
//! All integers are big endian. Header: type=3, version=1, total:u16,
//! index:u16, chunk_size:u16, message_id:u64, obfuscation_input:[u8;16].
use std::collections::{hash_map::RandomState, HashMap};
use std::hash::{BuildHasher, Hasher};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::wgobfs::MAX_RND_LEN;
use crate::{OPMode, MAX_UDP_PAYLOAD};

const HEADER: usize = 32;
const TIMEOUT: Duration = Duration::from_secs(5);
// Across all senders sharing this receiver, at most about 4 MiB of payload.
const MAX_PENDING: usize = 64;
pub const DEFAULT_LIMIT: usize = 1200;
pub const MIN_LIMIT: usize = 128;
pub const MAX_LIMIT: usize = 65_507;

struct Pending {
    created: Instant,
    chunk: usize,
    data: Vec<u8>,
    seen: Vec<bool>,
    remaining: usize,
}

pub struct Codec {
    ids: RandomState,
    counter: u64,
    pending: HashMap<(SocketAddr, u64), Pending>,
}

impl Default for Codec {
    fn default() -> Self {
        Self {
            ids: RandomState::new(),
            counter: 0,
            pending: HashMap::new(),
        }
    }
}

#[derive(Default)]
pub struct Packets<'a> {
    single: Option<&'a [u8]>,
    multiple: Vec<Vec<u8>>,
}

impl Packets<'_> {
    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.single
            .into_iter()
            .chain(self.multiple.iter().map(Vec::as_slice))
    }
}

impl Codec {
    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|_, p| now.duration_since(p.created) < TIMEOUT);
    }

    pub fn packets<'a>(
        &mut self,
        mode: OPMode,
        buf: &'a mut [u8],
        len: usize,
        key: &[u8; 32],
        peer: SocketAddr,
    ) -> Packets<'a> {
        let Some(limit) = mode.fragment_limit() else {
            return Packets {
                single: mode.transform(buf, len, key).map(|n| &buf[..n]),
                multiple: Vec::new(),
            };
        };
        if mode.is_obfs() {
            Packets {
                single: None,
                multiple: self.encode(&buf[..len], limit, key),
            }
        } else {
            let Some(n) = mode.transform(buf, len, key) else {
                return Packets::default();
            };
            Packets {
                single: None,
                multiple: self
                    .receive(peer, &buf[..n], Instant::now())
                    .into_iter()
                    .collect(),
            }
        }
    }

    fn encode(&mut self, packet: &[u8], limit: usize, key: &[u8; 32]) -> Vec<Vec<u8>> {
        if packet.len() < 32
            || packet.len() > MAX_UDP_PAYLOAD
            || !(MIN_LIMIT..=MAX_LIMIT).contains(&limit)
        {
            return Vec::new();
        }
        // Reserve worst-case padding even for short final fragments.
        let chunk = limit - HEADER - MAX_RND_LEN;
        let mut hash = self.ids.build_hasher();
        hash.write_u64(self.counter);
        self.counter = self.counter.wrapping_add(1);
        let id = hash.finish().to_be_bytes();
        packet
            .chunks(chunk)
            .enumerate()
            .filter_map(|(index, part)| {
                let mut frame = vec![0; HEADER + part.len() + MAX_RND_LEN];
                frame[0] = 3; // Avoid WG keepalive suppression and handshake rewriting.
                frame[1] = 1;
                frame[2..4].copy_from_slice(&(packet.len() as u16).to_be_bytes());
                frame[4..6].copy_from_slice(&(index as u16).to_be_bytes());
                frame[6..8].copy_from_slice(&(chunk as u16).to_be_bytes());
                frame[8..16].copy_from_slice(&id);
                // Scramble the per-message/index input so fragments do not expose
                // a visible counter relationship in the unmasked header bytes.
                let mut input: [u8; 16] = packet[16..32].try_into().unwrap();
                for i in 0..8 {
                    input[i] ^= id[i];
                }
                let index_bytes = (index as u16).to_be_bytes();
                input[8] ^= index_bytes[0];
                input[9] ^= index_bytes[1];
                crate::chacha_glue::chacha_hash(&input, key, &mut frame[16..32], 4);
                frame[HEADER..HEADER + part.len()].copy_from_slice(part);
                let n = OPMode::Obfs.transform(&mut frame, HEADER + part.len(), key)?;
                frame.truncate(n);
                Some(frame)
            })
            .collect()
    }

    fn receive(&mut self, peer: SocketAddr, frame: &[u8], now: Instant) -> Option<Vec<u8>> {
        self.expire(now);
        if frame.len() <= HEADER || frame[0..2] != [3, 1] {
            return None;
        }
        let total = u16::from_be_bytes(frame[2..4].try_into().unwrap()) as usize;
        let index = u16::from_be_bytes(frame[4..6].try_into().unwrap()) as usize;
        let chunk = u16::from_be_bytes(frame[6..8].try_into().unwrap()) as usize;
        let id = u64::from_be_bytes(frame[8..16].try_into().unwrap());
        if !(32..=MAX_UDP_PAYLOAD).contains(&total)
            || !(MIN_LIMIT - HEADER - MAX_RND_LEN..=MAX_LIMIT - HEADER - MAX_RND_LEN)
                .contains(&chunk)
        {
            return None;
        }
        let count = total.div_ceil(chunk);
        let offset = index.checked_mul(chunk)?;
        if index >= count || frame.len() - HEADER != chunk.min(total - offset) {
            return None;
        }
        let identity = (peer, id);
        if count == 1 {
            return Some(frame[HEADER..].to_vec());
        }
        if !self.pending.contains_key(&identity) {
            if self.pending.len() >= MAX_PENDING {
                return None;
            }
            self.pending.insert(
                identity,
                Pending {
                    created: now,
                    chunk,
                    data: vec![0; total],
                    seen: vec![false; count],
                    remaining: count,
                },
            );
        }
        let pending = self.pending.get_mut(&identity)?;
        if pending.data.len() != total || pending.chunk != chunk {
            return None;
        }
        if pending.seen[index] {
            // Identical duplicates are harmless; conflicting copies cannot
            // overwrite data already accepted for this message.
            return None;
        }
        pending.data[offset..offset + frame.len() - HEADER].copy_from_slice(&frame[HEADER..]);
        pending.seen[index] = true;
        pending.remaining -= 1;
        if pending.remaining != 0 {
            return None;
        }
        Some(self.pending.remove(&identity)?.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn plain_frames(codec: &mut Codec, packet: &[u8], limit: usize) -> Vec<Vec<u8>> {
        let key = [19; 32];
        codec
            .encode(packet, limit, &key)
            .into_iter()
            .map(|mut frame| {
                assert!(
                    frame.len() <= limit,
                    "wire payload exceeds configured limit"
                );
                let len = frame.len();
                let len = OPMode::UnObfs.transform(&mut frame, len, &key).unwrap();
                frame.truncate(len);
                frame
            })
            .collect()
    }

    #[test]
    fn limits_roundtrips_reordering_and_duplicates() {
        for limit in [MIN_LIMIT, 576, 1200, 1472, MAX_LIMIT] {
            for size in [
                32,
                92,
                148,
                200,
                201,
                1136,
                1137,
                1500,
                9000,
                MAX_UDP_PAYLOAD,
            ] {
                let packet: Vec<_> = (0..size).map(|i| (i as u8).wrapping_mul(17)).collect();
                let mut tx = Codec::default();
                let frames = plain_frames(&mut tx, &packet, limit);
                let mut rx = Codec::default();
                let now = Instant::now();
                let mut completed = Vec::new();
                for frame in frames.iter().rev() {
                    if let Some(data) = rx.receive(peer(1), frame, now) {
                        completed.push(data);
                    }
                    if frames.len() > 1 {
                        assert!(rx.receive(peer(1), frame, now).is_none());
                    }
                }
                assert_eq!(completed, [packet], "limit={limit}, size={size}");
            }
        }
    }

    #[test]
    fn loss_timeout_resource_limit_and_sender_isolation() {
        let mut tx = Codec::default();
        let frames = plain_frames(&mut tx, &vec![42; 1500], 1200);
        let now = Instant::now();
        let mut rx = Codec::default();
        assert!(rx.receive(peer(1), &frames[0], now).is_none());
        assert!(rx.receive(peer(2), &frames[1], now).is_none());
        assert_eq!(rx.pending.len(), 2);
        assert_eq!(rx.receive(peer(1), &frames[1], now), Some(vec![42; 1500]));
        rx.expire(now + TIMEOUT);
        assert!(rx.pending.is_empty());
        // A late final fragment alone cannot resurrect the original datagram.
        assert!(rx.receive(peer(1), &frames[1], now + TIMEOUT).is_none());
        for port in 2..=100 {
            assert!(rx.receive(peer(port), &frames[0], now + TIMEOUT).is_none());
        }
        assert_eq!(rx.pending.len(), MAX_PENDING);
        rx.expire(now + TIMEOUT + TIMEOUT);
        assert!(rx.pending.is_empty());
    }

    #[test]
    fn malformed_and_inconsistent_fragments() {
        let mut tx = Codec::default();
        let frames = plain_frames(&mut tx, &vec![42; 1500], 1200);
        let mut rx = Codec::default();
        let now = Instant::now();
        for len in 0..frames[0].len() {
            assert!(rx.receive(peer(1), &frames[0][..len], now).is_none());
        }
        assert!(rx.pending.is_empty());
        for range in [0..2, 2..4, 4..6, 6..8] {
            let mut frame = frames[0].clone();
            frame[range].fill(255);
            assert!(rx.receive(peer(1), &frame, now).is_none());
        }
        assert!(rx.pending.is_empty());
        assert!(rx.receive(peer(1), &frames[0], now).is_none());
        let mut inconsistent = frames[1].clone();
        inconsistent[2..4].copy_from_slice(&1499u16.to_be_bytes());
        inconsistent.pop();
        assert!(rx.receive(peer(1), &inconsistent, now).is_none());
        assert_eq!(rx.receive(peer(1), &frames[1], now), Some(vec![42; 1500]));
    }
}
