//! MD5 (RFC 1321) — std-only.
//!
//! Present for one reason: **import hashing**. `imphash` is defined by the
//! wider malware-analysis ecosystem as an MD5 over the normalized import
//! table, so producing the same value as `pefile`/VirusTotal requires the
//! same hash function. Everything else in this crate keeps using SHA-256
//! (`src/sha256.rs`); MD5 here is a *fingerprint*, never a security claim.

use std::io::Read;
use std::path::Path;

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
];

fn compress(state: &mut [u32; 4], block: &[u8]) {
    debug_assert_eq!(block.len(), 64);
    let mut m = [0u32; 16];
    for (i, word) in m.iter_mut().enumerate() {
        let o = i * 4;
        *word = u32::from_le_bytes([block[o], block[o + 1], block[o + 2], block[o + 3]]);
    }
    let [mut a, mut b, mut c, mut d] = *state;
    for i in 0..64 {
        let (f, g) = match i / 16 {
            0 => ((b & c) | (!b & d), i),
            1 => ((d & b) | (!d & c), (5 * i + 1) % 16),
            2 => (b ^ c ^ d, (3 * i + 5) % 16),
            _ => (c ^ (b | !d), (7 * i) % 16),
        };
        let tmp = d;
        d = c;
        c = b;
        b = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(K[i])
                .wrapping_add(m[g])
                .rotate_left(S[i]),
        );
        a = tmp;
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
}

/// Incremental MD5 fingerprint; never used as an integrity guarantee.
#[derive(Clone)]
pub struct Md5 {
    state: [u32; 4],
    buffer: [u8; 64],
    used: usize,
    total: u64,
}

impl Md5 {
    pub fn new() -> Self {
        Self { state: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476],
            buffer: [0; 64], used: 0, total: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.used > 0 {
            let take = (64 - self.used).min(data.len());
            self.buffer[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < 64 { return; }
            compress(&mut self.state, &self.buffer);
            self.used = 0;
        }
        while data.len() >= 64 {
            compress(&mut self.state, &data[..64]);
            data = &data[64..];
        }
        self.buffer[..data.len()].copy_from_slice(data);
        self.used = data.len();
    }

    pub fn finalize(mut self) -> [u8; 16] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.used != 56 { self.update(&[0]); }
        self.update(&bits.to_le_bytes());
        let mut out = [0u8; 16];
        for (i, word) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

impl Default for Md5 {
    fn default() -> Self { Self::new() }
}

/// Raw 16-byte MD5 digest.
pub fn digest(data: &[u8]) -> [u8; 16] {
    let mut hash = Md5::new();
    hash.update(data);
    hash.finalize()
}

/// Lowercase hex MD5 of a byte slice.
pub fn hash_bytes(data: &[u8]) -> String {
    let mut hex = String::with_capacity(32);
    for byte in digest(data) {
        hex.push(char::from_digit((byte >> 4) as u32, 16).unwrap_or('0'));
        hex.push(char::from_digit((byte & 0x0f) as u32, 16).unwrap_or('0'));
    }
    hex
}

/// Streaming MD5 of a file (used for imphash inputs that may be large).
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut hash = Md5::new();
    loop {
        let read = file.read(&mut buf)?;
        if read == 0 { break; }
        hash.update(&buf[..read]);
    }
    Ok(crate::sha256::to_hex(&hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incremental_chunks_and_padding_boundaries_match_vectors() {
        for len in [0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 1000] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            for chunk in [1, 3, 7, 63, 64, 65, 129] {
                let mut hash = Md5::new();
                for bytes in data.chunks(chunk) {
                    hash.update(bytes);
                    hash.update(&[]);
                }
                assert_eq!(hash.finalize(), digest(&data), "len {len}, chunk {chunk}");
            }
        }
        let mut hash = Md5::new();
        for _ in 0..1000 { hash.update(&[b'a'; 1000]); }
        assert_eq!(crate::sha256::to_hex(&hash.finalize()), "7707d6ae4e027c70eea2a935c2296f21");
    }

    #[test]
    fn rfc1321_vectors() {
        assert_eq!(hash_bytes(b""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(hash_bytes(b"abc"), "900150983cd24fb0d6963f7d28e17f72");
        assert_eq!(
            hash_bytes(b"message digest"),
            "f96b697d7cb7938d525a2f31aaf161d0"
        );
        assert_eq!(
            hash_bytes(b"12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
            "57edf4a22be3c955ac49da2e2107b67a"
        );
    }

    #[test]
    fn multi_block_matches_streaming_file() {
        // > 4 blocks + a partial tail exercises the length padding.
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        assert_eq!(hash_bytes(&data), hash_bytes(&data.clone()));
        let dir = std::env::temp_dir().join(format!("rea_offline_md5_{}", crate::util::new_id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("blob.bin");
        std::fs::write(&path, &data).unwrap();
        assert_eq!(hash_file(&path).unwrap(), hash_bytes(&data));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
