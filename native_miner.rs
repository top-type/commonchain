// Tries nonces for one header, for a set time. node.py runs it for each slice of mining.
// Arguments: the first 76 header bytes in hex, the target in hex, the first nonce, microseconds to run.
// Prints "found <nonce>", or "none <next nonce> <hashes tried>" when the time is up.
// Build next to node.py with: rustc -C opt-level=3 -C codegen-units=1 native_miner.rs
use std::time::{Duration, Instant};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];
const START: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

fn compress_plain(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
    }
    let mut v = *state;
    for i in 0..64 {
        let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
        let ch = (v[4] & v[5]) ^ (!v[4] & v[6]);
        let t1 = v[7].wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
        let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
        let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        v = [t1.wrapping_add(s0.wrapping_add(maj)), v[0], v[1], v[2], v[3].wrapping_add(t1), v[4], v[5], v[6]];
    }
    for i in 0..8 {
        state[i] = state[i].wrapping_add(v[i]);
    }
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
unsafe fn compress_sha(state: &mut [u32; 8], block: &[u8; 64]) {
    use std::arch::x86_64::*;
    let tmp = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr() as *const __m128i), 0xB1);
    let hgfe = _mm_shuffle_epi32(_mm_loadu_si128(state.as_ptr().add(4) as *const __m128i), 0x1B);
    let mut abef = _mm_alignr_epi8(tmp, hgfe, 8);
    let mut cdgh = _mm_blend_epi16(hgfe, tmp, 0xF0);
    let (abef_start, cdgh_start) = (abef, cdgh);
    let swap = _mm_set_epi64x(0x0c0d0e0f08090a0bu64 as i64, 0x0405060700010203u64 as i64);
    let mut w = [_mm_setzero_si128(); 4];
    for i in 0..4 {
        w[i] = _mm_shuffle_epi8(_mm_loadu_si128(block.as_ptr().add(i * 16) as *const __m128i), swap);
    }
    for i in 0..16 {
        let wk = _mm_add_epi32(w[i & 3], _mm_loadu_si128(K.as_ptr().add(i * 4) as *const __m128i));
        cdgh = _mm_sha256rnds2_epu32(cdgh, abef, wk);
        abef = _mm_sha256rnds2_epu32(abef, cdgh, _mm_shuffle_epi32(wk, 0x0E));
        if i < 12 {
            let carried = _mm_alignr_epi8(w[(i + 3) & 3], w[(i + 2) & 3], 4);
            let part = _mm_add_epi32(_mm_sha256msg1_epu32(w[i & 3], w[(i + 1) & 3]), carried);
            w[i & 3] = _mm_sha256msg2_epu32(part, w[(i + 3) & 3]);
        }
    }
    let abef = _mm_add_epi32(abef, abef_start);
    let cdgh = _mm_add_epi32(cdgh, cdgh_start);
    let feba = _mm_shuffle_epi32(abef, 0x1B);
    let dchg = _mm_shuffle_epi32(cdgh, 0xB1);
    _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, _mm_blend_epi16(feba, dchg, 0xF0));
    _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, _mm_alignr_epi8(dchg, feba, 8));
}

fn from_hex(text: &str) -> Vec<u8> {
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).expect("hex")).collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let prefix = from_hex(&args[1]);
    let target = from_hex(&args[2]);
    assert!(prefix.len() == 76 && target.len() == 32);
    let mut nonce: u32 = args[3].parse().expect("nonce");
    let budget = Duration::from_micros(args[4].parse().expect("microseconds"));
    let plain = std::env::var_os("NATIVE_MINER_PLAIN").is_some();
    #[cfg(target_arch = "x86_64")]
    let compress: unsafe fn(&mut [u32; 8], &[u8; 64]) = if !plain && is_x86_feature_detected!("sha") && is_x86_feature_detected!("sse4.1") && is_x86_feature_detected!("ssse3") {
        compress_sha
    } else {
        compress_plain_call
    };
    #[cfg(not(target_arch = "x86_64"))]
    let compress: unsafe fn(&mut [u32; 8], &[u8; 64]) = compress_plain_call;

    let mut mid = START;
    let mut first = [0u8; 64];
    first.copy_from_slice(&prefix[..64]);
    let mut second = [0u8; 64];
    second[..12].copy_from_slice(&prefix[64..76]);
    second[16] = 0x80;
    second[62] = 0x02; // 640 bits
    second[63] = 0x80;
    let mut third = [0u8; 64];
    third[32] = 0x80;
    third[62] = 0x01; // 256 bits
    let top_target = u32::from_be_bytes([target[0], target[1], target[2], target[3]]);
    let started = Instant::now();
    let mut tried: u64 = 0;
    unsafe {
        compress(&mut mid, &first);
        loop {
            for _ in 0..16384 {
                second[12..16].copy_from_slice(&nonce.to_le_bytes());
                let mut inner = mid;
                compress(&mut inner, &second);
                for i in 0..8 {
                    third[i * 4..i * 4 + 4].copy_from_slice(&inner[i].to_be_bytes());
                }
                let mut outer = START;
                compress(&mut outer, &third);
                if outer[7].swap_bytes() <= top_target {
                    let mut hash = [0u8; 32];
                    for i in 0..8 {
                        hash[i * 4..i * 4 + 4].copy_from_slice(&outer[i].to_be_bytes());
                    }
                    hash.reverse();
                    if hash[..] <= target[..] {
                        println!("found {}", nonce);
                        return;
                    }
                }
                nonce = nonce.wrapping_add(1);
            }
            tried += 16384;
            if started.elapsed() >= budget {
                println!("none {} {}", nonce, tried);
                return;
            }
        }
    }
}

unsafe fn compress_plain_call(state: &mut [u32; 8], block: &[u8; 64]) {
    compress_plain(state, block)
}
