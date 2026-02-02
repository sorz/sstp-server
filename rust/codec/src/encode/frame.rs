#[cfg(avx512)]
use core::arch::x86_64::{
    __m256i, _cvtmask32_u32, _cvtmask64_u64, _kor_mask32, _kor_mask64, _kshiftli_mask64,
    _mm256_cmpeq_epi8_mask, _mm256_loadu_si256, _mm256_set1_epi8, _mm256_storeu_si256,
    _mm512_bslli_epi128, _mm512_cmpeq_epi8_mask, _mm512_cvtepu8_epi16, _mm512_mask_blend_epi8,
    _mm512_mask_compressstoreu_epi8, _mm512_or_si512, _mm512_set1_epi8, _mm512_set1_epi16,
    _mm512_xor_si512,
};

use super::fcs::Fcs;
use crate::{CONTROL_ESCAPE, ESCAPE_MASK, FLAG_SEQUENCE};

// FLAG_SEQUENCE, CONTROL_ESCAPE, and any < ESCAPE_MASK
const ESACPE_MAP_FULL: [bool; 256] = {
    let mut table = [false; 256];
    table[FLAG_SEQUENCE as usize] = true;
    table[CONTROL_ESCAPE as usize] = true;
    let mut i = 0;
    while i < ESCAPE_MASK as usize {
        table[i] = true;
        i += 1;
    }
    table
};

#[inline]
fn full_escape_to(bytes: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0;
    for &byte in bytes {
        if ESACPE_MAP_FULL[byte as usize] {
            out[pos] = CONTROL_ESCAPE;
            out[pos + 1] = byte ^ ESCAPE_MASK;
            pos += 2;
        } else {
            out[pos] = byte;
            pos += 1
        }
    }
    pos
}

#[inline]
fn escape_to(bytes: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0;
    for &byte in bytes {
        if byte == CONTROL_ESCAPE || byte == FLAG_SEQUENCE {
            out[pos] = CONTROL_ESCAPE;
            out[pos + 1] = byte ^ ESCAPE_MASK;
            pos += 2;
        } else {
            out[pos] = byte;
            pos += 1
        }
    }
    pos
}

macro_rules! escape_to {
    ($full:expr, $bytes:expr, $out:expr) => {
        if $full {
            full_escape_to($bytes, $out)
        } else {
            escape_to($bytes, $out)
        }
    };
}

pub(crate) fn encode_frame(full: bool, data: &[u8], buf: &mut [u8]) -> usize {
    let mut fcs = Fcs::new();
    let mut buf_pos = 0;
    // encode flag
    buf[buf_pos] = FLAG_SEQUENCE;
    buf_pos += 1;

    // encode main body
    // let (len, remainder) = encode_scalar(full, &mut fcs, data, &mut buf[buf_pos..]);
    let (len, remainder) = if full || data.len() < 640 {
        encode_scalar(full, &mut fcs, data, &mut buf[buf_pos..])
    } else {
        #[cfg(avx512)]
        {
            let (len, rem) = encode_vector(&mut fcs, data, &mut buf[buf_pos..]);
            buf_pos += len;
            encode_scalar(full, &mut fcs, rem, &mut buf[buf_pos..])
        }
        #[cfg(not(avx512))]
        encode_scalar(full, &mut fcs, data, &mut buf[buf_pos..])
    };
    buf_pos += len;

    // encode remainder
    fcs.update(remainder);
    buf_pos += escape_to!(full, remainder, &mut buf[buf_pos..]);
    // encode fcs and flag
    buf_pos += escape_to!(full, &fcs.checksum().to_le_bytes(), &mut buf[buf_pos..]);
    buf[buf_pos] = FLAG_SEQUENCE;
    buf_pos += 1;
    buf_pos
}

fn encode_scalar<'a>(
    full: bool,
    fcs: &mut Fcs,
    raw: &'a [u8],
    out: &mut [u8],
) -> (usize, &'a [u8]) {
    let mut chunks = raw.chunks_exact(8);
    let mut pos = 0;
    for chunk in chunks.by_ref() {
        fcs.update(chunk);
        pos += escape_to!(full, chunk, &mut out[pos..]);
    }
    (pos, chunks.remainder())
}

/// Escape frame data with AVX-512 instructions
///
/// Similar to https://lemire.me/blog/2022/09/14/escaping-strings-faster-with-avx-512/
/// Steps:
/// 1. read 32 bytes (128 bits) in each chunk
/// 2. fast check, bypass if no flag/ctrl found
/// 3. pad zero byte before/after each input byte, result in two 512b vectors
///    - input_lo: 0D0D0D...0D0D (lo - data is on the lower bits of each i16)
///    - input_hi: D0D0D0...D0D0 (D - input byte, 0 - 0x00 padding)
/// 4. check flag/ctrl against to input_hi to get mask
/// 5. xor input data with ESCAPE_MASK, use the mask to select bytes from
///    either raw or xor-ed data
/// 6. put CONTROL_ESCAPE before each data bytes
/// 7. write out bytes, use the mask to skip unwanted control bytes
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx",
    target_feature = "avx512f",
    target_feature = "avx512bw",
    target_feature = "avx512vl",
    target_feature = "avx512vbmi2"
))]
pub(crate) fn encode_vector<'a>(fcs: &mut Fcs, raw: &'a [u8], out: &mut [u8]) -> (usize, &'a [u8]) {
    let mut chunks = raw.chunks_exact(32);
    let mut pos = 0;

    let flag_32 = unsafe { _mm256_set1_epi8(FLAG_SEQUENCE as i8) };
    let ctrl_32 = unsafe { _mm256_set1_epi8(CONTROL_ESCAPE as i8) };

    let flag = unsafe { _mm512_set1_epi8(FLAG_SEQUENCE as i8) };
    let ctrl_lo = unsafe { _mm512_set1_epi16(i16::from_le_bytes([CONTROL_ESCAPE, 0x00])) };
    let esc_hi = unsafe { _mm512_set1_epi16(i16::from_le_bytes([0x00, ESCAPE_MASK])) };
    let mask_hi = 0xaaaa_aaaa_aaaa_aaaa;

    for chunk in chunks.by_ref() {
        fcs.update(chunk);
        unsafe {
            let input = _mm256_loadu_si256(chunk.as_ptr() as *const __m256i);
            // fast check
            let bypass = {
                let is_flag = _mm256_cmpeq_epi8_mask(input, flag_32);
                let is_ctrl = _mm256_cmpeq_epi8_mask(input, ctrl_32);
                let mask = _kor_mask32(is_flag, is_ctrl);
                _cvtmask32_u32(mask) == 0
            };
            if bypass {
                _mm256_storeu_si256(out[pos..].as_mut_ptr() as *mut __m256i, input);
                pos += 32;
                continue;
            }
            // pad 0x00 after each of input byte
            let input_lo = _mm512_cvtepu8_epi16(input);
            // check flag & ctrl
            let is_special_lo = {
                let is_flag = _mm512_cmpeq_epi8_mask(input_lo, flag);
                let is_ctrl = _mm512_cmpeq_epi8_mask(input_lo, ctrl_lo);
                _kor_mask64(is_flag, is_ctrl)
            };
            // escape input data (xor with ESCAPE_MASK)
            let input_hi = {
                let input_hi = _mm512_bslli_epi128(input_lo, 1);
                let input_esc_hi = _mm512_xor_si512(input_hi, esc_hi);
                let is_special_hi = _kshiftli_mask64(is_special_lo, 1);
                _mm512_mask_blend_epi8(is_special_hi, input_hi, input_esc_hi)
            };
            // combine data & escape
            let output = _mm512_or_si512(input_hi, ctrl_lo);
            // write out data & required escape
            let keep = _kor_mask64(is_special_lo, mask_hi);
            _mm512_mask_compressstoreu_epi8(out[pos..].as_mut_ptr() as *mut i8, keep, output);
            pos += _cvtmask64_u64(keep).count_ones() as usize;
        }
    }
    (pos, chunks.remainder())
}
