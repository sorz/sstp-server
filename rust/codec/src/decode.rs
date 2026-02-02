#[cfg(avx512_decode)]
use core::arch::x86_64::{
     _mm512_cmpeq_epi8_mask, _mm512_mask_blend_epi8,
    _mm512_mask_compressstoreu_epi8, _mm512_set1_epi8,
    _mm512_xor_si512, _mm512_loadu_epi8
};

use crate::{CONTROL_ESCAPE, ESCAPE_MASK, FLAG_SEQUENCE};

#[derive(Debug, Default)]
pub(crate) struct PartialFrame {
    frame: Vec<u8>,
    escaped: bool,
}

impl PartialFrame {
    pub(crate) fn len(&self) -> usize {
        self.frame.len()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Frame {
    pub(crate) start: usize,
    pub(crate) len: usize,
}

impl Frame {
    #[inline]
    fn adv(&mut self, n: usize) {
        self.len += n;
    }

    #[inline]
    pub(crate) fn end(&self) -> usize {
        self.start + self.len
    }

    #[inline]
    fn drop(&mut self) {
        self.start += self.len;
        self.len = 0;
    }

    fn next(&mut self) -> Self {
        let done = Self {
            start: self.start,
            // trim 2-byte fcs
            len: self.len.saturating_sub(2),
        };
        self.drop();
        done
    }
}

/// Unescape all `raw` frames into `out` buffer
/// Put (start index, length) of each frame to `frames` vec
/// Update `partial` with remaining frame data
pub(crate) fn decode_frames(
    partial: &mut PartialFrame,
    input: &[u8],
    out: &mut [u8],
    frames: &mut Vec<Frame>,
) {
    let mut frame: Frame = Default::default();
    // fill with incomplete frame from the last call
    out[..partial.len()].copy_from_slice(&partial.frame);
    frame.adv(partial.len());

    let escaped = if input.len() < 640 {
        decode_scalar(input, out, partial.escaped, &mut frame, frames)
    } else {
        #[cfg(avx512_decode)]
        {
            let (esc, rem) = decode_vector(input, out, partial.escaped, &mut frame, frames);
            decode_scalar(rem, out, esc, &mut frame, frames)
        }
        #[cfg(not(avx512_decode))]
        decode_scalar(input, out, partial.escaped, &mut frame, frames)
    };

    // save incomplete frame for next call
    partial.escaped = escaped;
    partial.frame.clear();
    partial
        .frame
        .extend_from_slice(&out[frame.start..frame.end()]);
}

fn decode_scalar(input: &[u8], out: &mut [u8], esc_first: bool, frame: &mut Frame, frames: &mut Vec<Frame>) -> bool {
    let mut mask = if esc_first { ESCAPE_MASK } else { 0 };
    for &byte in input {
        match byte {
            FLAG_SEQUENCE => {
                if frame.len < 4 {
                    // drop empty/short frames
                    // minimal: 2-byte fcs + 2-byte ppp header
                    frame.drop();
                } else {
                    // new frame, remove 2-byte trailing fcs
                    frames.push(frame.next());
                }
            }
            CONTROL_ESCAPE => mask = ESCAPE_MASK,
            _ => {
                out[frame.end()] = byte ^ mask;
                frame.adv(1);
                mask = 0;
            }
        }
    }
    mask == ESCAPE_MASK
}

#[cfg(avx512_decode)]
fn decode_vector<'a>(
    input: &'a [u8],
    out: &mut [u8],
    esc_first: bool,
    frame: &mut Frame,
    frames: &mut Vec<Frame>
) -> (bool, &'a [u8]) {
    let flag = unsafe { _mm512_set1_epi8(FLAG_SEQUENCE as i8) };
    let ctrl = unsafe { _mm512_set1_epi8(CONTROL_ESCAPE as i8) };
    let esc = unsafe { _mm512_set1_epi8(ESCAPE_MASK as i8) };

    let mut escape: u64 = if esc_first { 1 } else { 0 };
    let mut chunks = input.chunks_exact(64);
    for chunk in chunks.by_ref() {
        let (mut keep, mut flag) = unsafe {
            // load data & compare with flag/ctrl
            let input = _mm512_loadu_epi8(chunk.as_ptr() as *const i8);
            let mask_flag = _mm512_cmpeq_epi8_mask(input, flag);
            let mask_ctrl = _mm512_cmpeq_epi8_mask(input, ctrl);
            // unescape input on mask_ctrl<<1 by xor with esc
            let input = {
                let unescaped = _mm512_xor_si512(input, esc);
                // escape = 1 if the first byte is escaped
                let mask = (mask_ctrl << 1) | escape;
                escape = mask_ctrl >> 63;
                _mm512_mask_blend_epi8(mask, input, unescaped)
            };
            // write out frame data
            let mask_keep = !(mask_flag|mask_ctrl);
            _mm512_mask_compressstoreu_epi8(
                out[frame.end()..].as_mut_ptr() as *mut i8,
                mask_keep,
                input
            );
            (mask_keep, mask_flag)
        };
        if flag == 0 { // fast path
            frame.adv(keep.count_ones() as usize);
        } else {
            while keep > 0 {
                let n = flag.trailing_zeros();
                let len = (keep.unbounded_shl(64 - n)).count_ones();
                frame.adv(len as usize);
                if flag > 0 {
                    if frame.len < 4 {
                        frame.next();
                    } else {
                        frames.push(frame.next());
                    }
                }
                flag = flag.unbounded_shr(n + 1);
                keep = keep.unbounded_shr(n + 1);
            }
        }
    }
    (escape == 1, chunks.remainder())
}
