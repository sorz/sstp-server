#[cfg(avx512_decode)]
use core::arch::x86_64::{
    _mm512_cmpeq_epi8_mask, _mm512_loadu_epi8, _mm512_mask_blend_epi8,
    _mm512_mask_compressstoreu_epi8, _mm512_set1_epi8, _mm512_xor_si512,
};
use std::cmp;

use crate::{CONTROL_ESCAPE, ESCAPE_MASK, FLAG_SEQUENCE};

const SSTP_HEADER_LEN: usize = 4;
const SSTP_VERSION: u8 = 0x10;
const SSTP_DATA_PACKET: u8 = 0x00;

const PPP_ADDR_CTRL: &[u8] = b"\xff\x03";
const PPP_CTRL_PROTOS: [u8; 4] = [
    // https://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml
    0x80, // 0x80** various protos, incl. 8021 IPCP, 8057 IP6CP
    0x82, // 0x82** few more
    0xC0, // 0xC0** incl. C021 LCP, C023 PAP
    0xC2, // 0xC2** incl. C223 CHAP, C227 EAP
];

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

pub(crate) struct FrameWriter<'a> {
    buf: &'a mut [u8],
    start: usize,
    pos: usize,
    ctrl_only: bool,
}

/// Feed unescaped PPP frame, write out SSTP data packet
/// Filter out broken frames and optionally non-ctrl frames
impl<'a> FrameWriter<'a> {
    fn new(buf: &'a mut [u8], ctrl_only: bool) -> Self {
        Self {
            buf,
            start: 0,
            pos: SSTP_HEADER_LEN, // jump after SSTP header
            ctrl_only,
        }
    }

    #[inline]
    fn write_u8(&mut self, byte: u8) {
        self.buf[self.pos] = byte;
        self.pos += 1;
    }

    #[inline]
    fn write_slice(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    #[inline]
    #[cfg(avx512_decode)]
    fn write_ptr(&mut self) -> *mut u8 {
        self.buf[self.pos..].as_mut_ptr()
    }

    #[inline]
    #[cfg(avx512_decode)]
    fn adv(&mut self, n: usize) {
        self.pos += n;
    }

    #[inline]
    fn has_space_for(&self, ppp_bytes: usize) -> bool {
        let ppp_bytes = cmp::min(0x0fff - 4, ppp_bytes);
        ppp_bytes == 0 || self.pos + ppp_bytes < self.buf.len()
    }

    /// Move `tail` bytes to the next SSTP packet before finish current one
    #[inline]
    #[cfg(avx512_decode)]
    fn insert_frame(&mut self, tail: usize) {
        let tail = self.pos..self.pos + tail;
        self.next_frame();
        self.buf.copy_within(tail, self.pos);
    }

    #[inline]
    fn next_frame(&mut self) {
        // check ppp frame
        let ppp = &self.buf[self.start + SSTP_HEADER_LEN..self.pos];
        if ppp.len() <= 3 {
            // 2-byte fcs + 1-byte ppp header
            return self.drop_frame();
        }
        if self.ctrl_only && !is_ppp_ctrl_frame(ppp) {
            return self.drop_frame();
        }

        // build sstp packet
        self.pos -= 2; // remove 2-byte trailing fcs of ppp
        self.buf[self.start] = SSTP_VERSION;
        self.buf[self.start + 1] = SSTP_DATA_PACKET;
        // packet length: 12-bit max in network order
        let len = self.pos - self.start;
        if len > 0x0fff {
            return self.drop_frame();
        }
        self.buf[self.start + 2] = (len >> 8) as u8;
        self.buf[self.start + 3] = len as u8;

        // next frame
        self.start = self.pos;
        self.pos = self.start + SSTP_HEADER_LEN;
    }

    #[inline]
    fn drop_frame(&mut self) {
        self.pos = self.start + SSTP_HEADER_LEN;
    }

    /// Return written SSTP streams and unfinished PPP frame (if any)
    fn finish(self) -> (&'a [u8], &'a [u8]) {
        (
            &self.buf[..self.start],
            &self.buf[self.start + SSTP_HEADER_LEN..self.pos],
        )
    }
}

/// Unescape all `raw` frames into `out` buffer
/// Put (start index, length) of each frame to `frames` vec
/// Update `partial` with remaining frame data
pub(crate) fn decode_frames(
    partial: &mut PartialFrame,
    input: &[u8],
    out: &mut [u8],
    ctrl_only: bool,
) -> usize {
    let mut writer = FrameWriter::new(out, ctrl_only);
    // fill with incomplete frame from the last call
    writer.write_slice(&partial.frame);

    let escaped = if input.len() < 640 {
        decode_scalar(input, partial.escaped, &mut writer)
    } else {
        #[cfg(avx512_decode)]
        {
            let (esc, rem) = decode_vector(input, partial.escaped, &mut writer);
            decode_scalar(rem, esc, &mut writer)
        }
        #[cfg(not(avx512_decode))]
        decode_scalar(input, partial.escaped, &mut writer)
    };

    // save incomplete frame for next call
    let (output, todo) = writer.finish();
    partial.escaped = escaped;
    partial.frame.clear();
    partial.frame.extend_from_slice(todo);
    output.len()
}

fn decode_scalar(input: &[u8], esc_first: bool, writer: &mut FrameWriter) -> bool {
    let mut mask = if esc_first { ESCAPE_MASK } else { 0 };
    for (byte_consumed, &byte) in input.iter().enumerate() {
        match byte {
            FLAG_SEQUENCE => {
                writer.next_frame();
                if !writer.has_space_for(input.len() - (byte_consumed + 1)) {
                    return false;
                }
            }
            CONTROL_ESCAPE => mask = ESCAPE_MASK,
            _ => {
                writer.write_u8(byte ^ mask);
                mask = 0;
            }
        }
    }
    mask == ESCAPE_MASK
}

#[cfg(avx512_decode)]
fn decode_vector<'a>(
    input: &'a [u8],
    esc_first: bool,
    writer: &mut FrameWriter,
) -> (bool, &'a [u8]) {
    let flag = unsafe { _mm512_set1_epi8(FLAG_SEQUENCE as i8) };
    let ctrl = unsafe { _mm512_set1_epi8(CONTROL_ESCAPE as i8) };
    let esc = unsafe { _mm512_set1_epi8(ESCAPE_MASK as i8) };

    let mut escape: u64 = if esc_first { 1 } else { 0 };
    let mut chunks = input.chunks_exact(64);
    for (chunk_consumed, chunk) in chunks.by_ref().enumerate() {
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
            let mask_keep = !(mask_flag | mask_ctrl);
            _mm512_mask_compressstoreu_epi8(writer.write_ptr() as *mut i8, mask_keep, input);
            (mask_keep, mask_flag)
        };
        if flag == 0 {
            // fast path
            writer.adv(keep.count_ones() as usize);
        } else {
            let mut bytes_consumed = chunk_consumed * 64;
            while keep > 0 {
                let n = flag.trailing_zeros();
                let len = (keep.unbounded_shl(64 - n)).count_ones();
                writer.adv(len as usize);
                if flag > 0 {
                    let tail = keep.count_ones() - len;
                    writer.insert_frame(tail as usize);
                    bytes_consumed += len as usize;
                    if !writer.has_space_for(input.len() - bytes_consumed) {
                        // TODO: log warning
                        return (false, &[]);
                    }
                }
                flag = flag.unbounded_shr(n + 1);
                keep = keep.unbounded_shr(n + 1);
            }
        }
    }
    (escape == 1, chunks.remainder())
}

fn is_ppp_ctrl_frame(buf: &[u8]) -> bool {
    if buf.starts_with(PPP_ADDR_CTRL) {
        buf.get(PPP_ADDR_CTRL.len())
    } else {
        // address & control field is omitted
        buf.first()
    }
    .map(|proto| PPP_CTRL_PROTOS.contains(proto))
    .unwrap_or_default()
}

#[test]
fn test_is_ppp_ctrl_frame() {
    assert!(is_ppp_ctrl_frame(b"\xff\x03\x80\x21")); // IPCP
    assert!(is_ppp_ctrl_frame(b"\x80\x57")); // IP6CP
    assert!(is_ppp_ctrl_frame(b"\xc2\x23")); // CHAP
    assert!(!is_ppp_ctrl_frame(b"\xff\x02\x21")); // IPv4
    assert!(!is_ppp_ctrl_frame(b"\x57")); // IPv4
}

#[test]
fn test_frame_writer() {
    let mut buf = [0u8; 1000];
    let mut w = FrameWriter::new(&mut buf, false);

    // write empty frame
    w.next_frame();
    w.next_frame();

    // write short frame (u8)
    w.write_u8(b'A');
    w.write_u8(b'A');
    assert_eq!(w.pos, 4 + 2);
    w.next_frame();
    assert_eq!(w.start, 0);
    assert_eq!(w.pos, 4);

    // write short frame (slice)
    w.write_slice(b"AAA");
    assert_eq!(w.pos, 4 + 3);
    w.next_frame();

    // good frame 1
    w.write_slice(b"ABC12");
    w.write_u8(b'3');
    w.write_slice(b"DEF--");
    w.next_frame();

    // good frame 2
    w.write_slice(b"778899--");
    w.next_frame();

    // bad after good
    w.write_slice(b"AAA");
    w.next_frame();

    // half frame
    w.write_slice(b"456");

    let (out, half) = w.finish();
    assert_eq!(out[0], SSTP_VERSION);
    assert_eq!(out[1], SSTP_DATA_PACKET);
    assert_eq!(out[2..4], 13u16.to_be_bytes());
    assert!(out[4..].starts_with(b"ABC123DEF"));
    assert!(out.ends_with(b"778899"));
    assert_eq!(half, b"456");
}
