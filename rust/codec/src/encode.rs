use crate::{CONTROL_ESCAPE, ESCAPE_MASK, FLAG_SEQUENCE, fcs};

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
    let mut fcs = fcs::Fcs::new();
    let mut buf_pos = 0;
    // encode flag
    buf[buf_pos] = FLAG_SEQUENCE;
    buf_pos += 1;

    // encode main body
    let (len, remainder) = encode_scalar(full, &mut fcs, data, &mut buf[buf_pos..]);
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
    fcs: &mut fcs::Fcs,
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
