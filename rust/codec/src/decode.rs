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

/// Unescape all `raw` frames into `out` buffer
/// Put index of last byte of each frame to `endings` vec
/// Put remaining frame data into `partial`
pub(crate) fn decode_frames(
    partial: &mut PartialFrame,
    raw: &[u8],
    out: &mut [u8],
    endings: &mut Vec<usize>,
) {
    let mut pos = 0; // writing position of `out`
    let mut len = 0; // current frame length
    // fill with incomplete frame from the last call
    out[..partial.len()].copy_from_slice(&partial.frame);
    pos += partial.len();
    len += partial.len();

    let mut mask = if partial.escaped { ESCAPE_MASK } else { 0 };
    for &byte in raw {
        match byte {
            FLAG_SEQUENCE => {
                if len <= 4 {
                    // drop empty/short frames
                    // minimal: 2-byte fcs + 2-byte ppp header
                    pos = pos.saturating_sub(len);
                } else {
                    // new frame, remove 2-byte trailing fcs
                    pos = pos.saturating_sub(2);
                    endings.push(pos);
                }
                // continue to process next frame
                len = 0;
            }
            CONTROL_ESCAPE => mask = ESCAPE_MASK,
            _ => {
                out[pos] = byte ^ mask;
                pos += 1;
                len += 1;
                mask = 0;
            }
        }
    }
    // save incomplete frame for next call
    partial.escaped = mask > 0;
    partial.frame.clear();
    partial.frame.extend_from_slice(&out[pos - len..pos]);
}
