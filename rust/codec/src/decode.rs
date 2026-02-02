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
    fn adv(&mut self, n: usize) {
        self.len += n;
    }

    pub(crate) fn end(&self) -> usize {
        self.start + self.len
    }

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
    mut raw: &[u8],
    out: &mut [u8],
    frames: &mut Vec<Frame>,
) {
    let mut frame: Frame = Default::default();
    // fill with incomplete frame from the last call
    out[..partial.len()].copy_from_slice(&partial.frame);
    frame.adv(partial.len());

    // first byte relates to previous call
    if partial.escaped {
        match raw.first() {
            None => return,
            Some(&FLAG_SEQUENCE) => {
                // CONTROL_ESCAPE ++ FLAG_SEQUENCE => cancaled frame
                frame.drop();
            }
            Some(b) => {
                raw = &raw[1..];
                out[frame.end()] = b ^ ESCAPE_MASK;
                frame.adv(1);
            }
        };
    }

    let escaped = decode_scalar(raw, out, &mut frame, frames);

    // save incomplete frame for next call
    partial.escaped = escaped;
    partial.frame.clear();
    partial
        .frame
        .extend_from_slice(&out[frame.start..frame.end()]);
}

fn decode_scalar(input: &[u8], out: &mut [u8], frame: &mut Frame, frames: &mut Vec<Frame>) -> bool {
    let mut mask = 0;

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
