use bytes::BufMut;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyMemoryView, PySlice};

mod fcs;

const FLAG_SEQUENCE: u8 = 0x7e;
const CONTROL_ESCAPE: u8 = 0x7d;
const ESCAPE_MASK: u8 = 0x20;

// FLAG_SEQUENCE, CONTROL_ESCAPE, and any < ESCAPE_MASK
const NEED_ESACPE: [bool; 256] = {
    let mut table = [false; 256];
    let mut i = 0;
    while i < ESCAPE_MASK as usize {
        table[i] = true;
        i += 1;
    }
    table[FLAG_SEQUENCE as usize] = true;
    table[CONTROL_ESCAPE as usize] = true;
    table
};

#[inline]
fn escape_to(bytes: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0;
    for &byte in bytes {
        if NEED_ESACPE[byte as usize] {
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

/// Escape a PPP frame ending with correct FCS code.
#[pyfunction]
fn escape<'py>(py: Python<'py>, data: &Bound<'py, PyBytes>) -> PyResult<Bound<'py, PyByteArray>> {
    let data = data.as_bytes();
    let mut fcs = fcs::Fcs::new();

    let mut buf_pos = 0;
    let buf = PyByteArray::new_with(py, (data.len() + 2) * 2 + 2, |buf| {
        buf[buf_pos] = FLAG_SEQUENCE;
        buf_pos += 1;

        // Safety: transmutes u8 to u64 is safe
        let (prefix, words, suffix) = unsafe { data.align_to::<u64>() };
        // prefix
        fcs.update(prefix);
        buf_pos += escape_to(prefix, &mut buf[buf_pos..]);
        // middle - fast slice-by-8 fcs
        for &word in words {
            fcs.update_u64(word);
            buf_pos += escape_to(&word.to_ne_bytes(), &mut buf[buf_pos..]);
        }
        // suffix
        fcs.update(suffix);
        buf_pos += escape_to(suffix, &mut buf[buf_pos..]);

        buf_pos += escape_to(&fcs.checksum().to_le_bytes(), &mut buf[buf_pos..]);
        buf[buf_pos] = FLAG_SEQUENCE;
        buf_pos += 1;
        Ok(())
    })?;
    buf.resize(buf_pos)?;
    Ok(buf)
}

/// PPP Decoder
#[pyclass]
struct PppDecoder {
    incomplete: Vec<u8>,
    escaped: bool,
}

#[pymethods]
impl PppDecoder {
    #[new]
    fn new() -> Self {
        PppDecoder {
            incomplete: Vec::new(),
            escaped: false,
        }
    }

    /// Unescape PPP frame stream, return a list of unescaped frame.
    fn unescape<'py>(
        &mut self,
        py: Python<'py>,
        data: &Bound<'py, PyBytes>,
    ) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let data = data.as_bytes();

        // unscape all data (all frames) into a single bytearray
        let mut frame_lens = Vec::new(); // length of each completed frame
        let buf = PyByteArray::new_with(py, self.incomplete.len() + data.len(), |buf| {
            let mut len = 0; // current incomplete frame's length
            let mut pos = 0; // writing position of the buf

            // fill with incomplete frame from the last call
            buf[..self.incomplete.len()].copy_from_slice(&self.incomplete);
            pos += self.incomplete.len();
            len += self.incomplete.len();

            let mut mask = if self.escaped { ESCAPE_MASK } else { 0 };
            for &byte in data {
                match byte {
                    FLAG_SEQUENCE => {
                        if len <= 4 {
                            // drop empty/short frames
                            // minimal: 2-byte fcs + 2-byte ppp header
                            pos = pos.saturating_sub(len);
                        } else {
                            // new frame, remove 2-byte trailing fcs
                            pos = pos.saturating_sub(2);
                            frame_lens.push(len - 2);
                        }
                        // continue to process next frame
                        len = 0;
                    }
                    CONTROL_ESCAPE => mask = ESCAPE_MASK,
                    _ => {
                        buf[pos] = byte ^ mask;
                        pos += 1;
                        len += 1;
                        mask = 0;
                    }
                }
            }

            // save incomplete frame for next call
            self.escaped = mask > 0;
            self.incomplete.clear();
            self.incomplete.put_slice(&buf[pos - len..pos]);
            Ok(())
        })?;

        match frame_lens.len() {
            0 => Ok(vec![]),
            1 => {
                // fast path: return bytearray
                buf.resize(frame_lens[0])?;
                Ok(vec![buf.into_any()])
            }
            _ => {
                // memoryview slicing
                let buf = PyMemoryView::from(&buf)?;
                frame_lens
                    .iter()
                    .scan(0, |pos, &len| {
                        *pos += len;
                        Some((*pos - len) as isize)
                    })
                    .zip(frame_lens.iter())
                    .map(|(pos, &len)| {
                        let slice = PySlice::new(py, pos, pos + len as isize, 1);
                        buf.get_item(slice)
                    })
                    .collect()
            }
        }
    }
}

#[pymodule]
fn codec(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(escape, m)?)?;
    m.add_class::<PppDecoder>()?;
    Ok(())
}
