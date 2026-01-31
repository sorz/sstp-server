use bytes::BufMut;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyMemoryView, PySlice};

mod fcs;
mod encode;

const FLAG_SEQUENCE: u8 = 0x7e;
const CONTROL_ESCAPE: u8 = 0x7d;
const ESCAPE_MASK: u8 = 0x20;

/// Escape a PPP frame ending with correct FCS code.
#[pyfunction]
 #[pyo3(signature = (data, full = true))]
fn escape<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyBytes>,
    full: bool)
-> PyResult<Bound<'py, PyByteArray>> {
    let data = data.as_bytes();
    let mut len = 0;
    let buf = PyByteArray::new_with(py, (data.len() + 2) * 2 + 2, |buf| {
        len = encode::encode_frame(full, data, buf);
        Ok(())
    })?;
    buf.resize(len)?;
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
