mod decode;
mod encode;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyList, PyMemoryView, PySlice};
use smallvec::SmallVec;

const FLAG_SEQUENCE: u8 = 0x7e;
const CONTROL_ESCAPE: u8 = 0x7d;
const ESCAPE_MASK: u8 = 0x20;

/// Escape a PPP frame ending with correct FCS code.
#[pyfunction]
#[pyo3(signature = (frames, full = true))]
fn escape<'py>(
    py: Python<'py>,
    frames: &Bound<'py, PyList>,
    full: bool,
) -> PyResult<Bound<'py, PyByteArray>> {
    let max_output_len = frames
        .iter()
        .fold(0, |len, f| len + (f.len().unwrap_or_default() + 2) * 2 + 2);

    let mut output_len = 0;
    let output = PyByteArray::new_with(py, max_output_len, |buf| {
        for item in frames.iter() {
            let data = {
                let mv = item.cast::<PyMemoryView>()?;
                let buf = PyBuffer::<u8>::get(&mv)?;
                if !buf.readonly() {
                    return Err(PyValueError::new_err("frame must be readonly buffer"));
                }
                let len = buf.item_count();
                let buf = buf.buf_ptr() as *const u8;
                // Safety: it's bytearray-backed contiguous readonly memoryview
                // no code on Python side will read/write to this buffer
                unsafe { std::slice::from_raw_parts(buf, len) }
            };
            output_len += encode::encode_frame(full, data, &mut buf[output_len..]);
        }
        Ok(())
    })?;
    output.resize(output_len)?;
    Ok(output)
}

/// PPP Decoder
#[pyclass]
struct PppDecoder {
    frame: decode::PartialFrame,
}

#[pymethods]
impl PppDecoder {
    #[new]
    fn new() -> Self {
        PppDecoder {
            frame: Default::default(),
        }
    }

    /// Unescape PPP frame stream, return a list of unescaped frame.
    fn unescape<'py>(
        &mut self,
        py: Python<'py>,
        data: &Bound<'py, PyBytes>,
    ) -> PyResult<Vec<Bound<'py, PyAny>>> {
        let data = data.as_bytes();

        let mut frames = SmallVec::new();
        let buf = PyByteArray::new_with(py, self.frame.len() + data.len(), |buf| {
            decode::decode_frames(&mut self.frame, data, buf, &mut frames);
            Ok(())
        })?;

        match frames.len() {
            0 => Ok(vec![]),
            1 if frames[0].start() == 0 => {
                // fast path: return bytearray
                buf.resize(frames[0].len())?;
                Ok(vec![buf.into_any()])
            }
            _ => {
                // memoryview slicing (avoid data copy)
                let buf = PyMemoryView::from(&buf)?;
                frames
                    .into_iter()
                    .map(|f| {
                        let slice = PySlice::new(py, f.start() as isize, f.end() as isize, 1);
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
