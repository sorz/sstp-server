mod decode;
mod encode;

use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyMemoryView, PySlice};
use smallvec::SmallVec;

const FLAG_SEQUENCE: u8 = 0x7e;
const CONTROL_ESCAPE: u8 = 0x7d;
const ESCAPE_MASK: u8 = 0x20;

/// Escape a PPP frame ending with correct FCS code.
#[pyfunction]
#[pyo3(signature = (data, full = true))]
fn escape<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyBytes>,
    full: bool,
) -> PyResult<Bound<'py, PyByteArray>> {
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
