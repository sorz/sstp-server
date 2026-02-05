mod ppp;

use pyo3::buffer::PyBuffer;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyList, PyMemoryView};
use std::cmp;

/// Escape a PPP frame ending with correct FCS code.
#[pyfunction]
#[pyo3(signature = (frames, full = true))]
fn sstp_to_ppp<'py>(
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
                let buf = PyBuffer::<u8>::get(mv)?;
                if !buf.readonly() {
                    return Err(PyValueError::new_err("frame must be readonly buffer"));
                }
                let len = buf.item_count();
                let buf = buf.buf_ptr() as *const u8;
                // Safety: it's bytearray-backed contiguous readonly memoryview
                // no code on Python side will read/write to this buffer
                unsafe { std::slice::from_raw_parts(buf, len) }
            };
            output_len += ppp::encode_frame(full, data, &mut buf[output_len..]);
        }
        Ok(())
    })?;
    output.resize(output_len)?;
    Ok(output)
}

/// PPP Decoder
#[pyclass]
struct PppDecoder {
    frame: ppp::PartialFrame,
}

#[pymethods]
impl PppDecoder {
    #[new]
    fn new() -> Self {
        PppDecoder {
            frame: Default::default(),
        }
    }

    /// Decode stream of PPP frames into stream of SSTP packets
    /// Optionally keep only PPP control protocols
    fn ppp_to_sstp<'py>(
        &mut self,
        py: Python<'py>,
        data: &Bound<'py, PyBytes>,
        ctrl_only: bool,
    ) -> PyResult<Bound<'py, PyByteArray>> {
        let data = data.as_bytes();
        // each frame take up to [input + 1] bytes (4B sstp - 3B ppp flag/fcs),
        // with 2 more bytes for the last one (fcs before remove).
        // shortest ppp is 4B. 256 buffer should be enough?
        let max_output_len = self.frame.len() + data.len() + cmp::min(data.len() / 4 + 2, 256);
        let mut output_len = 0;
        let buf = PyByteArray::new_with(py, max_output_len, |buf| {
            output_len = ppp::decode_frames(&mut self.frame, data, buf, ctrl_only);
            Ok(())
        })?;
        buf.resize(output_len)?;
        Ok(buf)
    }
}

#[pymodule]
fn codec(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sstp_to_ppp, m)?)?;
    m.add_class::<PppDecoder>()?;
    Ok(())
}
