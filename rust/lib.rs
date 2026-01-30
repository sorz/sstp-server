use pyo3::prelude::*;
use pyo3::types::PyBytes;

mod fcs;

const FLAG_SEQUENCE: u8 = 0x7e;
const CONTROL_ESCAPE: u8 = 0x7d;
const ESCAPE_MASK: u8 = 0x20;
const MAX_FRAME_SIZE: usize = 9000;

#[inline]
fn escape_to(byte: u8, out: &mut Vec<u8>) {
    if byte < ESCAPE_MASK || byte == FLAG_SEQUENCE || byte == CONTROL_ESCAPE {
        out.push(CONTROL_ESCAPE);
        out.push(byte ^ ESCAPE_MASK);
    } else {
        out.push(byte);
    }
}

/// Escape a PPP frame ending with correct FCS code.
#[pyfunction]
fn escape<'py>(py: Python<'py>, data: &Bound<'py, PyBytes>) -> PyResult<Bound<'py, PyBytes>> {
    let data = data.as_bytes();
    let mut buffer = Vec::with_capacity((data.len() + 2) * 2 + 2);
    let mut fcs = fcs::Fcs::new();
    buffer.push(FLAG_SEQUENCE);

    // Calculate FCS
    fcs.update_bytes(data);

    // Escape data
    for &byte in data {
        escape_to(byte, &mut buffer);
    }

    let fcs = fcs.checksum();
    escape_to(fcs as u8, &mut buffer);
    escape_to((fcs >> 8) as u8, &mut buffer);

    buffer.push(FLAG_SEQUENCE);
    Ok(PyBytes::new(py, &buffer))
}

/// PPP Decoder
#[pyclass]
struct PppDecoder {
    frame_buf: Vec<u8>,
    escaped: bool,
}

#[pymethods]
impl PppDecoder {
    #[new]
    fn new() -> Self {
        PppDecoder {
            frame_buf: Vec::with_capacity(MAX_FRAME_SIZE),
            escaped: false,
        }
    }

    /// Unescape PPP frame stream, return a list of unescaped frame.
    fn unescape<'py>(
        &mut self,
        py: Python<'py>,
        data: &Bound<'py, PyBytes>,
    ) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let mut frames = Vec::new();
        let mut mask = if self.escaped { ESCAPE_MASK } else { 0 };
        for &byte in data.as_bytes() {
            match byte {
                FLAG_SEQUENCE => {
                    if self.frame_buf.len() > 4 {
                        // ignore 2-bytes FCS field
                        let bytes = PyBytes::new(py, &self.frame_buf[..self.frame_buf.len() - 2]);
                        frames.push(bytes);
                    }
                    self.frame_buf.clear();
                    mask = 0;
                }
                CONTROL_ESCAPE => mask = ESCAPE_MASK,
                _ => {
                    self.frame_buf.push(byte ^ mask);
                    mask = 0;
                }
            }
        }
        self.escaped = mask > 0;
        Ok(frames)
    }
}

#[pymodule]
fn codec(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(escape, m)?)?;
    m.add_class::<PppDecoder>()?;
    Ok(())
}
