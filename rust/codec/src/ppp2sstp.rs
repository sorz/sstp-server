use pyo3::{
    prelude::*,
    types::{PyByteArray, PyBytes},
};
use std::cmp;

use crate::ppp;

/// Repack PPP frames to SSTP packets
#[pyclass]
pub(crate) struct Ppp2Sstp {
    frame: ppp::PartialFrame,
    write_sstp_data: Py<PyAny>,
    #[pyo3(get, set)]
    ctrl_only: bool,
}

#[pymethods]
impl Ppp2Sstp {
    #[new]
    #[pyo3(signature = (write_sstp_data))]
    fn new(write_sstp_data: Py<PyAny>) -> Self {
        Self {
            frame: Default::default(),
            ctrl_only: true,
            write_sstp_data,
        }
    }

    /// Decode stream of PPP frames into stream of SSTP packets
    /// Optionally keep only PPP control protocols
    fn write<'py>(&mut self, py: Python<'py>, data: &Bound<'py, PyBytes>) -> PyResult<()> {
        let data = data.as_bytes();
        // each frame take up to [input + 1] bytes (4B sstp - 3B ppp flag/fcs),
        // with 2 more bytes for the last one (fcs before remove).
        // shortest ppp is 4B. 256 buffer should be enough?
        let max_output_len = self.frame.len() + data.len() + cmp::min(data.len() / 4 + 2, 256);
        let mut output_len = 0;
        let buf = PyByteArray::new_with(py, max_output_len, |buf| {
            output_len = ppp::decode_frames(&mut self.frame, data, buf, self.ctrl_only);
            Ok(())
        })?;
        buf.resize(output_len)?;
        self.write_sstp_data.call1(py, (buf,))?;
        Ok(())
    }
}
