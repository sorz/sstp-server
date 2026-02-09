use pyo3::{
    prelude::*,
    types::{PyByteArray, PyBytes},
};
use smallvec::SmallVec;
use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use crate::{
    ppp,
    sstp::{self, PppFrameType, SstpDataPacket, SstpPacket},
};

/// Repack PPP frames to SSTP packets
#[pyclass]
pub(crate) struct Sstp2Ppp {
    buf: Mutex<Option<Vec<u8>>>,
    sstp_control_received: Py<PyAny>,
    ppp_full_escape: AtomicBool,
    ppp_ctrl_only: AtomicBool,
    write_ppp_data: Mutex<Option<Py<PyAny>>>,
}

impl Sstp2Ppp {
    fn process(&self, py: Python<'_>, mut data: &[u8]) -> PyResult<Option<Vec<u8>>> {
        let mut data_pkts = SmallVec::<[&[u8]; 30]>::new();
        while let Some(pkt) = sstp::get_next_packet(data)? {
            data = &data[pkt.len()..];
            match pkt {
                SstpPacket::Control(pkt) => {
                    if !data_pkts.is_empty() {
                        self.process_data_packets(py, &data_pkts)?;
                        data_pkts.clear();
                    }
                    let buf = PyBytes::new(py, pkt);
                    self.sstp_control_received.call1(py, (buf,))?;
                }
                SstpPacket::Data(SstpDataPacket {
                    ppp: PppFrameType::Data,
                    ..
                }) if self.ppp_ctrl_only.load(Ordering::Relaxed) => (),
                SstpPacket::Data(SstpDataPacket { payload, .. }) => {
                    data_pkts.push(payload);
                }
            }
        }
        if !data_pkts.is_empty() {
            self.process_data_packets(py, &data_pkts)?;
            data_pkts.clear();
        }
        if data.is_empty() {
            Ok(None)
        } else {
            Ok(Some(data.into()))
        }
    }

    fn process_data_packets(&self, py: Python<'_>, pkts: &[&[u8]]) -> PyResult<()> {
        let max_output_len = pkts.iter().fold(0, |len, f| len + (f.len() + 2) * 2 + 2);
        let full_escape = self.ppp_full_escape.load(Ordering::Relaxed);
        let mut output_len = 0;
        let output = PyByteArray::new_with(py, max_output_len, |buf| {
            for pkt in pkts.iter() {
                output_len += ppp::encode_frame(full_escape, pkt, &mut buf[output_len..]);
            }
            Ok(())
        })?;
        output.resize(output_len)?;
        if let Some(callback) = &*self.write_ppp_data.lock().unwrap() {
            callback.call1(py, (output,))?;
        }
        Ok(())
    }
}

#[pymethods]
impl Sstp2Ppp {
    #[new]
    #[pyo3(signature = (sstp_control_received))]
    fn new(sstp_control_received: Py<PyAny>) -> Self {
        Self {
            buf: Default::default(),
            sstp_control_received,
            ppp_full_escape: true.into(),
            ppp_ctrl_only: true.into(),
            write_ppp_data: Default::default(),
        }
    }

    #[setter]
    fn set_ppp_full_escape(&self, new: bool) {
        self.ppp_full_escape.store(new, Ordering::Relaxed);
    }

    #[setter]
    fn set_ppp_ctrl_only(&self, new: bool) {
        self.ppp_ctrl_only.store(new, Ordering::Relaxed);
    }

    #[setter]
    fn set_write_ppp_data(&self, new: Py<PyAny>) {
        let mut lock = self.write_ppp_data.lock().unwrap();
        *lock = Some(new);
    }

    /// Decode stream of PPP frames into stream of SSTP packets
    /// Optionally keep only PPP control protocols
    fn write<'py>(&self, py: Python<'py>, data: &Bound<'py, PyBytes>) -> PyResult<()> {
        let mut buf_lock = self.buf.lock().unwrap();

        let rem = if let Some(mut buf) = buf_lock.take() {
            buf.extend_from_slice(data.as_bytes());
            if sstp::get_first_completed_packet(&buf)?.is_none() {
                *buf_lock = Some(buf);
                return Ok(());
            }
            self.process(py, &buf)?
        } else {
            let data = data.as_bytes();
            if sstp::get_first_completed_packet(data)?.is_none() {
                *buf_lock = Some(data.into());
                return Ok(());
            }
            self.process(py, data)?
        };

        *buf_lock = rem;
        Ok(())
    }
}
