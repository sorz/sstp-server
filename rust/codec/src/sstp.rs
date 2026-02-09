use pyo3::{exceptions::PyValueError, prelude::*};

use crate::ppp;

pub(crate) enum SstpPacket<'a> {
    Control(&'a [u8]),
    Data(SstpDataPacket<'a>),
}

pub(crate) struct SstpDataPacket<'a> {
    pub(crate) ppp: PppFrameType,
    pub(crate) payload: &'a [u8],
}

pub(crate) enum PppFrameType {
    Data,
    Ctrl,
}

impl<'a> SstpPacket<'a> {
    pub(crate) fn len(&self) -> usize {
        match self {
            Self::Control(pkt) => pkt.len(),
            Self::Data(SstpDataPacket { payload, .. }) => payload.len() + 4,
        }
    }
}

/// Get the first completed SSTP packet on `buf`
/// Return PyValueError if SSTP protocol is not 0x10
pub(crate) fn get_first_completed_packet(buf: &[u8]) -> PyResult<Option<&[u8]>> {
    // check version
    match buf.first() {
        None => return Ok(None),
        Some(&0x10) => (),
        Some(_) => return Err(PyValueError::new_err("unsupported SSTP version")),
    };
    // parse packet length
    let len = match (buf.get(2), buf.get(3)) {
        (Some(&a), Some(&b)) => (u16::from_be_bytes([a, b]) & 0x0fff) as usize,
        _ => return Ok(None),
    };
    if buf.len() < len {
        Ok(None)
    } else {
        Ok(Some(&buf[..len]))
    }
}

pub(crate) fn get_next_packet(buf: &[u8]) -> PyResult<Option<SstpPacket<'_>>> {
    let buf = match get_first_completed_packet(buf)? {
        None => return Ok(None),
        Some(buf) => buf,
    };
    let payload = &buf[4..];
    let pkt = if buf[1] & 0x01 == 1 {
        SstpPacket::Control(buf)
    } else {
        let ppp = if ppp::is_ppp_ctrl_frame(payload) {
            PppFrameType::Ctrl
        } else {
            PppFrameType::Data
        };
        SstpPacket::Data(SstpDataPacket { ppp, payload })
    };
    Ok(Some(pkt))
}
