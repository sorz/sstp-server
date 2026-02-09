mod ppp;
mod ppp2sstp;
mod sstp;
mod sstp2ppp;

use pyo3::prelude::*;

#[pymodule]
fn codec(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ppp2sstp::Ppp2Sstp>()?;
    m.add_class::<sstp2ppp::Sstp2Ppp>()?;
    Ok(())
}
