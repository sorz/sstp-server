use anyhow::bail;
use nix::ioctl_write_ptr;
use std::{fs, os::raw::c_int};

// PPPIOCSASYNCMAP: include/uapi/linux/ppp-ioctl.h
ioctl_write_ptr!(ioctl_set_ppp_asyncmap, 't', 87, c_int);

/// Set send Async-Control-Character-Map (ACCM) on ppp link to 0
///
/// Normally it's negotiated over LCP. Our pppd ask receive map to be 0 by
/// default, while Windows do not set any value. Without async map been sent
/// on the other side, our send map will be 0xffffffff by default.
///
/// Set async map to zero enable faster frame unescape.
pub(crate) fn force_set_asyncmap_zero() -> anyhow::Result<()> {
    // use ioctl on ppp channel to set asyncmap
    // pppd do not expose ppp fd to plugin, so we search all opened fd instead
    for entry in fs::read_dir("/proc/self/fd")? {
        let path = entry?.path();
        let fd: c_int = match path.file_name() {
            None => continue,
            Some(name) => name.to_string_lossy().parse()?,
        };
        // better to check device id?
        if fs::read_link(&path)?.as_path() == "/dev/ppp" {
            match unsafe { ioctl_set_ppp_asyncmap(fd, &0) } {
                Ok(_) => return Ok(()),
                Err(err) => eprintln!("SSTP:INFO:failed to set asyncmap {}", err),
            }
        }
    }
    bail!("valid ppp fd not found")
}
