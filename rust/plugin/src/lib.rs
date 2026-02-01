//! SSTP PPPD Plugin
//!
//! This plugin intent to be loaded by pppd via option `plugin /path/to/plugin.so`.
//! Upon loaded, it listens for NF_AUTH_UP event then extract key materials
//! required by SSTP for crypto binding.
//!
//! Unlike [sstp-client](https://gitlab.com/sstp-project/sstp-client)'s
//! plugin, it --
//! - sends hashed key (CMK) instead of raw keys to reduce risk of disclosure.
//! - does not implement compat functions for older version of pppd.
//! - uses pppd's stderr instead of dedicated unix domain socket.
mod hack;
mod key;
mod sys;

use std::{
    fmt,
    os::raw::{c_int, c_void},
    ptr,
};

/// pppd will check its version number with it,
/// and only work if they are matched.
#[unsafe(no_mangle)]
pub static pppd_version: [u8; 6] = *sys::PPPD_VERSION;

/// pppd plugin entry
/// register our notify here
#[unsafe(no_mangle)]
pub extern "C" fn plugin_init() {
    unsafe {
        sys::ppp_add_notify(
            sys::ppp_notify_t_NF_AUTH_UP,
            Some(notify_auth_up),
            ptr::null_mut(),
        );
    }
    eprintln!("SSTP:LOADED:{}", env!("CARGO_PKG_VERSION"));
}

/// Callback by pppd when authentication is done
unsafe extern "C" fn notify_auth_up(_ctx: *mut c_void, _arg: c_int) {
    let cmk = match key::extract_cmk() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("SSTP:ERROR:failed to extract cmk {}", e);
            return;
        }
    };
    eprintln!("SSTP:CMK:SHA256:{}", HexDisplay(&cmk.sha256));
    eprintln!("SSTP:CMK:SHA1:{}", HexDisplay(&cmk.sha1));

    match hack::force_set_asyncmap_zero() {
        Ok(_) => eprintln!("SSTP:ASYNCMAP:OK"),
        Err(err) => eprintln!("SSTP:ASYNCMAP:ERR:{}", err),
    }
}

struct HexDisplay<'a>(&'a [u8]);

impl<'a> fmt::Display for HexDisplay<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            f.write_fmt(format_args!("{:02X}", byte))?;
        }
        Ok(())
    }
}
