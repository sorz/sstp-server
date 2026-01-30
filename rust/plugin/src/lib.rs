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
mod sys;

use anyhow::{Context, bail};
use digest::Digest;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use std::{
    cmp, fmt,
    os::raw::{c_int, c_void},
    ptr,
};
use zeroize::Zeroize;

const CMAC_SEED: &str = "SSTP inner method derived CMK";

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
}

/// Callback by pppd when authentication is done
unsafe extern "C" fn notify_auth_up(_ctx: *mut c_void, _arg: c_int) {
    let cmk = match extract_cmk() {
        Ok(k) => k,
        Err(e) => {
            eprintln!("SSTP:ERROR:failed to extract cmk {}", e);
            return;
        }
    };
    eprintln!("SSTP:CMK:SHA-256:{}", HexDisplay(&cmk.sha256));
    eprintln!("SSTP:CMK:SHA-1:{}", HexDisplay(&cmk.sha1));
}

fn extract_cmk() -> anyhow::Result<CompoundMacKey> {
    let mppe_key = if !unsafe { sys::mppe_keys_isset() } {
        eprintln!("SSTP:INFO:mppe keys is unset");
        Default::default()
    } else {
        MppeKeys::try_get().context("retrive mppe keys")?
    };
    mppe_key.generate_cmk().context("generate cmk")
}

struct CompoundMacKey {
    sha1: [u8; 20],
    sha256: [u8; 32],
}

#[derive(Default)]
struct MppeKeys {
    recv_key: Vec<u8>,
    send_key: Vec<u8>,
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

impl MppeKeys {
    fn try_get() -> anyhow::Result<Self> {
        Ok(Self {
            recv_key: mppe_get_recv_key()?,
            send_key: mppe_get_send_key()?,
        })
    }
    fn generate_cmk(&self) -> anyhow::Result<CompoundMacKey> {
        // Higher-Layer Authentication Key (HLAK)
        // SSTP Server HLAK = MasterReceiveKey | MasterSendKe
        let mut hlak = [0u8; 32];
        let recv_len = cmp::min(hlak.len(), self.recv_key.len());
        let send_len = hlak.len().saturating_sub(recv_len);
        hlak[..recv_len].copy_from_slice(&self.recv_key[..recv_len]);
        hlak[recv_len..].copy_from_slice(&self.send_key[..send_len]);

        // HMAC-SHA1 (key, seed | output length | 0x01)
        let cmk_sha1 = Hmac::<Sha1>::new_from_slice(&hlak)?
            .chain_update(CMAC_SEED.as_bytes())
            .chain_update(Sha1::output_size().to_le_bytes())
            .chain_update([0x01])
            .finalize()
            .into_bytes();

        // HMAC-SHA256 (key, seed | output length | 0x01)
        let cmk_sha256 = Hmac::<Sha256>::new_from_slice(&hlak)?
            .chain_update(CMAC_SEED.as_bytes())
            .chain_update(Sha256::output_size().to_le_bytes())
            .chain_update([0x01])
            .finalize()
            .into_bytes();

        hlak.zeroize();
        Ok(CompoundMacKey {
            sha1: cmk_sha1.into(),
            sha256: cmk_sha256.into(),
        })
    }
}

impl Drop for MppeKeys {
    fn drop(&mut self) {
        self.recv_key.zeroize();
        self.send_key.zeroize();
    }
}

macro_rules! impl_mppe_get_key {
    ($fn_name:ident) => {
        fn $fn_name() -> anyhow::Result<Vec<u8>> {
            let mut buf = vec![0u8; sys::MPPE_MAX_KEY_LEN as usize];
            let len = unsafe { sys::$fn_name(buf.as_mut_slice().as_mut_ptr(), buf.len() as c_int) };
            if len <= 0 || len > buf.len() as c_int {
                bail!("failed to get mppe key");
            }
            buf.resize(len as usize, 0);
            Ok(buf)
        }
    };
}

impl_mppe_get_key!(mppe_get_recv_key);
impl_mppe_get_key!(mppe_get_send_key);
