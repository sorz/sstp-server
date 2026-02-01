use anyhow::{Context, bail};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::Sha256;
use std::{cmp, os::raw::c_int};
use zeroize::Zeroize;

use crate::sys;

const CMAC_SEED: &str = "SSTP inner method derived CMK";

pub(crate) fn extract_cmk() -> anyhow::Result<CompoundMacKey> {
    let mppe_key = if !unsafe { sys::mppe_keys_isset() } {
        eprintln!("SSTP:INFO:mppe keys is unset");
        Default::default()
    } else {
        MppeKeys::try_get().context("retrive mppe keys")?
    };
    mppe_key.generate_cmk().context("generate cmk")
}

pub(crate) struct CompoundMacKey {
    pub(crate) sha1: [u8; 20],
    pub(crate) sha256: [u8; 32],
}

#[derive(Default)]
struct MppeKeys {
    recv_key: Vec<u8>,
    send_key: Vec<u8>,
}

// HMAC (key, seed | output length (u16 le) | 0x01)
macro_rules! get_cmk {
    ($hash:ident, $size:expr, $hlak:expr) => {
        Hmac::<$hash>::new_from_slice($hlak)?
            .chain_update(CMAC_SEED.as_bytes())
            .chain_update($size.to_le_bytes())
            .chain_update([1])
            .finalize()
            .into_bytes()
    };
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
        // Truncate/pad to 32 bytes
        let mut hlak = [0u8; 32];
        let full_len = cmp::min(hlak.len(), self.recv_key.len() + self.send_key.len());
        let recv_len = cmp::min(hlak.len(), self.recv_key.len());
        let send_len = full_len.saturating_sub(recv_len);
        hlak[..recv_len].copy_from_slice(&self.recv_key[..recv_len]);
        hlak[recv_len..full_len].copy_from_slice(&self.send_key[..send_len]);

        let cmk_sha1 = get_cmk!(Sha1, 20u16, &hlak);
        let cmk_sha256 = get_cmk!(Sha256, 32u16, &hlak);
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
