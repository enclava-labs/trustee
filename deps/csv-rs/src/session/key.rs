// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::*;

use std::{
    ops::{Deref, DerefMut},
    ptr::write_volatile,
};

use openssl::*;

#[repr(transparent)]
pub struct Key(Vec<u8>);

impl Drop for Key {
    fn drop(&mut self) {
        for b in self.0.iter_mut() {
            unsafe {
                write_volatile(b as *mut u8, 0u8);
            }
        }
    }
}

impl Deref for Key {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl DerefMut for Key {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl codicon::Encoder<()> for Key {
    type Error = Error;
    fn encode(&self, mut writer: impl Write, _: ()) -> std::io::Result<()> {
        writer.write_all(&self.0)?;

        Ok(())
    }
}

impl Key {
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }

    pub fn zeroed(size: usize) -> Self {
        Key(vec![0u8; size])
    }

    pub fn random(size: usize) -> Result<Self> {
        let mut key = Key::zeroed(size);
        rand::rand_bytes(&mut key)?;
        Ok(key)
    }

    pub fn get_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Key {
    // NIST 800-108 5.1 - KDF in Counter Mode
    pub fn derive(&self, size: usize, ctx: &[u8], label: &str) -> Result<Key> {
        let mut prepend: Vec<u8> = Vec::new();
        let cat_symbol: u8 = 0;
        prepend.extend_from_slice(self.0.as_slice());
        for c in label.bytes() {
            prepend.push(c);
        }
        prepend.push(cat_symbol);
        prepend.extend_from_slice(ctx);
        let hbytes = 32; //sha
        let mut out = Key::zeroed((size + hbytes - 1) / hbytes * hbytes);
        let buf = &mut out[..];

        crate::crypto::sm::SM2::ecdh_kdf_x9_63(&mut buf[..], &prepend[..])?;
        prepend.extend_from_slice(buf);
        crate::crypto::sm::SM2::ecdh_kdf_x9_63(&mut buf[..], &prepend[..])?;

        out.0.truncate(size);
        Ok(out)
    }

    pub fn mac(&self, data: &[u8]) -> Result<[u8; 32]> {
        let mut mac = [0u8; 32];
        let key = pkey::PKey::hmac(self)?;
        let mut sig = sign::Signer::new(hash::MessageDigest::sm3(), &key)?;

        sig.update(data)?;
        sig.sign(&mut mac)?;
        Ok(mac)
    }
}

#[cfg(test)]
#[test]
fn derive() {
    let master = Key::zeroed(16)
        .derive(16, &[0u8; 16], "csv-master-secret")
        .unwrap();
    assert_eq!(
        master.0,
        vec![
            0x19, 0xE8, 0xD5, 0x50, 0xE3, 0xA7, 0x99, 0xB2, 0x91, 0x7B, 0xC5, 0x91, 0x46, 0xAA,
            0xAD, 0xAE,
        ]
    )
}

#[cfg(test)]
#[test]
fn mac() {
    let mac = Key::zeroed(16).mac(&[0u8; 4]).unwrap();
    assert_eq!(
        mac,
        [
            0x5F, 0x08, 0xF1, 0x9A, 0x7D, 0x6D, 0x8A, 0xCE, 0xB7, 0xA6, 0x95, 0x5B, 0x15, 0x33,
            0x17, 0x3C, 0xDD, 0x34, 0x20, 0x39, 0xD4, 0xF7, 0x6A, 0x11, 0x7F, 0xE1, 0xAA, 0xAA,
            0xB7, 0xB2, 0x7F, 0xEC
        ]
    )
}
