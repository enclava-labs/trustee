// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Interfaces for GuoMi that is not supported on rust-openssl.

use crate::crypto::key::{ecc, group};
use libc::*;
use openssl::nid;
use openssl_sys::*;
use std::{
    io::{Error, ErrorKind, Result},
    ptr,
};

#[cfg(ossl111)]
pub const EVP_PKEY_CTRL_SET1_ID: c_int = EVP_PKEY_ALG_CTRL + 11;

const ECDH_KDF_MAX: size_t = 1 << 30;

extern "C" {
    #[cfg(ossl111)]
    pub fn EVP_PKEY_set_alias_type(pkey: *mut EVP_PKEY, ttype: c_int) -> c_int;

    pub fn EVP_MD_CTX_set_pkey_ctx(ctx: *mut EVP_MD_CTX, sctx: *mut EVP_PKEY_CTX) -> c_int;

    #[cfg(ossl300)]
    pub fn EVP_PKEY_CTX_set1_id(ctx: *mut EVP_PKEY_CTX, id: *const c_void, len: c_int) -> c_int;

    /// openssl libc functions
    pub fn EC_GROUP_get0_order(group: *const EC_GROUP) -> *const BIGNUM;
    pub fn BN_CTX_start(ctx: *mut BN_CTX) -> c_void;
    pub fn BN_CTX_get(ctx: *mut BN_CTX) -> *mut BIGNUM;
    pub fn BN_priv_rand_range(r: *mut BIGNUM, range: *const BIGNUM) -> c_int;
    pub fn BN_bn2binpad(a: *const BIGNUM, to: *mut c_uchar, tolen: c_int) -> c_int;
}

#[cfg(ossl111)]
#[allow(non_snake_case)]
pub unsafe fn EVP_PKEY_CTX_set1_id(
    ctx: *mut EVP_PKEY_CTX,
    id: *const c_void,
    id_len: c_int,
) -> c_int {
    EVP_PKEY_CTX_ctrl(
        ctx,
        -1,
        -1,
        EVP_PKEY_CTRL_SET1_ID,
        id_len,
        id as *mut c_void,
    )
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct SM2 {}

impl SM2 {
    /// use SM2 algorithm to verify a msg's signature
    pub fn verify(
        ecc_pubkey: ecc::PubKey,
        sig: &[u8],
        id: &Vec<u8>,
        msg: &Vec<u8>,
    ) -> Result<bool> {
        let mut verify_result = false;
        let pubkey_size = ecc_pubkey.g.size()?;

        unsafe {
            let eckey = EC_KEY_new_by_curve_name(NID_sm2);
            let pub_x = &ecc_pubkey.x[..pubkey_size]
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>();
            let pub_y = &ecc_pubkey.y[..pubkey_size]
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>();
            let bn_x = BN_bin2bn(
                pub_x.as_ptr() as *const c_uchar,
                pubkey_size as c_int,
                ptr::null_mut(),
            );
            let bn_y = BN_bin2bn(
                pub_y.as_ptr() as *const c_uchar,
                pubkey_size as c_int,
                ptr::null_mut(),
            );
            EC_KEY_set_public_key_affine_coordinates(eckey, bn_x, bn_y);
            let pkey = EVP_PKEY_new();
            if EVP_PKEY_assign(pkey, EVP_PKEY_SM2, eckey as *mut c_void) <= 0 {
                EVP_PKEY_free(pkey);
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "EVP_KEY_set1_EC_KEY failed",
                ));
            }

            #[cfg(ossl111)]
            EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

            let mctx: *mut EVP_MD_CTX = EVP_MD_CTX_new();
            let pctx = EVP_PKEY_CTX_new(pkey, ptr::null_mut());
            EVP_PKEY_CTX_set1_id(pctx, id.as_ptr() as *mut c_void, id.len() as c_int);
            EVP_MD_CTX_set_pkey_ctx(mctx, pctx);
            EVP_DigestVerifyInit(mctx, ptr::null_mut(), EVP_sm3(), ptr::null_mut(), pkey);
            EVP_DigestVerifyUpdate(mctx, msg.as_ptr() as *mut c_void, msg.len());
            if EVP_DigestVerifyFinal(mctx, sig.as_ptr(), sig.len()) == 1 {
                verify_result = true;
            }
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);
            EVP_MD_CTX_free(mctx);
        }
        Ok(verify_result)
    }

    pub fn generate(group: group::Group) -> Result<(ecc::PubKey, *mut EC_KEY)> {
        let value: nid::Nid = group.try_into()?;
        let mut qx: Vec<u8> = vec![0; 32];
        let mut qy: Vec<u8> = vec![0; 32];
        let eckey: *mut EC_KEY = unsafe { EC_KEY_new() };
        unsafe {
            let c = BN_CTX_new();
            if eckey.is_null() || c.is_null() {
                return Err(ErrorKind::InvalidData.into());
            }
            let x = BN_new();
            let y = BN_new();
            if x.is_null() || y.is_null() {
                return Err(ErrorKind::InvalidData.into());
            }
            let g: *mut EC_GROUP = EC_GROUP_new_by_curve_name(value.as_raw());
            if EC_KEY_set_group(eckey, g) == 0 {
                EC_KEY_free(eckey);
                return Err(ErrorKind::InvalidData.into());
            }

            if 0 == EC_KEY_generate_key(eckey) {
                EC_KEY_free(eckey);
                return Err(ErrorKind::InvalidData.into());
            }

            if 0 == EC_POINT_get_affine_coordinates(g, EC_KEY_get0_public_key(eckey), x, y, c)
                || BN_bn2binpad(x, qx.as_mut_ptr() as *mut c_uchar, 32) < 0
                || BN_bn2binpad(y, qy.as_mut_ptr() as *mut c_uchar, 32) < 0
            {
                return Err(ErrorKind::InvalidData.into());
            }
        }
        qx.reverse();
        qy.reverse();
        qx.resize(72, 0);
        qy.resize(72, 0);
        let pubkey = ecc::PubKey {
            g: group,
            x: qx.try_into().unwrap(),
            y: qy.try_into().unwrap(),
        };

        Ok((pubkey, eckey))
    }

    pub fn sign(pri_key: *mut EC_KEY, id: &Vec<u8>, data: &Vec<u8>) -> Result<Vec<u8>> {
        let r = unsafe {
            let pkey = EVP_PKEY_new();
            if pkey.is_null() {
                return Err(ErrorKind::InvalidData.into());
            }
            if EVP_PKEY_assign(pkey, EVP_PKEY_SM2, pri_key as *mut c_void) <= 0 {
                EVP_PKEY_free(pkey);
                return Err(Error::new(ErrorKind::InvalidData, "EVP_PKEY_assign failed"));
            }

            #[cfg(ossl111)]
            EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2);

            let mctx: *mut EVP_MD_CTX = EVP_MD_CTX_new();
            let pctx = EVP_PKEY_CTX_new(pkey, ptr::null_mut());
            EVP_PKEY_CTX_set1_id(pctx, id.as_ptr() as *mut c_void, id.len() as c_int);
            EVP_MD_CTX_set_pkey_ctx(mctx, pctx);

            let sig_len: *mut size_t = Box::into_raw(Box::new(0));
            EVP_DigestSignInit(mctx, ptr::null_mut(), EVP_sm3(), ptr::null_mut(), pkey);
            EVP_DigestSign(mctx, ptr::null_mut(), sig_len, data.as_ptr(), data.len());
            let mut sig = vec![0; *sig_len].into_boxed_slice();
            EVP_DigestSign(mctx, sig.as_mut_ptr(), sig_len, data.as_ptr(), data.len());
            EVP_MD_CTX_free(mctx);
            EVP_PKEY_CTX_free(pctx);
            EVP_PKEY_free(pkey);

            let mut result_vec = sig.to_vec();
            result_vec.truncate(*sig_len);
            result_vec
        };
        Ok(r)
    }

    /// KDF function of ecdh
    pub fn ecdh_kdf_x9_63(out: &mut [u8], input: &[u8]) -> Result<()> {
        let mut outlen = out.len();
        let mut buf = &mut out[..];
        let inlen = input.len();

        if outlen > ECDH_KDF_MAX || inlen > ECDH_KDF_MAX {
            return Err(ErrorKind::InvalidData.into());
        }
        unsafe {
            let md = EVP_sm3();
            let mctx = EVP_MD_CTX_new();
            if mctx.is_null() {
                return Err(ErrorKind::InvalidData.into());
            }
            let mdlen = EVP_MD_size(md);
            let mdlen = mdlen as usize;
            let mut counter: u32 = 1;
            while outlen > 0 {
                let counter_be = counter.to_be_bytes();
                if 0 == EVP_DigestInit_ex(mctx, md, ptr::null_mut()) {
                    return Err(ErrorKind::InvalidData.into());
                }
                if 0 == EVP_DigestUpdate(mctx, input.as_ptr() as *const c_void, inlen) {
                    return Err(ErrorKind::InvalidData.into());
                }
                if 0 == EVP_DigestUpdate(
                    mctx,
                    counter_be.as_ptr() as *const c_void,
                    counter_be.len(),
                ) {
                    return Err(ErrorKind::InvalidData.into());
                }
                if 0 == EVP_DigestUpdate(mctx, ptr::null_mut(), 0) {
                    return Err(ErrorKind::InvalidData.into());
                }
                if outlen >= mdlen {
                    if 0 == EVP_DigestFinal(mctx, buf.as_ptr() as *mut c_uchar, ptr::null_mut()) {
                        return Err(ErrorKind::InvalidData.into());
                    }
                    outlen -= mdlen;
                    if outlen == 0 {
                        break;
                    }
                    buf = &mut buf[mdlen..];
                } else {
                    let mtmp: Vec<u8> = vec![0; 64];
                    if 0 == EVP_DigestFinal(mctx, mtmp.as_ptr() as *mut c_uchar, ptr::null_mut()) {
                        return Err(ErrorKind::InvalidData.into());
                    }
                    buf.copy_from_slice(&mtmp[..outlen]);
                    break;
                }
                counter += 1;
            }

            EVP_MD_CTX_free(mctx);
        }
        Ok(())
    }

    /// use SM2 algorithm to encrypt data with pubKey
    pub fn encrypt(data: &[u8], pub_key: ecc::PubKey) -> Result<Vec<u8>> {
        let pubkey_size = pub_key.g.size()?;
        let mut ciphertext_buf: Vec<u8> = Vec::new();
        unsafe {
            let eckey = EC_KEY_new_by_curve_name(NID_sm2);
            let pub_x = &pub_key.x[..pubkey_size]
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>();
            let pub_y = &pub_key.y[..pubkey_size]
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>();
            let bn_x = BN_bin2bn(
                pub_x.as_ptr() as *const c_uchar,
                pubkey_size as c_int,
                ptr::null_mut(),
            );
            let bn_y = BN_bin2bn(
                pub_y.as_ptr() as *const c_uchar,
                pubkey_size as c_int,
                ptr::null_mut(),
            );
            EC_KEY_set_public_key_affine_coordinates(eckey, bn_x, bn_y);

            let c3_size: size_t = 32;
            let group = EC_KEY_get0_group(eckey);
            let order = EC_GROUP_get0_order(group);
            let pub_key = EC_KEY_get0_public_key(eckey);
            let field_size: size_t = 32;

            let k_g = EC_POINT_new(group);
            let k_p = EC_POINT_new(group);
            let ctx = BN_CTX_new();
            if k_g.is_null() || k_p.is_null() || ctx.is_null() {
                return Err(ErrorKind::InvalidData.into());
            }

            BN_CTX_start(ctx);
            let k = BN_CTX_get(ctx);
            let x1 = BN_CTX_get(ctx);
            let x2 = BN_CTX_get(ctx);
            let y1 = BN_CTX_get(ctx);
            let y2 = BN_CTX_get(ctx);

            if y2.is_null() {
                return Err(ErrorKind::InvalidData.into());
            }

            let mut x2_u8: Vec<u8> = vec![0; 32];
            let mut y2_u8: Vec<u8> = vec![0; 32];
            let mut c3: Vec<u8> = vec![0; c3_size];

            if BN_priv_rand_range(k, order) == 0 {
                return Err(ErrorKind::InvalidData.into());
            }

            if EC_POINT_mul(group, k_g, k, ptr::null_mut(), ptr::null_mut(), ctx) == 0
                || 0 == EC_POINT_get_affine_coordinates(group, k_g, x1, y1, ctx)
                || 0 == EC_POINT_mul(group, k_p, ptr::null_mut(), pub_key, k, ctx)
                || 0 == EC_POINT_get_affine_coordinates(group, k_p, x2, y2, ctx)
            {
                return Err(ErrorKind::InvalidData.into());
            }

            if BN_bn2binpad(x2, x2_u8.as_mut_ptr() as *mut c_uchar, field_size as i32) < 0
                || BN_bn2binpad(y2, y2_u8.as_mut_ptr() as *mut c_uchar, field_size as i32) < 0
            {
                return Err(ErrorKind::InvalidData.into());
            }

            let mut msg_mask: Vec<u8> = vec![0; data.len()];
            let mut x2y2: Vec<u8> = Vec::new();
            x2y2.extend_from_slice(&x2_u8[..]);
            x2y2.extend_from_slice(&y2_u8[..]);
            /* X9.63 with no salt happens to match the KDF used in SM2 */
            SM2::ecdh_kdf_x9_63(&mut msg_mask[..], &x2y2[..])?;
            for i in 0..data.len() {
                msg_mask[i] ^= data[i];
            }

            let md_ctx: *mut EVP_MD_CTX = EVP_MD_CTX_new();
            if md_ctx.is_null() {
                return Err(ErrorKind::InvalidData.into());
            }

            if EVP_DigestInit(md_ctx, EVP_sm3()) == 0
                || EVP_DigestUpdate(md_ctx, x2_u8.as_ptr() as *const c_void, field_size) == 0
                || EVP_DigestUpdate(md_ctx, data.as_ptr() as *const c_void, data.len()) == 0
                || EVP_DigestUpdate(md_ctx, y2_u8.as_ptr() as *const c_void, field_size) == 0
                || EVP_DigestFinal(md_ctx, c3.as_mut_ptr() as *mut c_uchar, ptr::null_mut()) == 0
            {
                return Err(ErrorKind::InvalidData.into());
            }

            let mut x1_u8: Vec<u8> = vec![0; 32];
            let mut y1_u8: Vec<u8> = vec![0; 32];

            BN_bn2bin(x1, x1_u8.as_mut_ptr());
            BN_bn2bin(y1, y1_u8.as_mut_ptr());

            // ciphertext_len = 1 + 32 + 32 + msg.len() + c3_size;
            ciphertext_buf.push(4);
            ciphertext_buf.extend_from_slice(&x1_u8[..]);
            ciphertext_buf.extend_from_slice(&y1_u8[..]);
            ciphertext_buf.extend_from_slice(&c3[..]);
            ciphertext_buf.extend_from_slice(&msg_mask[..]); //C2
        };
        Ok(ciphertext_buf)
    }
}
