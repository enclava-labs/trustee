// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

use crate::util::*;
use log::*;
use openssl::{bn, ecdsa};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::{Error, Result};

/// The Raw format of ecdsa signature.
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
pub struct Signature {
    #[serde(with = "BigArray")]
    pub r: [u8; 72],
    #[serde(with = "BigArray")]
    pub s: [u8; 72],
}

impl From<ecdsa::EcdsaSig> for Signature {
    #[inline]
    fn from(value: ecdsa::EcdsaSig) -> Self {
        Signature {
            r: value.r().as_le_bytes(),
            s: value.s().as_le_bytes(),
        }
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    #[inline]
    fn try_from(value: &[u8]) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::from_der(value)?.into())
    }
}

impl TryFrom<&Signature> for ecdsa::EcdsaSig {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        let r = bn::BigNum::from_le(&value.r)?;
        let s = bn::BigNum::from_le(&value.s)?;
        Ok(ecdsa::EcdsaSig::from_private_components(r, s)?)
    }
}

impl TryFrom<&Signature> for Vec<u8> {
    type Error = Error;

    #[inline]
    fn try_from(value: &Signature) -> Result<Self> {
        Ok(ecdsa::EcdsaSig::try_from(value)?.to_der()?)
    }
}

impl Default for Signature {
    fn default() -> Self {
        Self {
            r: [0u8; 72],
            s: [0u8; 72],
        }
    }
}
impl Signature {
    pub fn print_fields(&self) {
        debug!("r: {:?}", self.r);
        debug!("s: {:?}", self.s);
    }
}
