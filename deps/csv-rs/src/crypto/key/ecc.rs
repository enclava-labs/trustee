// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Interfaces for ecc keys.

use crate::{crypto::key::group::Group, util::*};
use openssl::{bn, ec, pkey};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::io::{Error, Result};

/// The Raw format of ecc pubkey.
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
pub struct PubKey {
    pub g: Group,
    #[serde(with = "BigArray")]
    pub x: [u8; 72],
    #[serde(with = "BigArray")]
    pub y: [u8; 72],
}

impl TryFrom<&PubKey> for ec::EcKey<pkey::Public> {
    type Error = Error;

    fn try_from(value: &PubKey) -> Result<Self> {
        let s = value.g.size()?;
        Ok(ec::EcKey::from_public_key_affine_coordinates(
            &*ec::EcGroup::try_from(value.g)?,
            &*bn::BigNum::from_le(&value.x[..s])?,
            &*bn::BigNum::from_le(&value.y[..s])?,
        )?)
    }
}

impl TryFrom<&ec::EcKey<pkey::Private>> for PubKey {
    type Error = Error;

    fn try_from(value: &ec::EcKey<pkey::Private>) -> Result<Self> {
        let g = value.group();
        let mut c = bn::BigNumContext::new()?;
        let mut x = bn::BigNum::new()?;
        let mut y = bn::BigNum::new()?;

        value
            .public_key()
            .affine_coordinates_gfp(g, &mut x, &mut y, &mut c)?;
        Ok(Self {
            g: Group::try_from(g)?,
            x: x.as_le_bytes(),
            y: y.as_le_bytes(),
        })
    }
}
