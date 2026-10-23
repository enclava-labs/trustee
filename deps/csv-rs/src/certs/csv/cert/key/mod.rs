// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Operations that can be done on a CSV certificate.

use super::*;
use crate::crypto::{key::group, sm, PrivateKey};

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Copy, Clone, Deserialize, Serialize)]
pub struct PubKey {
    pub usage: Usage,
    pub algo: Algorithm,
    pub key: ecc::PubKey,
}

impl PubKey {
    pub fn generate(usage: Usage, id: Option<[u8; 16]>) -> Result<(PubKey, PrivateKey<Usage>)> {
        let algo = Algorithm::try_from(usage)?;

        let (key, prv) = sm::SM2::generate(group::Group::SM2_256)?;

        Ok((
            Self { usage, algo, key },
            PrivateKey {
                usage,
                key: prv,
                id,
                hash: algo.try_into()?,
            },
        ))
    }
}
