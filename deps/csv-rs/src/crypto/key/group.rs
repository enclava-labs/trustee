// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

use openssl::{ec, nid};
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind, Result};

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
pub struct Group(u32);

impl Group {
    pub const SM2_256: Group = Group(3u32.to_le());

    pub fn size(self) -> Result<usize> {
        Ok(match self {
            Group::SM2_256 => 32,
            _ => return Err(ErrorKind::InvalidInput.into()),
        })
    }
}

impl TryFrom<Group> for nid::Nid {
    type Error = Error;
    fn try_from(value: Group) -> Result<Self> {
        Ok(match value {
            Group::SM2_256 => nid::Nid::SM2,
            _ => return Err(ErrorKind::InvalidInput.into()),
        })
    }
}

impl TryFrom<nid::Nid> for Group {
    type Error = Error;

    fn try_from(value: nid::Nid) -> Result<Self> {
        Ok(match value {
            nid::Nid::SM2 => Group::SM2_256,
            _ => return Err(ErrorKind::InvalidInput.into()),
        })
    }
}

impl TryFrom<Group> for ec::EcGroup {
    type Error = Error;

    fn try_from(value: Group) -> Result<Self> {
        Ok(ec::EcGroup::from_curve_name(value.try_into()?)?)
    }
}

impl TryFrom<&ec::EcGroupRef> for Group {
    type Error = Error;

    fn try_from(value: &ec::EcGroupRef) -> Result<Self> {
        value
            .curve_name()
            .ok_or(ErrorKind::InvalidInput)?
            .try_into()
    }
}
