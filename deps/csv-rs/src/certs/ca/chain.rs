// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! For operating on Certificate Authority chains.

use super::*;
use crate::certs::{ca::cert::Certificate, Usage};

use serde::{Deserialize, Serialize};

/// A complete Certificate Authority chain.
#[repr(C)]
#[derive(Deserialize, Serialize)]
pub struct Chain {
    /// The HYGON Sighing Key certificate.
    pub hsk: Certificate,

    /// The HYGON Root Key certificate.
    pub hrk: Certificate,
}

impl codicon::Decoder<()> for Chain {
    type Error = Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let hsk = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&hsk)? != Usage::HSK {
            return Err(ErrorKind::InvalidInput.into());
        }

        let hrk: Certificate = Certificate::decode(&mut reader, ())?;
        if Usage::try_from(&hrk)? != Usage::HRK {
            return Err(ErrorKind::InvalidInput.into());
        }

        Ok(Self { hsk, hrk })
    }
}

impl codicon::Encoder<()> for Chain {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> Result<()> {
        self.hsk.encode(&mut writer, crate::Body)?;
        self.hrk.encode(&mut writer, crate::Body)
    }
}

impl<'a> Verifiable for &'a Chain {
    type Output = &'a Certificate;

    fn verify(self) -> Result<Self::Output> {
        (&self.hrk, &self.hrk).verify()?;
        (&self.hrk, &self.hsk).verify()?;
        Ok(&self.hsk)
    }
}
