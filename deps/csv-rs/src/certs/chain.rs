// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Utilities for operating on entire certificate chains.

use super::*;
use crate::certs::{ca, csv};

use serde::{Deserialize, Serialize};

/// A complete certificate chain.
#[repr(C)]
#[derive(Deserialize, Serialize)]
pub struct Chain {
    /// The Certificate Authority chain
    pub ca: ca::Chain,

    /// The CSV platform chain.
    pub csv: csv::Chain,
}

impl codicon::Decoder<()> for Chain {
    type Error = Error;

    fn decode(mut reader: impl Read, _: ()) -> Result<Self> {
        let csv = csv::Chain::decode(&mut reader, ())?;
        let ca = ca::Chain::decode(&mut reader, ())?;
        Ok(Self { ca, csv })
    }
}

impl codicon::Encoder<()> for Chain {
    type Error = Error;

    fn encode(&self, mut writer: impl Write, _: ()) -> Result<()> {
        self.csv.encode(&mut writer, ())?;
        self.ca.encode(&mut writer, ())
    }
}

impl<'a> Verifiable for &'a Chain {
    type Output = &'a csv::Certificate;

    fn verify(self) -> Result<Self::Output> {
        let ask = self.ca.verify()?;
        (ask, &self.csv.cek).verify()?;
        self.csv.verify()
    }
}
