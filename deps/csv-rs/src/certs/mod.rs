// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Everything needed for working with HYGON CSV certificate chains.

pub mod builtin;
pub mod ca;
mod chain;
pub mod csv;

use serde::{Deserialize, Serialize};
use std::{
    convert::*,
    io::{Error, ErrorKind, Read, Result, Write},
};

pub use chain::Chain;

use openssl::hash;

/// An interface for types that may containe entities
/// such as signatures that must be verified.
pub trait Verifiable {
    /// An output type for successful verification.
    type Output;

    /// Self-verifies signatures.
    fn verify(self) -> Result<Self::Output>;
}

/// An interface for types that can sign another type (i.e., a certificate).
pub trait Signer<T> {
    /// The now-signed type.
    type Output;

    /// Signs the target.
    fn sign(&self, target: &mut T, uid: String) -> Result<Self::Output>;
}

/// Denotes a certificate's usage.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage(u32);

impl Usage {
    /// HYGON Root Key.
    pub const HRK: Usage = Usage(0x0000u32.to_le());

    /// HYGON Signing key.
    pub const HSK: Usage = Usage(0x0013u32.to_le());

    /// Owner Certificate Authority.
    pub const OCA: Usage = Usage(0x1001u32.to_le());

    /// Platform Endorsement Key.
    pub const PEK: Usage = Usage(0x1002u32.to_le());

    /// Platform Diffie-Hellman.
    pub const PDH: Usage = Usage(0x1003u32.to_le());

    /// Chip Endorsement Key.
    pub const CEK: Usage = Usage(0x1004u32.to_le());

    const INV: Usage = Usage(0x1000u32.to_le());
}

impl Default for Usage {
    fn default() -> Self {
        Usage(0)
    }
}

impl From<u32> for Usage {
    fn from(value: u32) -> Self {
        Self(value.to_le())
    }
}

impl TryFrom<Usage> for String {
    type Error = Error;

    fn try_from(value: Usage) -> Result<Self> {
        match value {
            Usage::HRK => Ok(String::from("HYGON-SSD-HRK")),
            Usage::HSK => Ok(String::from("HYGON-SSD-HSK")),
            Usage::OCA => Ok(String::from("HYGON-SSD-OCA")),
            Usage::PEK => Ok(String::from("HYGON-SSD-PEK")),
            Usage::PDH => Ok(String::from("HYGON-SSD-PDH")),
            Usage::CEK => Ok(String::from("HYGON-SSD-CEK")),

            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

impl TryFrom<Usage> for Algorithm {
    type Error = Error;

    fn try_from(value: Usage) -> Result<Self> {
        match value {
            Usage::PDH => Ok(Algorithm::SM2_DH),
            Usage::HRK | Usage::HSK | Usage::OCA | Usage::PEK | Usage::CEK => Ok(Algorithm::SM2_SA),

            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Algorithm(u32);

impl Algorithm {
    pub const SM2_SA: Algorithm = Algorithm(0x0004u32.to_le());
    pub const SM2_DH: Algorithm = Algorithm(0x0005u32.to_le());
    pub const NONE: Algorithm = Algorithm(0x0000u32.to_le());
}

impl Default for Algorithm {
    fn default() -> Self {
        Algorithm(0)
    }
}

impl From<u32> for Algorithm {
    fn from(value: u32) -> Self {
        Self(value.to_le())
    }
}

impl TryFrom<Algorithm> for hash::MessageDigest {
    type Error = Error;

    fn try_from(value: Algorithm) -> Result<Self> {
        match value {
            Algorithm::SM2_SA | Algorithm::SM2_DH => Ok(hash::MessageDigest::sm3()),

            _ => Err(ErrorKind::InvalidInput.into()),
        }
    }
}
