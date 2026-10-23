// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use crate::{
    certs::{csv::Certificate, Usage, Verifiable},
    crypto::{sig::ecdsa, PublicKey, Signature},
    util::*,
};

use log::*;
use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::io::Write;
use hex::encode;

/// A structure representing the body of an attestation report.
/// This is marked with `repr(C)` for C compatibility and can be serialized/deserialized.
#[repr(C)]
#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
pub struct Body {
    /// Version number of the attestation report format
    pub version: u32,
    /// Unique identifier of the hardware chip (16 bytes)
    pub chip_id: [u8; 16],
    /// User data value (64 bytes)
    #[serde(with = "serde_bytes")]
    pub user_data: [u8; 64],
    /// Measurement data (32 bytes)
    pub measure: [u8; 32],
    /// Reserved data (128 bytes)
    #[serde(with = "serde_bytes")]
    pub reserved: [u8; 128],
    /// Indicates the purpose/usage of the signature
    pub sig_usage: u32,
    /// Algorithm used for generating the signature
    pub sig_algo: u32,
}

impl Default for Body {
    /// Creates a default Body with all fields zero-initialized
    fn default() -> Self {
        Self {
            version: Default::default(),
            chip_id: Default::default(),
            user_data: [0u8;64],
            measure: Default::default(),
            reserved: [0u8;128],
            sig_usage: Default::default(),
            sig_algo: Default::default(),
        }
    }
}

impl Body {
    /// Prints each field of the `Body` struct in human-readable format
    pub fn print_fields(&self) {
        trace!("Version: {}", self.version);
        trace!("Chip ID: {}", String::from_utf8_lossy(&self.chip_id));
        trace!("User data: {}", encode(&self.user_data));
        trace!("Measure: {:?}", self.measure);
        trace!("Signature Usage: {}", self.sig_usage);
        trace!("Signature Algorithm: {}", self.sig_algo);
    }
}

/// This structure contains both the report body and its cryptographic signature.
#[repr(C)]
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AttestationReport {
    /// The main content of the attestation report
    pub body: Body,
    /// ECDSA signature verifying the report authenticity
    pub sig: ecdsa::Signature,
}

impl AttestationReport {
    /// Prints both the body and signature fields of the attestation report
    pub fn print_report(&self) {
        self.body.print_fields();
        self.sig.print_fields();
    }
}

impl Default for AttestationReport {
    /// Creates a default AttestationReport with empty body and signature
    fn default() -> Self {
        Self {
            body: Default::default(),
            sig: Default::default(),
        }
    }
}

/// Response structure containing the attestation report from the dcu devices
#[repr(C)]
#[derive(Debug, serde::Deserialize)]
pub struct AttestationResponse {
    /// Size of the contained report in bytes
    pub report_size: u32,
    /// Reserved space for future extensions (28 bytes)
    pub reserved: [u8; 28],
    /// The actual attestation report data
    pub report: AttestationReport,
}

impl Default for AttestationResponse {
    /// Creates a default response with zero-sized report and empty fields
    fn default() -> Self {
        Self {
            report_size: 0,
            reserved: [0u8; 28],
            report: AttestationReport::default(),
        }
    }
}

impl AttestationResponse {
    /// Safely constructs a mutable reference from a raw C pointer
    /// # Safety
    /// Caller must ensure the pointer is valid and properly aligned
    pub unsafe fn from_raw<'a>(ptr: *mut c_void) -> Option<&'a mut Self> {
        if ptr.is_null() {
            None
        } else {
            Some(&mut *(ptr as *mut Self))
        }
    }
}

/// Implementation of encoding functionality for AttestationReport
impl codicon::Encoder<crate::Body> for AttestationReport {
    type Error = std::io::Error;

    /// Encodes the report body into the writer
    fn encode(&self, mut writer: impl Write, _: crate::Body) -> Result<(), std::io::Error> {
        writer.save(&self.body)
    }
}

impl TryFrom<&AttestationReport> for Signature {
    type Error = std::io::Error;

    /// Attempts to convert an AttestationReport into a Signature structure
    #[inline]
    fn try_from(value: &AttestationReport) -> Result<Self, std::io::Error> {
        let sig = Vec::try_from(&value.sig)?;
        Ok(Self {
            sig,
            id: None,
            usage: Usage::CEK,
            algo: None,
        })
    }
}

/// Implementation of verification for a certificate and attestation report pair
impl Verifiable for (&Certificate, &AttestationReport) {
    type Output = ();

    /// Verifies the attestation report using the provided certificate
    fn verify(self) -> Result<(), std::io::Error> {
        let key: PublicKey = self.0.try_into()?;
        let sig: Signature = self.1.try_into()?;
        key.verify(
            self.1,
            &self.0.body.data.user_id[..self.0.body.data.uid_size as usize],
            &sig,
        )
    }
}
