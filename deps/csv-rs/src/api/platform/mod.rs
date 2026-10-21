// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Modules for interfacing with CSV Firmware
//! Rust-fridenly API wrappers to communicate the the FFI functions.

/// A handle to the CSV platform.
mod ioctl;
pub use ioctl::*;

mod types;
pub use types::*;

use crate::{certs::csv::*, error::*, Build, Version};
use std::{
    fs::{File, OpenOptions},
    mem::MaybeUninit,
    os::unix::io::{AsRawFd, RawFd},
};

/// The CPU-unique identifier for the platform.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identifier(pub Vec<u8>);

impl From<Identifier> for Vec<u8> {
    fn from(id: Identifier) -> Vec<u8> {
        id.0
    }
}

impl std::fmt::Display for Identifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for b in self.0.iter() {
            write!(f, "{b:02X}")?;
        }

        Ok(())
    }
}

pub struct Firmware(File);

impl Firmware {
    /// Create a handle to the CSV platform.
    pub fn open() -> std::io::Result<Firmware> {
        Ok(Firmware(
            OpenOptions::new().read(true).write(true).open("/dev/sev")?,
        ))
    }

    /// Reset the platform persistent state.
    pub fn platform_reset(&mut self) -> Result<(), Indeterminate<Error>> {
        PLATFORM_RESET.ioctl(&mut self.0, &mut Command::from(&PlatformReset))?;
        Ok(())
    }

    /// Query the platform status.
    pub fn platform_status(&mut self) -> Result<Status, Indeterminate<Error>> {
        let mut info: PlatformStatus = Default::default();
        PLATFORM_STATUS.ioctl(&mut self.0, &mut Command::from_mut(&mut info))?;

        Ok(Status {
            build: Build {
                version: Version {
                    major: info.version.major,
                    minor: info.version.minor,
                },
                build: info.build,
            },
            guests: info.guest_count,
            flags: info.flags,
            state: match info.state {
                0 => State::Uninitialized,
                1 => State::Initialized,
                2 => State::Working,
                _ => return Err(Indeterminate::Unknown),
            },
        })
    }

    /// Generate a new Platform Encryption Key (PEK).
    pub fn pek_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PEK_GEN.ioctl(&mut self.0, &mut Command::from(&PekGen))?;
        Ok(())
    }

    /// Request a signature for the PEK.
    pub fn pek_csr(&mut self) -> Result<Certificate, Indeterminate<Error>> {
        let mut pek = MaybeUninit::uninit();
        let mut csr = PekCsr::new(&mut pek);
        PEK_CSR.ioctl(&mut self.0, &mut Command::from_mut(&mut csr))?;

        Ok(unsafe { pek.assume_init() })
    }

    /// Generate a new Platform Diffie-Hellman (PDH) key pair.
    pub fn pdh_generate(&mut self) -> Result<(), Indeterminate<Error>> {
        PDH_GEN.ioctl(&mut self.0, &mut Command::from(&PdhGen))?;
        Ok(())
    }

    /// Export the CSV certificate chain.
    pub fn pdh_cert_export(&mut self) -> Result<Chain, Indeterminate<Error>> {
        let mut chain: MaybeUninit<[Certificate; 3]> = MaybeUninit::uninit();
        let mut pdh = MaybeUninit::uninit();

        let mut pdh_cert_export = PdhCertExport::new(&mut pdh, &mut chain);
        PDH_CERT_EXPORT.ioctl(&mut self.0, &mut Command::from_mut(&mut pdh_cert_export))?;

        Ok(Chain {
            pdh: unsafe { pdh.assume_init() },
            pek: unsafe { chain.assume_init() }[0],
            oca: unsafe { chain.assume_init() }[1],
            cek: unsafe { chain.assume_init() }[2],
        })
    }

    /// Take ownership of the CSV platform.
    pub fn pek_cert_import(
        &mut self,
        pek: &Certificate,
        oca: &Certificate,
    ) -> Result<(), Indeterminate<Error>> {
        let pek_cert_import = PekCertImport::new(pek, oca);
        PEK_CERT_IMPORT.ioctl(&mut self.0, &mut Command::from(&pek_cert_import))?;
        Ok(())
    }

    /// Get the unique CPU identifier.
    ///
    /// This is especially helpful for sending HYGON an HTTP request to fetch
    /// the signed CEK certificate.
    pub fn get_identifier(&mut self) -> Result<Identifier, Indeterminate<Error>> {
        let mut bytes = [0u8; 64];
        let mut id = GetId::new(&mut bytes);

        GET_ID.ioctl(&mut self.0, &mut Command::from_mut(&mut id))?;

        Ok(Identifier(id.as_slice().to_vec()))
    }
}

impl AsRawFd for Firmware {
    fn as_raw_fd(&self) -> RawFd {
        self.0.as_raw_fd()
    }
}
