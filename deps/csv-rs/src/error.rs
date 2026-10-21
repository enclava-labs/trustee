// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use openssl::error::ErrorStack;
use std::{
    convert::From,
    error,
    fmt::{Debug, Display},
    io,
};

/// Error conditions returned by the CSV platform or by layers above it
/// (i.e., the Linux kernel).
///
/// These error conditions are documented in the HYGON CSV API spec, but
/// their documentation has been copied here for completeness.
#[derive(Debug)]
#[repr(u32)]
pub enum Error {
    /// Something went wrong when communicating with
    /// kernel or CSV platform
    IoError(io::Error),

    /// The platform state is invalid for this command.
    InvalidPlatformState, // 0x0001

    /// The guest state is invalid for this command.
    InvalidGuestState, // 0x0002

    /// The platform configuration is invalid.
    InvalidConfig, // 0x0003

    /// A memory buffer is too small.
    InvalidLen, // 0x0004

    /// The platform is already owned.
    AlreadyOwned, // 0x0005

    /// The certificate is invalid.
    InvalidCertificate, // 0x0006

    /// Request is not allowed by guest policy.
    PolicyFailure, // 0x0007

    /// The guest is inactive.
    Inactive, // 0x0008

    /// The address provided is invalid.
    InvalidAddress, // 0x0009

    /// The provided signature is invalid.
    BadSignature, // 0x000A

    /// The provided measurement is invalid.
    BadMeasurement, // 0x000B

    /// The ASID is already owned.
    AsidOwned, // 0x000C

    /// The ASID is invalid.
    InvalidAsid, // 0x000D

    /// WBINVD instruction required.
    WbinvdRequired, // 0x000E

    /// `DF_FLUSH` invocation required.
    DfFlushRequired, // 0x000F

    /// The guest handle is invalid.
    InvalidGuest, // 0x0010

    /// The command issued is invalid.
    InvalidCommand, // 0x0011

    /// The guest is active.
    Active, // 0x0012

    /// A hardware condition has occurred affecting the platform. It is safe
    /// to re-allocate parameter buffers.
    HardwarePlatform, // 0x0013

    /// A hardware condition has occurred affecting the platform. Re-allocating
    /// parameter buffers is not safe.
    HardwareUnsafe, // 0x0014

    /// Feature is unsupported.
    Unsupported, // 0x0015

    /// A given parameter is invalid.
    InvalidParam, // 0x0016

    /// The CSV firmware has run out of a resource required to carry out the
    /// command.
    ResourceLimit, // 0x0017

    /// The CSV platform observed a failed integrity check.
    SecureDataInvalid, // 0x0018

    /// The RMP page size is incorrect.
    InvalidPageSize, // 0x0019

    /// The RMP page state is incorrect
    InvalidPageState, // 0x001A

    /// The metadata entry is invalid.
    InvalidMdataEntry, // 0x001B

    /// The page ownership is incorrect
    InvalidPageOwner, // 0x001C

    /// The AEAD algorithm would have overflowed
    AEADOFlow, // 0x001D

    /// A Mailbox mode command was sent while the CSV FW was in Ring Buffer
    /// mode. Ring Buffer mode has been exited; the Mailbox mode command
    /// has been ignored. Retry is recommended.
    RbModeExited = 0x001F, // 0x001F

    /// The RMP must be reinitialized.
    RMPInitRequired = 0x0020, // 0x0020

    /// SVN of provided image is lower than the committed SVN.
    BadSvn, // 0x0021

    /// Firmware version anti-rollback.
    BadVersion, // 0x0022

    /// An invocation of SNP_SHUTDOWN is required to complete this action.
    ShutdownRequired, // 0x0023

    /// Update of the firmware internal state or a guest context page has failed.
    UpdateFailed, // 0x0024

    /// Installation of the committed firmware image required
    RestoreRequired, // 0x0025

    /// The RMP initialization failed.
    RMPInitFailed, // 0x0026

    /// The key requested is invalid, not present, or not allowed.
    InvalidKey, // 0x0027

    /// Custom error message (catch-all for unclassified errors)
    Custom(String), // 0x0028

    /// Unknown error
    Unknown, // 0x0029
}

/// There are a number of error conditions that can occur between this
/// layer all the way down to the CSV platform. Most of these cases have
/// been enumerated; however, there is a possibility that some error
/// conditions are not encapsulated here.
#[derive(Debug)]
pub enum Indeterminate<T: Debug> {
    /// The error condition is known.
    Known(T),

    /// The error condition is unknown.
    Unknown,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_description = match self {
            Error::IoError(_) => "I/O Error",
            Error::InvalidPlatformState => "Invalid platform state",
            Error::InvalidGuestState => "Invalid guest state",
            Error::InvalidConfig => "Platform configuration invalid",
            Error::InvalidLen => "Memory buffer too small",
            Error::AlreadyOwned => "Platform is already owned",
            Error::InvalidCertificate => "Invalid certificate",
            Error::PolicyFailure => "Policy failure",
            Error::Inactive => "Guest is inactive",
            Error::InvalidAddress => "Provided address is invalid",
            Error::BadSignature => "Provided signature is invalid",
            Error::BadMeasurement => "Provided measurement is invalid",
            Error::AsidOwned => "ASID is already owned",
            Error::InvalidAsid => "ASID is invalid",
            Error::WbinvdRequired => "WBINVD instruction required",
            Error::DfFlushRequired => "DF_FLUSH invocation required",
            Error::InvalidGuest => "Guest handle is invalid",
            Error::InvalidCommand => "Issued command is invalid",
            Error::Active => "Guest is active",
            Error::HardwarePlatform => {
                "Hardware condition occured, safe to re-allocate parameter buffers"
            }
            Error::HardwareUnsafe => {
                "Hardware condition occured, unsafe to re-allocate parameter buffers"
            }
            Error::Unsupported => "Feature is unsupported",
            Error::InvalidParam => "Given parameter is invalid",
            Error::ResourceLimit => {
                "CSV firmware has run out of required resources to carry out command"
            }
            Error::SecureDataInvalid => "CSV platform observed a failed integrity check",
            Error::InvalidPageSize => "The RMP page size is incorrect.",
            Error::InvalidPageState => "The RMP page state is incorrect.",
            Error::InvalidMdataEntry => "The metadata entry is invalid.",
            Error::InvalidPageOwner => "The page ownership is incorrect",
            Error::AEADOFlow => "The AEAD algorithm would have overflowed.",
            Error::RbModeExited => "A Mailbox mode command was sent while the CSV FW was in Ring Buffer \
                                    mode. Ring Buffer mode has been exited; the Mailbox mode command has \
                                    been ignored. Retry is recommended.",
            Error::RMPInitRequired => "The RMP must be reinitialized.",
            Error::BadSvn => "SVN of provided image is lower than the committed SVN",
            Error::BadVersion => "Firmware version anti-rollback.",
            Error::ShutdownRequired => "An invocation of SNP_SHUTDOWN is required to complete this action.",
            Error::UpdateFailed => "Update of the firmware internal state or a guest context page has failed.",
            Error::RestoreRequired => "Installation of the committed firmware image required.",
            Error::RMPInitFailed => "The RMP initialization failed.",
            Error::InvalidKey => "The key requested is invalid, not present, or not allowed",
            Error::Custom(msg) => msg,
            Error::Unknown => "Unknown Error",
        };
        write!(f, "{err_description}")
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(error: io::Error) -> Error {
        Error::IoError(error)
    }
}

impl From<ErrorStack> for Error {
    #[inline]
    fn from(error: ErrorStack) -> Error {
        Error::IoError(io::Error::from(error))
    }
}

impl error::Error for Indeterminate<Error> {}

impl Display for Indeterminate<Error> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let err_description = match self {
            Indeterminate::Known(error) => format!("Known Error: {error}"),
            Indeterminate::Unknown => "Unknown Error Encountered".to_string(),
        };

        write!(f, "{err_description}")
    }
}

impl From<io::Error> for Indeterminate<Error> {
    #[inline]
    fn from(error: io::Error) -> Indeterminate<Error> {
        Indeterminate::Known(error.into())
    }
}

impl From<u32> for Indeterminate<Error> {
    #[inline]
    fn from(error: u32) -> Indeterminate<Error> {
        Indeterminate::Known(match error {
            0x00 => io::Error::last_os_error().into(),
            0x01 => Error::InvalidPlatformState,
            0x02 => Error::InvalidGuestState,
            0x03 => Error::InvalidConfig,
            0x04 => Error::InvalidLen,
            0x05 => Error::AlreadyOwned,
            0x06 => Error::InvalidCertificate,
            0x07 => Error::PolicyFailure,
            0x08 => Error::Inactive,
            0x09 => Error::InvalidAddress,
            0x0A => Error::BadSignature,
            0x0B => Error::BadMeasurement,
            0x0C => Error::AsidOwned,
            0x0D => Error::InvalidAsid,
            0x0E => Error::WbinvdRequired,
            0x0F => Error::DfFlushRequired,
            0x10 => Error::InvalidGuest,
            0x11 => Error::InvalidCommand,
            0x12 => Error::Active,
            0x13 => Error::HardwarePlatform,
            0x14 => Error::HardwareUnsafe,
            0x15 => Error::Unsupported,
            0x16 => Error::InvalidParam,
            0x17 => Error::ResourceLimit,
            0x18 => Error::SecureDataInvalid,
            0x19 => Error::InvalidPageSize,
            0x1A => Error::InvalidPageState,
            0x1B => Error::InvalidMdataEntry,
            0x1C => Error::InvalidPageOwner,
            0x1D => Error::AEADOFlow,
            0x1F => Error::RbModeExited,
            0x20 => Error::RMPInitRequired,
            0x21 => Error::BadSvn,
            0x22 => Error::BadVersion,
            0x23 => Error::ShutdownRequired,
            0x24 => Error::UpdateFailed,
            0x25 => Error::RestoreRequired,
            0x26 => Error::RMPInitFailed,
            0x27 => Error::InvalidKey,
            0x28 => Error::Custom(format!("Custom error (code: 0x{:X})", error)),
            _ => return Indeterminate::Unknown,
        })
    }
}

impl From<Indeterminate<Error>> for io::Error {
    #[inline]
    fn from(indeterminate: Indeterminate<Error>) -> io::Error {
        match indeterminate {
            Indeterminate::Known(e) => io::Error::new(io::ErrorKind::Other, e),
            Indeterminate::Unknown => io::Error::new(io::ErrorKind::Other, "unknown CSV error"),
        }
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for Error {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Error::Custom(e.to_string())
    }
}
