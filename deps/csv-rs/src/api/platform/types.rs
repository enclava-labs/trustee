// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

use std::{
    marker::PhantomData,
    mem::{size_of_val, MaybeUninit},
};

use crate::{certs::csv, Build, Version};

/// Reset the platform's persistent state.
pub struct PlatformReset;

bitflags::bitflags! {
    /// The platform's status flags.
    #[derive(Default)]
    pub struct PlatformStatusFlags: u32 {
        /// If set, this platform is owned. Otherwise, it is self-owned.
        const OWNED           = 1 << 0;

        /// If set, encrypted state functionality is present.
        const ENCRYPTED_STATE = 1 << 8;
    }
}

/// The platform state.
///
/// The underlying CSV platform behaves like a state machine and can
/// only perform certain actions while it is in certain states.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    /// The platform is uninitialized.
    Uninitialized,

    /// The platform is initialized, but not currently managing any
    /// guests.
    Initialized,

    /// The platform is initialized and is overseeing execution
    /// of encrypted guests.
    Working,
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self {
            State::Uninitialized => "uninitialized",
            State::Initialized => "initialized",
            State::Working => "working",
        };
        write!(f, "{state}")
    }
}

/// Information regarding the CSV platform's current status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    /// The build number.
    pub build: Build,

    /// The platform's current state.
    pub state: State,

    /// Additional platform information is encoded into flags.
    ///
    /// These could describe whether encrypted state functionality
    /// is enabled, or whether the platform is self-owned.
    pub flags: PlatformStatusFlags,

    /// The number of valid guests supervised by this platform.
    pub guests: u32,
}

/// Query CSV platform status.
#[derive(Default)]
#[repr(C, packed)]
pub struct PlatformStatus {
    /// The firmware version (major.minor)
    pub version: Version,

    /// The Platform State.
    pub state: u8,

    /// Right now the only flag that is communicated in
    /// this single byte is whether the platform is self-
    /// owned or not. If the first bit is set then the
    /// platform is externally owned. If it is cleared, then
    /// the platform is self-owned. Self-owned is the default
    /// state.
    pub flags: PlatformStatusFlags,

    /// The firmware build ID for this API version.
    pub build: u8,

    /// The number of valid guests maintained by the CSV firmware.
    pub guest_count: u32,
}

/// Generate a new Platform Endorsement Key (PEK).
pub struct PekGen;

/// Request certificate signing.
#[repr(C, packed)]
pub struct PekCsr<'a> {
    addr: u64,
    len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PekCsr<'a> {
    pub fn new(cert: &'a mut MaybeUninit<csv::Certificate>) -> Self {
        Self {
            addr: cert as *mut _ as _,
            len: size_of_val(cert) as _,
            _phantom: PhantomData,
        }
    }
}

/// Join the platform to the domain.
#[repr(C, packed)]
pub struct PekCertImport<'a> {
    pek_addr: u64,
    pek_len: u32,
    oca_addr: u64,
    oca_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PekCertImport<'a> {
    pub fn new(pek: &'a csv::Certificate, oca: &'a csv::Certificate) -> Self {
        Self {
            pek_addr: pek as *const _ as _,
            pek_len: size_of_val(pek) as _,
            oca_addr: oca as *const _ as _,
            oca_len: size_of_val(oca) as _,
            _phantom: PhantomData,
        }
    }
}

/// (Re)generate the Platform Diffie-Hellman (PDH).
pub struct PdhGen;

/// Retrieve the PDH and the platform certificate chain.
#[repr(C, packed)]
pub struct PdhCertExport<'a> {
    pdh_addr: u64,
    pdh_len: u32,
    certs_addr: u64,
    certs_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> PdhCertExport<'a> {
    pub fn new(
        pdh: &'a mut MaybeUninit<csv::Certificate>,
        certs: &'a mut MaybeUninit<[csv::Certificate; 3]>,
    ) -> Self {
        Self {
            pdh_addr: pdh as *mut _ as _,
            pdh_len: size_of_val(pdh) as _,
            certs_addr: certs.as_mut_ptr() as _,
            certs_len: size_of_val(certs) as _,
            _phantom: PhantomData,
        }
    }
}

/// Get the CPU's unique ID that can be used for getting
/// a certificate for the CEK public key.
#[repr(C, packed)]
pub struct GetId<'a> {
    id_addr: u64,
    id_len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> GetId<'a> {
    pub fn new(id: &'a mut [u8; 64]) -> Self {
        Self {
            id_addr: id.as_mut_ptr() as _,
            id_len: id.len() as _,
            _phantom: PhantomData,
        }
    }

    /// This method is only meaningful if called *after* the GET_ID2 ioctl is called because the
    /// kernel will write the length of the unique CPU ID to `GetId.id_len`.
    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.id_addr as *const u8, self.id_len as _) }
    }
}
