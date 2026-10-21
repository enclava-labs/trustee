// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::{io::{Error, ErrorKind}, ptr};

pub const CSV_RTMR_VERSION_MAX: u16 = 1;
pub const CSV_RTMR_VERSION_MIN: u16 = 1;

pub const CSV_RTMR_REG_SIZE: usize = 32;
pub const CSV_RTMR_EXTEND_LEN: usize = CSV_RTMR_REG_SIZE;

pub const CSV_RTMR_REG_NUM: usize = 5;
pub const CSV_RTMR_REG_INDEX_MAX: usize = CSV_RTMR_REG_NUM - 1;

#[repr(u16)]
pub enum CsvGuestUserRtmrSubcmd {
    Status = 0x1,
    Start = 02,
    Read = 0x3,
    Extend = 0x4,
}

#[repr(u8)]
pub enum CsvGuestRtmrStatus {
    Uninit = 0x0,
    Init = 0x1,
    Working = 0x2,
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct CsvGuestUserRtmrStatus {
    /// The rtmr version used in the guest.
    pub version: u16,
    /// The state of the guest's rtmr.
    pub state: u8,
}

impl CsvGuestUserRtmrStatus {
    /// Create a new rtmr_status request.
    pub fn new() -> Self {
        Self {
            version: 0,
            state: 0,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct CsvGuestUserRtmrStart {
    /// The rtmr version requested by the caller.
    pub version: u16,
}

impl CsvGuestUserRtmrStart {
    /// Create a new rtmr_start request.
    pub fn new(version: u16) -> Self {
        Self {
            version: version,
        }
    }
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct CsvGuestUserRtmrRead {
    /// The bitmap specified the rtmr registers to read.
    pub bitmap: u32,
    /// The buffer to store the first rtmr register returned by the firmware.
    pub data: [u8; CSV_RTMR_REG_SIZE],
}

impl CsvGuestUserRtmrRead {
    pub fn new(bitmap: u32) -> Self {
        Self {
            bitmap: bitmap,
            data: [0; CSV_RTMR_REG_SIZE],
        }
    }

    pub fn allocate_with_capacity(bitmap: u32, num_regs: usize) -> (Box<[u8]>, &'static mut Self) {
        let total_size = std::mem::size_of::<Self>() + (num_regs - 1) * CSV_RTMR_REG_SIZE;
        let mut buffer = vec![0u8; total_size].into_boxed_slice();

        let read = CsvGuestUserRtmrRead {
            bitmap: bitmap,
            data: [0; CSV_RTMR_REG_SIZE],
        };

        unsafe {
            let ptr = buffer.as_mut_ptr() as *mut Self;
            ptr::write(ptr, read);

            (buffer, &mut *ptr)
        }
    }

    pub fn get_read_reg(&self, bit: usize) -> &[u8; CSV_RTMR_REG_SIZE] {
        unsafe {
            let ptr = self.data.as_ptr().add(bit * CSV_RTMR_REG_SIZE) as *const _;
            &*ptr
        }
    }
}

#[repr(C, packed)]
#[derive(Debug)]
pub struct CsvGuestUserRtmrExtend {
    /// The index of the specified rtmr register.
    pub index: u8,
    /// The reserved field, just for alignment.
    pub rsvd: u8,
    /// The length of the data to be extended.
    pub data_len: u16,
    /// The data to be extened.
    pub data: [u8; CSV_RTMR_EXTEND_LEN],
}

impl CsvGuestUserRtmrExtend {
    /// Create a new rtmr_extend request.
    pub fn new(index: u8, data: &[u8]) -> Result<Self, Error> {
        if data.len() < CSV_RTMR_EXTEND_LEN {
            Err(Error::new(
                ErrorKind::InvalidInput,
                format!("invalid length: expected >= {}", CSV_RTMR_EXTEND_LEN)
            ))
        } else {
            let mut array = [0u8; CSV_RTMR_EXTEND_LEN];

            array[0..CSV_RTMR_EXTEND_LEN].copy_from_slice(&data[0..CSV_RTMR_EXTEND_LEN]);

            Ok(Self {
                index: index,
                rsvd: 0,
                data_len: CSV_RTMR_EXTEND_LEN as u16,
                data: array,
            })
        }
    }
}