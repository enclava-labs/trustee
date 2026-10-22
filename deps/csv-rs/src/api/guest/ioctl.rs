// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use iocuddle::{Group, Ioctl, WriteRead};

use std::marker::PhantomData;

use super::rtmr::CsvGuestUserRtmrSubcmd;

pub enum CsvGuestIoctl {
    GetReport = 0x1,
    RtmrReq = 0x2,
    _Undefined,
}

const CSV: Group = Group::new(b'D');

/// //////////////////// Attestation report ioctl interface ////////////////////

pub const CSV_GET_REPORT: Ioctl<WriteRead, &GuestReportRequest> =
    unsafe { CSV.write_read(CsvGuestIoctl::GetReport as u8) };

/// The structure used for making guest report request to the PSP as a guest owner.
/// This struct is defined in the Linux kernel: drivers/virt/coco/csv-guest/csv-guest.h
#[repr(C)]
pub struct GuestReportRequest<'a> {
    /// Address of the data buffer with user REPORT_DATA included,
    /// and CSV_REPORT output from PSP to be saved.
    pub addr: u64,

    /// The page aligned length of the buffer start from [`req_rsp_addr`]
    pub len: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> GuestReportRequest<'a> {
    /// Creates a new report request from the adresses provided.
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            addr: data.as_ptr() as _,
            len: data.len() as _,
            _phantom: PhantomData,
        }
    }
}


/// ////////////////////// Rtmr operations ioctl interface /////////////////////

pub const CSV_RTMR_REQ: Ioctl<WriteRead, &GuestRtmrRequest> =
    unsafe { CSV.write_read(CsvGuestIoctl::RtmrReq as u8) };

/// The structure used for making guest rtmr request to the PSP as a guest owner.
/// This struct is defined in the Linux kernel: drivers/virt/coco/csv-guest/csv-guest.h
#[repr(C, packed)]
pub struct GuestRtmrRequest<'a> {
    /// Address of the rtmr subcommand buffer. This subcommand buffers request
    /// info and saves the response data returned by the firmware.
    pub buf: u64,
    /// The length of the subcommand buffer.
    pub len: u64,
    /// The identifier of the rtmr subcommand.
    pub subcmd_id: u16,
    /// The reserved field, just for alignment.
    pub rsvd: u16,
    /// The return code that a rtmr subcommand returned by the firmware.
    pub fw_error_code: u32,
    _phantom: PhantomData<&'a ()>,
}

impl<'a> GuestRtmrRequest<'a> {
    /// Create a new rtmr request.
    pub fn new(subcmd_buf: &'a [u8], subcmd_id: CsvGuestUserRtmrSubcmd) -> Self {
        Self {
            buf: subcmd_buf.as_ptr() as _,
            len: subcmd_buf.len() as _,
            subcmd_id: subcmd_id as u16,
            rsvd: 0,
            fw_error_code: 0,
            _phantom: PhantomData,
        }
    }

    /// Return fw_error_code to the caller
    pub fn get_fw_error_code(&self) -> u32 {
        self.fw_error_code
    }
}