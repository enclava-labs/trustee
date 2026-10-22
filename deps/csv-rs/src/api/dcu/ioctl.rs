// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use super::types::{AttestationReport, AttestationResponse};
use iocuddle::{Group, Ioctl, WriteRead};
use libc::c_void;
use log::*;
use std::io;

/// Page size constant used for memory allocation (4KB)
const PAGE_SIZE: usize = 4096;

/// IOCTL command enumeration for DCU device operations
pub enum DcuDeviceIoctl {
    /// Command to request attestation report from device
    GetReport = 0x17,
    /// Placeholder for undefined/unused commands
    _Undefined,
}

/// IOCTL group identifier for DCU device ('M' magic number)
const DCU: Group = Group::new(b'M');

/// Predefined IOCTL command for getting attestation reports
/// Uses write-read operation mode with MkfdIoctlSecurityAttestationArgs structure
pub const DCU_GET_REPORT: Ioctl<WriteRead, &MkfdIoctlSecurityAttestationArgs> =
    unsafe { DCU.write_read(DcuDeviceIoctl::GetReport as u8) };

/// IOCTL arguments structure for security attestation requests
/// Note: Maintains #[repr(C)] for compatibility with kernel interface
#[repr(C)]
pub struct MkfdIoctlSecurityAttestationArgs {
    /// DCU identifier for target device
    pub dcu_id: u32,
    /// For compatibility
    pub cmd_id :u32,
    /// Message version number(default 1)
    pub version: u32,
    /// Request structure address
    pub request_data: *mut c_void,
    /// Request structure size
    pub request_size: u64,
    /// Response structure address
    pub response_data: *mut c_void,
    /// Response structure size
    pub response_size: u64,
    /// Firmware error address
    pub fw_err: u64,
}

impl MkfdIoctlSecurityAttestationArgs {
    /// Creates a new instance with default values
    /// Note: Buffers are initialized as null pointers
    pub fn new() -> Self {
        Self {
            dcu_id: 0,
            cmd_id: 0,
            version: 1,
            request_data: std::ptr::null_mut(),
            request_size: 0,
            response_data: std::ptr::null_mut(),
            response_size: 0,
            fw_err: 0,
        }
    }

    /// Configures attestation arguments with DCU ID and nonce
    ///
    /// # Safety
    /// Contains unsafe operations for memory allocation and pointer manipulation
    ///
    /// # Arguments
    /// * `dcu_id` - Target DCU device identifier
    /// * `userdata` - 64-byte cryptographic nonce for attestation
    pub fn set_attestation_args(&mut self, dcu_id: u32, userdata: [u8; 64]) -> std::io::Result<()> {
        unsafe {
            // Allocate page-aligned request buffer
            self.request_data = libc::malloc(PAGE_SIZE);
            if self.request_data.is_null() {
                return Err(std::io::Error::last_os_error());
            }

            // Initialize request buffer with zeros
            libc::memset(self.request_data, 0, PAGE_SIZE);
            self.request_size = PAGE_SIZE as u64;

            // Copy nonce into request buffer
            std::ptr::copy_nonoverlapping(
                userdata.as_ptr(),
                self.request_data as *mut u8,
                userdata.len(),
            );

            // Debug output: hex dump of nonce in request buffer
            trace!("Generated random number for DCU report request");
            hex_dump(self.request_data as *const u8, 64);

            // Allocate page-aligned response buffer
            self.response_data = libc::malloc(PAGE_SIZE);
            if self.response_data.is_null() {
                // Cleanup request buffer on allocation failure
                libc::free(self.request_data);
                return Err(std::io::Error::last_os_error());
            }

            // Initialize response buffer with zeros
            libc::memset(self.response_data, 0, PAGE_SIZE);
            self.response_size = PAGE_SIZE as u64;

            // Set target DCU identifier
            self.dcu_id = dcu_id;
            Ok(())
        }
    }

    /// Releases allocated memory buffers
    ///
    /// # Safety
    /// Must only be called when buffers are no longer needed
    /// Calling with dangling pointers is undefined behavior
    pub unsafe fn free_buffers(&mut self) {
        if !self.request_data.is_null() {
            libc::free(self.request_data);
            self.request_data = std::ptr::null_mut();
        }
        if !self.response_data.is_null() {
            libc::free(self.response_data);
            self.response_data = std::ptr::null_mut();
        }
    }

    /// Extracts attestation report from response buffer
    ///
    /// Returns:
    /// - Some(AttestationReport) if valid report exists
    /// - None if response buffer contains no valid report
    pub fn extract_report(&mut self) -> Result<Option<AttestationReport>, io::Error> {
        unsafe {
            if let Some(response) = AttestationResponse::from_raw(self.response_data) {
                return Ok(Some(response.report.clone()));
            }
        }
        Ok(None)
    }
}

impl Default for MkfdIoctlSecurityAttestationArgs {
    fn default() -> Self {
        Self::new()
    }
}

/// Automatic cleanup implementation to prevent memory leaks
impl Drop for MkfdIoctlSecurityAttestationArgs {
    fn drop(&mut self) {
        unsafe { self.free_buffers() }
    }
}

/// Utility function for debugging memory contents with logging
///
/// # Arguments
/// * `data` - Pointer to memory region
/// * `len` - Number of bytes to dump
fn hex_dump(data: *const u8, len: usize) {
    let mut output = String::new();

    for i in 0..len {
        unsafe {
            output.push_str(&format!("{:02x} ", *data.add(i)));
        }
        if (i + 1) % 16 == 0 {
            output.push('\n');
        }
    }

    trace!("Memory dump:\n{}", output);
}
