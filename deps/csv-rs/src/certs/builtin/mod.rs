// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! HYGON's certificates.
//! Certificate provenance: <https://cert.hygon.cn/hrk>
//! The certificate is embedded here as byte slices.

/// The public HRK certificate.
pub const HRK: &[u8] = include_bytes!("hrk.cert");
