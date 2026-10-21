// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use std::env;
use std::path::Path;

fn main() {
    if cfg!(feature = "hw_tests") || Path::new("/dev/sev").exists() {
        println!("cargo:rustc-cfg=has_dev_sev");
    }

    if cfg!(feature = "hw_tests") || Path::new("/dev/csv-guest").exists() {
        println!("cargo:rustc-cfg=has_dev_csv_guest");
    }
    println!("cargo:rustc-check-cfg=cfg(has_dev_dcu)");
    if cfg!(feature = "hw_tests") || Path::new("/dev/mkfd").exists() {
        println!("cargo:rustc-cfg=has_dev_dcu");
    }

    if let Ok(version) = env::var("DEP_OPENSSL_VERSION_NUMBER") {
        let version = u64::from_str_radix(&version, 16).unwrap();
        match version {
            v if v < 0x1_01_01_00_0 => panic!("Unsupported openssl version:{}", version),
            v if v < 0x3_00_00_00_0 => println!("cargo:rustc-cfg=ossl111"),
            v if v < 0x4_00_00_00_0 => println!("cargo:rustc-cfg=ossl300"),
            _ => panic!("Unsupported openssl version:0x{:x}", version),
        }
    }
}
