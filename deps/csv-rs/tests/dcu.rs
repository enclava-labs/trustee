// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use csv_rs::api::dcu::*;
//use crate::certs::csv;
use rand::{thread_rng, Rng};

#[cfg_attr(not(has_dev_dcu), ignore)]
#[test_log::test]
fn get_report() {
    let mut rng = thread_rng();
    let mut userdata = [0u8; 64];
    rng.fill(&mut userdata);

    let mut dcu_device: DcuDevice = DcuDevice::new().unwrap();

    let reports = dcu_device.get_report(userdata).unwrap();

    for report in &reports {
        assert_eq!(userdata, report.body.user_data);
    }
}

#[cfg_attr(not(has_dev_dcu), ignore)]
#[cfg(feature = "network")]
#[tokio::test]
async fn get_report_and_verify() {
    let mut rng = thread_rng();
    let mut userdata = [0u8; 64];
    rng.fill(&mut userdata);
    let mut dcu_device = DcuDevice::new().unwrap();

    let reports = dcu_device.get_report(userdata).unwrap();

    verify_reports(&reports, &userdata).await.unwrap();
}
