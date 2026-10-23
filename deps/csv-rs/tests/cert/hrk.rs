// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use codicon::Decoder;
use csv_rs::certs::{builtin::HRK, ca, Verifiable};

#[test]
fn verify() {
    let hrk = ca::Certificate::decode(&mut &HRK[..], ()).unwrap();
    (&hrk, &hrk).verify().unwrap();
}
