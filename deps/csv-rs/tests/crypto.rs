// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//

use csv_rs::{crypto::key::group, crypto::sm};

#[test]
fn sm2_gen_sig_verify() {
    let (key, prv) = sm::SM2::generate(group::Group::SM2_256).unwrap();
    let id = String::from("test").as_bytes().to_vec();
    let data: Vec<u8> = vec![1, 2, 3, 4];
    let sig = sm::SM2::sign(prv, &id, &data).unwrap();
    let res = sm::SM2::verify(key, &sig, &id, &data).unwrap();
    assert_eq!(true, res);
}
