// Copyright (C) Hygon Info Technologies Ltd.
//
// SPDX-License-Identifier: Apache-2.0

//! Helpful primitives for developing the crate.

pub mod cached_chain;
mod impl_const_id;

use std::{
    io::{Read, Result, Write},
    mem::{size_of, MaybeUninit},
    slice::{from_raw_parts, from_raw_parts_mut},
};

pub trait FromLe: Sized {
    fn from_le(value: &[u8]) -> Result<Self>;
}

pub trait AsLeBytes<T> {
    fn as_le_bytes(&self) -> T;
}

impl FromLe for openssl::bn::BigNum {
    #[inline]
    fn from_le(value: &[u8]) -> Result<Self> {
        Ok(Self::from_slice(
            &value.iter().rev().cloned().collect::<Vec<_>>(),
        )?)
    }
}

impl AsLeBytes<[u8; 72]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 72] {
        let mut buf = [0u8; 72];

        for (i, b) in self.to_vec().iter().rev().cloned().enumerate() {
            buf[i] = b;
        }

        buf
    }
}

impl AsLeBytes<[u8; 512]> for openssl::bn::BigNumRef {
    fn as_le_bytes(&self) -> [u8; 512] {
        let mut buf = [0u8; 512];

        for (i, b) in self.to_vec().iter().rev().cloned().enumerate() {
            buf[i] = b;
        }

        buf
    }
}

pub trait TypeLoad: Read {
    fn load<T: Sized + Copy>(&mut self) -> Result<T> {
        #[allow(clippy::uninit_assumed_init)]
        let mut t = unsafe { MaybeUninit::uninit().assume_init() };
        let p = &mut t as *mut T as *mut u8;
        let s = unsafe { from_raw_parts_mut(p, size_of::<T>()) };
        self.read_exact(s)?;
        Ok(t)
    }
}

pub trait TypeSave: Write {
    fn save<T: Sized + Copy>(&mut self, value: &T) -> Result<()> {
        let p = value as *const T as *const u8;
        let s = unsafe { from_raw_parts(p, size_of::<T>()) };
        self.write_all(s)
    }
}

impl<T: Read> TypeLoad for T {}
impl<T: Write> TypeSave for T {}
