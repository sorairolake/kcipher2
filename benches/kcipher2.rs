// SPDX-FileCopyrightText: 2026 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![feature(test)]

extern crate test;

cipher::stream_cipher_bench!(
    kcipher2::KCipher2;
    kcipher2_bench1_16b 16;
    kcipher2_bench2_256b 256;
    kcipher2_bench3_1kib 1024;
    kcipher2_bench4_16kib 16384;
);
