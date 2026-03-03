// SPDX-FileCopyrightText: 2026 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Utilities for the [KCipher-2] stream cipher.
//!
//! [KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2

use crate::consts;

/// The operation mode.
pub enum Mode {
    /// The operation is used for initialization.
    Init,

    /// The operation is used for generating secure key streams.
    Normal,
}

/// A non-linear function as defined in [RFC 7008 Section 2.4.1].
///
/// [RFC 7008 Section 2.4.1]: https://datatracker.ietf.org/doc/html/rfc7008#section-2.4.1
pub const fn nlf(a: u32, b: u32, c: u32, d: u32) -> u32 {
    a.wrapping_add(b) ^ c ^ d
}

#[expect(clippy::cast_possible_truncation)]
/// A substitution function as defined in [RFC 7008 Section 2.4.2].
///
/// [RFC 7008 Section 2.4.2]: https://datatracker.ietf.org/doc/html/rfc7008#section-2.4.2
pub fn sub_k2(input: u32) -> u32 {
    fn gf_mult_by_2(t: u8) -> u8 {
        let mut lq = u32::from(t) << 1;
        if (lq & 0x100) != 0 {
            lq ^= 0x011B;
        }
        (lq as u8) ^ 0xFF
    }

    fn gf_mult_by_3(t: u8) -> u8 {
        let mut lq = (u32::from(t) << 1) ^ u32::from(t);
        if (lq & 0x100) != 0 {
            lq ^= 0x011B;
        }
        (lq as u8) ^ 0xFF
    }

    let w0 = usize::from(input as u8);
    let w1 = usize::from((input >> 8) as u8);
    let w2 = usize::from((input >> 16) as u8);
    let w3 = usize::from((input >> 24) as u8);

    let t0 = consts::S_BOX[w0];
    let t1 = consts::S_BOX[w1];
    let t2 = consts::S_BOX[w2];
    let t3 = consts::S_BOX[w3];

    let q0 = gf_mult_by_2(t0) ^ gf_mult_by_3(t1) ^ t2 ^ t3;
    let q1 = t0 ^ gf_mult_by_2(t1) ^ gf_mult_by_3(t2) ^ t3;
    let q2 = t0 ^ t1 ^ gf_mult_by_2(t2) ^ gf_mult_by_3(t3);
    let q3 = gf_mult_by_3(t0) ^ t1 ^ t2 ^ gf_mult_by_2(t3);

    (u32::from(q3) << 24) | (u32::from(q2) << 16) | (u32::from(q1) << 8) | u32::from(q0)
}
