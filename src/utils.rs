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

/// A substitution function as defined in [RFC 7008 Section 2.4.2].
///
/// [RFC 7008 Section 2.4.2]: https://datatracker.ietf.org/doc/html/rfc7008#section-2.4.2
pub fn sub_k2(input: u32) -> u32 {
    let w = input.to_be_bytes();

    consts::T_0[usize::from(w[3])]
        ^ consts::T_1[usize::from(w[2])]
        ^ consts::T_2[usize::from(w[1])]
        ^ consts::T_3[usize::from(w[0])]
}
