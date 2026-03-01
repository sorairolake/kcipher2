// SPDX-FileCopyrightText: 2026 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `kcipher2` crate is an implementation of the [KCipher-2] stream cipher
//! as described in [RFC 7008].
//!
//! [KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2
//! [RFC 7008]: https://datatracker.ietf.org/doc/html/rfc7008

#![doc(html_root_url = "https://docs.rs/kcipher2/0.1.0/")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Lint levels of rustc.
#![deny(missing_docs)]

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
