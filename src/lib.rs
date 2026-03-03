// SPDX-FileCopyrightText: 2026 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! The `kcipher2` crate is an implementation of the [KCipher-2] stream cipher
//! as described in [RFC 7008].
//!
//! Cipher functionality is accessed using traits from re-exported [`cipher`]
//! crate.
//!
//! # Examples
//!
//! ```
//! use hex_literal::hex;
//! use kcipher2::{
//!     KCipher2,
//!     cipher::{KeyIvInit, StreamCipher},
//! };
//!
//! let key = [0x42; 16];
//! let nonce = [0x24; 16];
//! let plaintext = hex!("00010203 04050607 08090A0B 0C0D0E0F");
//! let ciphertext = hex!("471694B5 EB93E4A6 EABA73DF A6F77057");
//!
//! // Key and IV must be references to the `Array` type. Here we use the `Into`
//! // trait to convert arrays into it.
//! let mut cipher = KCipher2::new(&key.into(), &nonce.into());
//!
//! let mut buf = plaintext;
//!
//! // Apply keystream (encrypt).
//! cipher.apply_keystream(&mut buf);
//! assert_eq!(buf, ciphertext);
//!
//! let ciphertext = buf;
//!
//! // Decrypt ciphertext by applying keystream again.
//! let mut cipher = KCipher2::new(&key.into(), &nonce.into());
//! cipher.apply_keystream(&mut buf);
//! assert_eq!(buf, plaintext);
//!
//! // Stream ciphers can be used with streaming messages.
//! let mut cipher = KCipher2::new(&key.into(), &nonce.into());
//! for chunk in buf.chunks_mut(3) {
//!     cipher.apply_keystream(chunk);
//! }
//! assert_eq!(buf, ciphertext);
//! ```
//!
//! [KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2
//! [RFC 7008]: https://datatracker.ietf.org/doc/html/rfc7008

#![doc(html_root_url = "https://docs.rs/kcipher2/0.1.0/")]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Lint levels of rustc.
#![deny(missing_docs)]

mod consts;
mod kcipher2;
mod utils;

pub use cipher;

pub use crate::kcipher2::{Iv, KCipher2, KCipher2Core, Key};
