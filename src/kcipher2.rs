// SPDX-FileCopyrightText: 2026 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! Implementation of the [KCipher-2] stream cipher.
//!
//! [KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2

use core::array;

#[cfg(feature = "zeroize")]
use cipher::zeroize::{Zeroize, ZeroizeOnDrop};
use cipher::{
    Block, BlockSizeUser, IvSizeUser, KeyIvInit, KeySizeUser, ParBlocksSizeUser,
    StreamCipherBackend, StreamCipherClosure, StreamCipherCore, StreamCipherCoreWrapper,
    consts::{U1, U8, U16},
};

use crate::{
    consts,
    utils::{self, Mode},
};

/// The [KCipher-2] stream cipher key.
///
/// [KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2
pub type Key = cipher::Key<KCipher2Core>;

/// The [KCipher-2] stream cipher initialization vector.
///
/// [KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2
pub type Iv = cipher::Iv<KCipher2Core>;

/// The [KCipher-2] stream cipher.
///
/// [KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2
pub type KCipher2 = StreamCipherCoreWrapper<KCipher2Core>;

/// Core state of the [KCipher-2] stream cipher.
///
/// [KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2
pub struct KCipher2Core {
    a: [u32; 5],
    b: [u32; 11],
    l1: u32,
    r1: u32,
    l2: u32,
    r2: u32,
}

impl KCipher2Core {
    #[expect(clippy::similar_names)]
    /// The `next()` operation as defined in [RFC 7008 Section 2.3.1].
    ///
    /// [RFC 7008 Section 2.3.1]: https://datatracker.ietf.org/doc/html/rfc7008#section-2.3.1
    fn next(&mut self, mode: Mode) {
        let next_l1 = utils::sub_k2(self.r2.wrapping_add(self.b[4]));
        let next_r1 = utils::sub_k2(self.l2.wrapping_add(self.b[9]));
        let next_l2 = utils::sub_k2(self.l1);
        let next_r2 = utils::sub_k2(self.r1);

        let mut feedback_a =
            (self.a[0] << 8) ^ consts::AMUL0[usize::try_from(self.a[0] >> 24).unwrap()] ^ self.a[3];
        if matches!(mode, Mode::Init) {
            feedback_a ^= utils::nlf(self.b[0], self.r2, self.r1, self.a[4]);
        }

        let temp1 = if (self.a[2] & 0x4000_0000) != 0 {
            (self.b[0] << 8) ^ consts::AMUL1[usize::try_from(self.b[0] >> 24).unwrap()]
        } else {
            (self.b[0] << 8) ^ consts::AMUL2[usize::try_from(self.b[0] >> 24).unwrap()]
        };

        let temp2 = if (self.a[2] & 0x8000_0000) != 0 {
            (self.b[8] << 8) ^ consts::AMUL3[usize::try_from(self.b[8] >> 24).unwrap()]
        } else {
            self.b[8]
        };

        let mut feedback_b = temp1 ^ self.b[1] ^ self.b[6] ^ temp2;

        if matches!(mode, Mode::Init) {
            feedback_b ^= utils::nlf(self.b[10], self.l2, self.l1, self.a[0]);
        }

        self.a.rotate_left(1);
        self.a[4] = feedback_a;

        self.b.rotate_left(1);
        self.b[10] = feedback_b;

        self.l1 = next_l1;
        self.r1 = next_r1;
        self.l2 = next_l2;
        self.r2 = next_r2;
    }

    fn setup_state_values(key: &Key, iv: &Iv) -> Self {
        fn key_expansion(key: &Key, iv: &Iv) -> ([u32; 12], [u32; 4]) {
            // TODO: Use `Iterator::next_chunk()` when stable.
            let key: [u32; 4] = {
                let mut iter = key
                    .chunks_exact(4)
                    .map(|c| u32::from_be_bytes(c.try_into().unwrap()));
                array::from_fn(|_| iter.next().unwrap())
            };

            // TODO: Use `Iterator::next_chunk()` when stable.
            let iv: [u32; 4] = {
                let mut iter = iv
                    .chunks_exact(4)
                    .map(|c| u32::from_be_bytes(c.try_into().unwrap()));
                array::from_fn(|_| iter.next().unwrap())
            };

            let mut ik: [u32; 12] = Default::default();

            ik[..4].copy_from_slice(&key);

            ik[4] = ik[0] ^ utils::sub_k2(ik[3].rotate_left(8)) ^ 0x0100_0000;

            ik[5] = ik[1] ^ ik[4];
            ik[6] = ik[2] ^ ik[5];
            ik[7] = ik[3] ^ ik[6];

            ik[8] = ik[4] ^ utils::sub_k2(ik[7].rotate_left(8)) ^ 0x0200_0000;

            ik[9] = ik[5] ^ ik[8];
            ik[10] = ik[6] ^ ik[9];
            ik[11] = ik[7] ^ ik[10];

            (ik, iv)
        }

        let (ik, iv) = key_expansion(key, iv);

        let a = [ik[4], ik[3], ik[2], ik[1], ik[0]];

        let b = [
            ik[10], ik[11], iv[0], iv[1], ik[8], ik[9], iv[2], iv[3], ik[7], ik[5], ik[6],
        ];

        let l1 = u32::default();
        let r1 = u32::default();
        let l2 = u32::default();
        let r2 = u32::default();

        Self {
            a,
            b,
            l1,
            r1,
            l2,
            r2,
        }
    }

    /// The `stream()` function as defined in [RFC 7008 Section 2.3.3].
    ///
    /// [RFC 7008 Section 2.3.3]: https://datatracker.ietf.org/doc/html/rfc7008#section-2.3.3
    fn stream(&self) -> u64 {
        let zh = utils::nlf(self.b[10], self.l2, self.l1, self.a[0]);
        let zl = utils::nlf(self.b[0], self.r2, self.r1, self.a[4]);
        (u64::from(zh) << u32::BITS) | u64::from(zl)
    }
}

impl BlockSizeUser for KCipher2Core {
    type BlockSize = U8;
}

impl KeySizeUser for KCipher2Core {
    type KeySize = U16;
}

impl IvSizeUser for KCipher2Core {
    type IvSize = U16;
}

impl KeyIvInit for KCipher2Core {
    fn new(key: &Key, iv: &Iv) -> Self {
        let mut state = Self::setup_state_values(key, iv);

        for _ in 0..24 {
            state.next(Mode::Init);
        }
        state
    }
}

impl StreamCipherCore for KCipher2Core {
    fn remaining_blocks(&self) -> Option<usize> {
        None
    }

    fn process_with_backend(&mut self, f: impl StreamCipherClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut Backend(self));
    }
}

#[cfg(feature = "zeroize")]
impl Drop for KCipher2Core {
    fn drop(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
        self.l1.zeroize();
        self.r1.zeroize();
        self.l2.zeroize();
        self.r2.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl ZeroizeOnDrop for KCipher2Core {}

struct Backend<'a>(&'a mut KCipher2Core);

impl BlockSizeUser for Backend<'_> {
    type BlockSize = <KCipher2Core as BlockSizeUser>::BlockSize;
}

impl ParBlocksSizeUser for Backend<'_> {
    type ParBlocksSize = U1;
}

impl StreamCipherBackend for Backend<'_> {
    fn gen_ks_block(&mut self, block: &mut Block<Self>) {
        let x = self.0.stream();
        self.0.next(Mode::Normal);
        block.copy_from_slice(&x.to_be_bytes());
    }
}
