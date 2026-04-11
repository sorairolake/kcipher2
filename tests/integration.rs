// SPDX-FileCopyrightText: 2026 Shun Sakai
//
// SPDX-License-Identifier: Apache-2.0 OR MIT

use hex_literal::hex;
use kcipher2::{
    KCipher2,
    cipher::{KeyIvInit, StreamCipher},
};

#[test]
fn rfc7008() {
    // RFC 7008 Appendix C.1.
    let tests = [
        (
            hex!("00000000 00000000 00000000 00000000"),
            hex!("00000000 00000000 00000000 00000000"),
            hex!(
                "F871EBEF 945B7272"
                "E40C0494 1DFF0537"
                "0B981A59 FBC8AC57"
                "566D3B02 C179DBB4"
                "3B46F1F0 33554C72"
                "5DE68BCC 9872858F"
                "57549602 4062F0E9"
                "F932C998 226DB6BA"
            ),
        ),
        (
            hex!("A37B7D01 2F897076 FE08C22D 142BB2CF"),
            hex!("33A6EE60 E57927E0 8B45CC4C A30EDE4A"),
            hex!(
                "60E9A6B6 7B4C2524"
                "FE726D44 AD5B402E"
                "31D0D1BA 5CA233A4"
                "AFC74BE7 D6069D36"
                "4A75BB6C D8D5B7F0"
                "38AAAA28 4AE4CD2F"
                "E2E5313D FC6CCD8F"
                "9D2484F2 0F86C50D"
            ),
        ),
        (
            hex!("3D62E9B1 8E5B042F 42DF43CC 7175C96E"),
            hex!("777CEFE4 541300C8 ADCACA8A 0B48CD55"),
            hex!(
                "690F108D 84F44AC7"
                "BF257BD7 E394F6C9"
                "AA1192C3 8E200C6E"
                "073C8078 AC18AAD1"
                "D4B8DADE 68802368"
                "2FA42076 83DEA5A4"
                "4C1D95EA E959F5B4"
                "2611F41E A40F0A58"
            ),
        ),
    ];

    for (key, iv, ks) in tests {
        for n in 1..ks.len() {
            let mut cipher = KCipher2::new_from_slices(&key, &iv).unwrap();
            let mut buf = ks;
            for chunk in buf.chunks_mut(n) {
                cipher.apply_keystream(chunk);
            }
            assert_eq!(buf, [0; 64]);
        }
    }
}
