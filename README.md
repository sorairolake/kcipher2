<!--
SPDX-FileCopyrightText: 2026 Shun Sakai

SPDX-License-Identifier: CC-BY-4.0
-->

# kcipher2

[![CI][ci-badge]][ci-url]
[![Version][version-badge]][version-url]
![MSRV][msrv-badge]
[![Docs][docs-badge]][docs-url]
![License][license-badge]

**kcipher2** is a pure [Rust] implementation of the [KCipher-2] stream cipher
as described in [RFC 7008].

## Usage

Run the following command in your project directory:

```sh
cargo add kcipher2
```

### Crate features

#### `zeroize`

Enables the [`zeroize`] crate.

### `no_std` support

This supports `no_std` mode.

### Documentation

See the [documentation][docs-url] for more details.

## Minimum supported Rust version

The minimum supported Rust version (MSRV) of this library is v1.85.0.

## Source code

The upstream repository is available at
<https://github.com/sorairolake/kcipher2.git>.

## Changelog

Please see [CHANGELOG.adoc].

## Contributing

Please see [CONTRIBUTING.adoc].

## License

Copyright (C) 2026 Shun Sakai (see [AUTHORS.adoc])

This library is distributed under the terms of either the _Apache License 2.0_
or the _MIT License_.

This project is compliant with version 3.3 of the [_REUSE Specification_]. See
copyright notices of individual files for more details on copyright and
licensing information.

[ci-badge]: https://img.shields.io/github/actions/workflow/status/sorairolake/kcipher2/CI.yaml?branch=develop&style=for-the-badge&logo=github&label=CI
[ci-url]: https://github.com/sorairolake/kcipher2/actions?query=branch%3Adevelop+workflow%3ACI++
[version-badge]: https://img.shields.io/crates/v/kcipher2?style=for-the-badge&logo=rust
[version-url]: https://crates.io/crates/kcipher2
[msrv-badge]: https://img.shields.io/crates/msrv/kcipher2?style=for-the-badge&logo=rust
[docs-badge]: https://img.shields.io/docsrs/kcipher2?style=for-the-badge&logo=docsdotrs&label=Docs.rs
[docs-url]: https://docs.rs/kcipher2
[license-badge]: https://img.shields.io/crates/l/kcipher2?style=for-the-badge
[Rust]: https://www.rust-lang.org/
[KCipher-2]: https://en.wikipedia.org/wiki/KCipher-2
[RFC 7008]: https://datatracker.ietf.org/doc/html/rfc7008
[`zeroize`]: https://crates.io/crates/zeroize
[CHANGELOG.adoc]: CHANGELOG.adoc
[CONTRIBUTING.adoc]: CONTRIBUTING.adoc
[AUTHORS.adoc]: AUTHORS.adoc
[_REUSE Specification_]: https://reuse.software/spec-3.3/
