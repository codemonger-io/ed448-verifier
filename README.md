# Ed448 Verifier

An [Ed448](https://datatracker.ietf.org/doc/html/rfc8032#section-5.2) verifier written in [Rust](https://www.rust-lang.org).

This crate does nothing but wraps the [`ed448-goldilocks`](https://crates.io/crates/ed448-goldilocks) crate which undertakes all the complicated arithmetics in an implementation of the [`Verifier`](https://docs.rs/signature/latest/signature/trait.Verifier.html) trait of the [`signature`](https://crates.io/crates/signature) crate.

As this crate has not been audited for security at all, use it at **YOUR OWN RISK**.

## Getting started

Add the following to your `Cargo.toml`:

```toml
ed448-verifier = { git = "https://github.com/codemonger-io/ed448-verifier.git", tag = "v0.0.1" }
```

## Usage

```rust
use ed448_verifier::{Signature, VerifyingKey};
use hex_literal::hex;
use signature::Verifier as _;

fn main() {
    // a test vector from RFC 8032
    let public_key_bytes: &[u8] = &hex!("3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580");
    let message: &[u8] = &hex!("64a65f3cdedcdd66811e2915");
    let signature_bytes: &[u8] = &hex!("7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00");

    let public_key = VerifyingKey::try_from(public_key_bytes).unwrap();
    let signature = Signature::try_from(signature_bytes).unwrap();
    assert!(public_key.verify(message, &signature).is_ok());
}
```

## API Documentation

You can find the API documentation at <https://codemonger-io.github.io/ed448-verifier/ed448_verifier/index.html>.

## Motivation

This crate was developed in the course of [my project](https://github.com/codemonger-io/webauthn-rs) where I am trying to remove the OpenSSL dependency from [`webauthn-rs`](https://github.com/kanidm/webauthn-rs).
As of November 23, 2024, there is no Ed448 verifier that implements the [`Verifier`](https://docs.rs/signature/2.2.0/signature/trait.Verifier.html) trait as far as I searched.
There is an unreleased crate [`ed448-signature`](https://github.com/RustCrypto/signatures/tree/master/ed448) maintained by [Rust Crypto](https://github.com/rustcrypto), but it is not intended to provide the actual curve implementation.

## License

While [`ed448-goldilocks` has no clear license](https://github.com/crate-crypto/Ed448-Goldilocks/pull/37), the original part of this crate is licensed under the [MIT license](./LICENSE).

## Acknowledgements

This crate was designed after [`ed22519-dalek`](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek).

The curve implementation is provided by [`ed448-goldilocks`](https://crates.io/crates/ed448-goldilocks).

The default [SHAKE256](https://en.wikipedia.org/wiki/SHA-3) implementation is provided by [`sha3`](https://crates.io/crates/sha3).

Test vectors for Ed448 verification were taken from [RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032).

Test vectors for SHAKE256 were downloaded from <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing>.