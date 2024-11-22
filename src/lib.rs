//! A naïve implementation of Ed448 verifier.
//!
//! ## Introduction
//!
//! This library has not been officially audited and reviewed.
//! Use it **AT YOUR OWN RISK**.
//!
//! This library wraps [`ed448-goldilocks`](https://docs.rs/ed448-goldilocks/latest/ed448_goldilocks/)
//! to provide the signature verification feature.
//! Please get started from looking at [`VerifyingKey`].
//!
//! Most of the design was taken from [`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/index.html).
//!
//! ## Features
//!
//! - `digest`: Implements [`signature::DigestVerifier`](https://docs.rs/signature/latest/signature/trait.DigestVerifier.html) for [`VerifyingKey`]
//! - `sha3`: Implements [`signature::Verifier`](https://docs.rs/signature/latest/signature/trait.Verifier.html),
//!   and optionally [`signature::DigestVerifier`](https://docs.rs/signature/latest/signature/trait.DigestVerifier.html),
//!   for [`VerifyingKey`] using [`sha3::Shake256`](https://docs.rs/sha3/latest/sha3/type.Shake256.html).
//!   This feature is **enabled by default**.

pub mod constants;
pub mod digest;
pub mod signature;
pub mod verifying;

pub use signature::Signature;
pub use verifying::VerifyingKey;
