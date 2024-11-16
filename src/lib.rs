//! A naïve implementation of Ed448 verifier.
//!
//! ## Introduction
//!
//! This library is not officially audited and reviewed.
//! Use it **AT YOUR OWN RISK**.
//!
//! This library wraps [`ed448-goldilocks`](https://docs.rs/ed448-goldilocks/latest/ed448_goldilocks/)
//! with an implementation of [`signature::Verifier`](https://docs.rs/signature/latest/signature/trait.Verifier.html).
//! [`VerifyingKey`].
//!
//! Most of the idea was taken from [`ed25519-dalek`](https://docs.rs/ed25519-dalek/latest/ed25519_dalek/index.html).

pub mod constants;
pub mod signature;
pub mod verifying;

pub use verifying::VerifyingKey;
