//! Ed448 signature.
//!
//! [`Signature`] was taken from [`ed448-signature`](https://github.com/RustCrypto/signatures/blob/85c984bcc9927c2ce70c7e15cbfe9c6936dd3521/ed448/src/lib.rs#L98-L99)
//! which is not released yet (as of November 19, 2024).

use ed448_goldilocks::{
    curve::edwards::CompressedEdwardsY,
    Scalar,
};

use crate::constants::SIGNATURE_LENGTH;

/// Signature error.
pub type SignatureError = signature::Error;

/// Ed448 signature.
#[allow(non_snake_case)]
pub struct Signature {
    pub(crate) R: CompressedEdwardsY,
    pub(crate) s: Scalar,
}

impl Signature {
    /// Creates a signature from a byte array.
    ///
    /// Fails if the byte representation of a scalar is not canonical.
    #[inline]
    #[allow(non_snake_case)]
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Result<Signature, SignatureError> {
        let mut R_bytes: [u8; 57] = [0u8; 57];
        let mut s_bytes: [u8; 57] = [0u8; 57];
        R_bytes.copy_from_slice(&bytes[0..57]);
        s_bytes.copy_from_slice(&bytes[57..114]);

        Ok(Signature {
            R: CompressedEdwardsY(R_bytes),
            s: check_scalar(s_bytes)?,
        })
    }
}

// Checks a scalar bytes and returns a scalar if it is canonical.
#[inline(always)]
fn check_scalar(bytes: [u8; 57]) -> Result<Scalar, SignatureError> {
    match Scalar::from_canonical_bytes(bytes) {
        None => Err(SignatureError::new()),
        Some(x) => Ok(x),
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use super::*;

    #[test]
    fn signature_from_bytes() {
        // https://datatracker.ietf.org/doc/html/rfc8032#section-7.4
        let bytes_vec = hex!("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");
        let mut bytes: [u8; SIGNATURE_LENGTH] = [0u8; SIGNATURE_LENGTH];
        bytes.copy_from_slice(&bytes_vec);
        assert!(Signature::from_bytes(&bytes).is_ok());
    }
}
