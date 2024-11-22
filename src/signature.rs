//! Ed448 signature.
//!
//! ## Example
//!
//! ```
//! use ed448_verifier::Signature;
//! use hex_literal::hex;
//!
//! // a test vector from RFC 8032
//! let signature_bytes = hex!("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");
//! let signature = Signature::from_bytes(&signature_bytes).unwrap();
//! ```

use ed448_goldilocks::{
    curve::edwards::CompressedEdwardsY,
    Scalar,
};

use crate::constants::SIGNATURE_LENGTH;

/// Signature error.
pub type SignatureError = signature::Error;

/// Ed448 signature.
///
///
/// ## Example
///
/// Please see the [`signature`][crate::signature] module.
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
    pub fn from_bytes(bytes: &[u8; SIGNATURE_LENGTH]) -> Result<Self, SignatureError> {
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

impl TryFrom<&[u8]> for Signature {
    type Error = SignatureError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes.try_into().map_err(|_| SignatureError::new())?;
        Self::from_bytes(&bytes)
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
        let bytes = hex!("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");
        assert!(Signature::from_bytes(&bytes).is_ok());
    }

    #[test]
    fn try_from_u8_slice() {
        // OK - https://datatracker.ietf.org/doc/html/rfc8032#section-7.4
        let bytes: &[u8] = &hex!("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");
        assert!(Signature::try_from(bytes).is_ok());

        // Bad - short by 1
        assert!(Signature::try_from(&bytes[2..]).is_err());

        // Bad - long by 1
        let bytes: &[u8] = &hex!("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600ab");
        assert!(Signature::try_from(bytes).is_err());
    }
}
