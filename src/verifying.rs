//! Ed448 verifier.
//!
//! ## Example
//!
//! ```
//! use ed448_verifier::{Signature, VerifyingKey};
//! use hex_literal::hex;
//! use signature::Verifier as _;
//!
//! // a test vector from RFC 8032
//! let public_key_bytes = hex!("3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580");
//! let message = hex!("64a65f3cdedcdd66811e2915");
//! let signature_bytes = hex!("7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00");
//!
//! let public_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
//! let signature = Signature::from_bytes(&signature_bytes).unwrap();
//! assert!(public_key.verify(&message, &signature).is_ok());
//! ```

#[cfg(feature = "digest")]
use digest::crypto_common::generic_array::typenum::U64;
use digest::{crypto_common::generic_array::typenum::U114, Digest};
use ed448_goldilocks::{
    curve::edwards::{CompressedEdwardsY, ExtendedPoint},
    Scalar,
};
#[cfg(all(feature = "sha3", feature = "digest"))]
use signature::DigestVerifier;
#[cfg(feature = "sha3")]
use signature::Verifier;

use crate::constants::{PUBLIC_KEY_LENGTH, SIGNATURE_LENGTH};
#[cfg(feature = "sha3")]
use crate::digest::Shake256U114;
#[cfg(all(feature = "sha3", feature = "digest"))]
use crate::digest::Shake256U64;
use crate::signature::{Signature, SignatureError};

/// Ed448 public key.
///
/// Optionally implements
/// - [`signature::Verifier`](https://docs.rs/signature/latest/signature/trait.Verifier.html):
///   if the "sha3" feature is enabled (default).
/// - [`signature::DigestVerifier`](https://docs.rs/signature/latest/signature/trait.DigestVerifier.html):
///   if the "sha3" and "digest" features are
///   enabled.
///
/// ## Example
///
/// Please see the [`verifying`][crate::verifying] module.
pub struct VerifyingKey {
    pub(crate) compressed: CompressedEdwardsY,
    pub(crate) point: ExtendedPoint,
}

impl VerifyingKey {
    /// Constructs a verifying key from a given byte slice.
    ///
    /// Fails if `bytes` is not 57 bytes long, or if `bytes` does not represent
    /// a valid point on the curve.
    #[inline]
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, SignatureError> {
        Self::from_owned_bytes(*bytes)
    }

    #[inline]
    pub(crate) fn from_owned_bytes(bytes: [u8; PUBLIC_KEY_LENGTH]) -> Result<Self, SignatureError> {
        let compressed = CompressedEdwardsY(bytes);
        let point = compressed
            .decompress()
            .ok_or_else(SignatureError::new)?;
        Ok(VerifyingKey { compressed, point })
    }

    /// Verifies a given signature for a specified message.
    ///
    /// As this function is intended to be internally used, please use
    /// [`VerifyingKey::verify`] instead unless you disable the "sha3" feature.
    #[allow(non_snake_case)]
    pub fn raw_verify<CtxDigest>(
        &self,
        context: Option<&[u8]>,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), SignatureError>
    where
        CtxDigest: Digest<OutputSize = U114>,
    {
        if context.is_some_and(|c| c.len() > 255) {
            // too long context
            return Err(SignatureError::new());
        }
        let expected_R = self.recompute_R::<CtxDigest>(false, context, signature, message);
        if expected_R.0 == signature.R.0 {
            Ok(())
        } else {
            Err(SignatureError::new())
        }
    }

    /// Verifies a given signature for a specified prehashed message.
    ///
    /// As this function is intended to be internally used, please use
    /// [`VerifyingKey::verify_digest`] instead unless you disable the "sha3"
    /// feature.
    #[cfg(feature = "digest")]
    #[allow(non_snake_case)]
    pub(crate) fn raw_verify_prehashed<CtxDigest, MsgDigest>(
        &self,
        context: Option<&[u8]>,
        prehashed_message: MsgDigest,
        signature: &Signature,
    ) -> Result<(), SignatureError>
    where
        CtxDigest: Digest<OutputSize = U114>,
        MsgDigest: Digest<OutputSize = U64>,
    {
        if context.is_some_and(|c| c.len() > 255) {
            // too long context
            return Err(SignatureError::new());
        }
        let message = prehashed_message.finalize();
        let expected_R = self.recompute_R::<CtxDigest>(true, context, signature, &message);
        if expected_R.0 == signature.R.0 {
            Ok(())
        } else {
            Err(SignatureError::new())
        }
    }

    #[allow(non_snake_case)]
    fn recompute_R<CtxDigest>(
        &self,
        prehashed: bool,
        context: Option<&[u8]>,
        signature: &Signature,
        M: &[u8],
    ) -> CompressedEdwardsY
    where
        CtxDigest: Digest<OutputSize = U114>,
    {
        let k = Self::compute_challenge::<CtxDigest>(
            prehashed,
            context,
            &signature.R,
            &self.compressed,
            M,
        );
        // calculates R = -[k]A + [s]B
        // Step 3 at https://datatracker.ietf.org/doc/html/rfc8032#section-5.2.7
        let minus_A: ExtendedPoint = -self.point;
        let k_a = minus_A.scalar_mul(&k);
        let s_B = ExtendedPoint::generator().scalar_mul(&signature.s);
        (k_a + s_B).compress()
    }

    #[allow(non_snake_case)]
    fn compute_challenge<CtxDigest>(
        prehashed: bool,
        context: Option<&[u8]>,
        R: &CompressedEdwardsY,
        A: &CompressedEdwardsY,
        M: &[u8],
    ) -> Scalar
    where
        CtxDigest: Digest<OutputSize = U114>,
    {
        let mut h = CtxDigest::new();
        // https://datatracker.ietf.org/doc/html/rfc8032#section-2
        // dom4(x, y) = "SigEd448" || octet(x) || octet(OLEN(y)) || y
        // where x = 0|1, and y = context
        h.update(b"SigEd448");
        h.update([if prehashed { 1 } else { 0 }]);
        if let Some(context) = context {
            h.update([context.len() as u8]);
            h.update(context);
        } else {
            h.update([0u8]);
        }

        h.update(R.0);
        h.update(A.0);
        h.update(M);

        let mut hash = [0u8; SIGNATURE_LENGTH];
        hash.copy_from_slice(h.finalize().as_slice());

        Scalar::from_bytes_mod_order_wide(&hash)
    }
}

#[cfg(feature = "sha3")]
impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &Signature) -> Result<(), SignatureError> {
        self.raw_verify::<Shake256U114>(None, msg, signature)
    }
}

#[cfg(all(feature = "sha3", feature = "digest"))]
impl DigestVerifier<Shake256U64, Signature> for VerifyingKey {
    fn verify_digest(
        &self,
        digest: Shake256U64,
        signature: &Signature,
    ) -> Result<(), SignatureError> {
        self.raw_verify_prehashed::<Shake256U114, Shake256U64>(None, digest, signature)
    }
}

impl TryFrom<&[u8]> for VerifyingKey {
    type Error = SignatureError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let bytes = bytes.try_into().map_err(|_| SignatureError::new())?;
        Self::from_owned_bytes(bytes)
    }
}

#[cfg(test)]
mod test {
    use hex_literal::hex;

    use super::*;

    // test vectors are taken from
    // https://datatracker.ietf.org/doc/html/rfc8032#section-7.4

    #[test]
    fn from_bytes() {
        assert!(VerifyingKey::from_bytes(&hex!(
            "5fd7449b59b461fd2ce787ec616ad46a
            1da1342485a70e1f8a0ea75d80e96778
            edf124769b46c7061bd6783df1e50f6c
            d1fa1abeafe8256180"
        ))
        .is_ok()); // TODO: check the point

        // obviously y > p = 2^448 - 2^224 - 1
        assert!(VerifyingKey::from_bytes(&hex!(
            "ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffffffffffffffffffff
            ffffffffffffffff80"
        ))
        .is_err());

        // TODO: case where y < p but x^2 has no root
    }

    #[test]
    fn try_from_u8_slice() {
        assert!(VerifyingKey::try_from(&hex!(
            "5fd7449b59b461fd2ce787ec616ad46a
            1da1342485a70e1f8a0ea75d80e96778
            edf124769b46c7061bd6783df1e50f6c
            d1fa1abeafe8256180"
        ) as &[u8])
        .is_ok()); // TODO: check the point

        // too short
        assert!(VerifyingKey::try_from(&hex!(
            "5fd7449b59b461fd2ce787ec616ad46a
            1da1342485a70e1f8a0ea75d80e96778
            edf124769b46c7061bd6783df1e50f6c
            d1fa1abeafe82580"
        ) as &[u8])
        .is_err());
        // too long
        assert!(VerifyingKey::try_from(&hex!(
            "5fd7449b59b461fd2ce787ec616ad46a
            1da1342485a70e1f8a0ea75d80e96778
            edf124769b46c7061bd6783df1e50f6c
            d1fa1abeafe825618000"
        ) as &[u8])
        .is_err());
    }
}

#[cfg(all(test, feature = "sha3"))]
mod test_sha3 {
    use hex_literal::hex;

    use super::*;

    // test vectors are taken from
    // https://datatracker.ietf.org/doc/html/rfc8032#section-7.4

    #[test]
    fn raw_verify_blank() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "5fd7449b59b461fd2ce787ec616ad46a
            1da1342485a70e1f8a0ea75d80e96778
            edf124769b46c7061bd6783df1e50f6c
            d1fa1abeafe8256180"
        ))
        .unwrap();
        let context = None;
        let message = hex!("");
        let signature = Signature::from_bytes(&hex!(
            "533a37f6bbe457251f023c0d88f976ae
            2dfb504a843e34d2074fd823d41a591f
            2b233f034f628281f2fd7a22ddd47d78
            28c59bd0a21bfd3980ff0d2028d4b18a
            9df63e006c5d1c2d345b925d8dc00b41
            04852db99ac5c7cdda8530a113a0f4db
            b61149f05a7363268c71d95808ff2e65
            2600"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());

        // bad public key
        let bad_public_key = VerifyingKey::from_bytes(&hex!(
            "43ba28f430cdff456ae531545f7ecd0a
            c834a55d9358c0372bfa0c6c6798c086
            6aea01eb00742802b8438ea4cb82169c
            235160627b4c3a9480"
        ))
        .unwrap();
        assert!(bad_public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_err());

        // bad signature
        let bad_signature = Signature::from_bytes(&hex!(
            "26b8f91727bd62897af15e41eb43c377
            efb9c610d48f2335cb0bd0087810f435
            2541b143c4b981b7e18f62de8ccdf633
            fc1bf037ab7cd779805e0dbcc0aae1cb
            cee1afb2e027df36bc04dcecbf154336
            c19f0af7e0a6472905e799f1953d2a0f
            f3348ab21aa4adafd1d234441cf807c0
            3a00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &bad_signature)
            .is_err());
    }

    #[test]
    fn raw_verify_1_octet() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "43ba28f430cdff456ae531545f7ecd0a
            c834a55d9358c0372bfa0c6c6798c086
            6aea01eb00742802b8438ea4cb82169c
            235160627b4c3a9480"
        ))
        .unwrap();
        let context = None;
        let message = hex!("03");
        let signature = Signature::from_bytes(&hex!(
            "26b8f91727bd62897af15e41eb43c377
            efb9c610d48f2335cb0bd0087810f435
            2541b143c4b981b7e18f62de8ccdf633
            fc1bf037ab7cd779805e0dbcc0aae1cb
            cee1afb2e027df36bc04dcecbf154336
            c19f0af7e0a6472905e799f1953d2a0f
            f3348ab21aa4adafd1d234441cf807c0
            3a00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());

        // bad public key
        let bad_public_key = VerifyingKey::from_bytes(&hex!(
            "5fd7449b59b461fd2ce787ec616ad46a
            1da1342485a70e1f8a0ea75d80e96778
            edf124769b46c7061bd6783df1e50f6c
            d1fa1abeafe8256180"
        ))
        .unwrap();
        assert!(bad_public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_err());

        // bad message
        let bad_message = hex!("04");
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &bad_message, &signature)
            .is_err());

        // bad signature
        let bad_signature = Signature::from_bytes(&hex!(
            "d4f8f6131770dd46f40867d6fd5d5055
            de43541f8c5e35abbcd001b32a89f7d2
            151f7647f11d8ca2ae279fb842d60721
            7fce6e042f6815ea000c85741de5c8da
            1144a6a1aba7f96de42505d7a7298524
            fda538fccbbb754f578c1cad10d54d0d
            5428407e85dcbc98a49155c13764e66c
            3c00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &bad_signature)
            .is_err());
    }

    #[test]
    fn raw_verify_1_octet_with_context() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "43ba28f430cdff456ae531545f7ecd0a
            c834a55d9358c0372bfa0c6c6798c086
            6aea01eb00742802b8438ea4cb82169c
            235160627b4c3a9480"
        ))
        .unwrap();
        let context: Option<&[u8]> = Some(&hex!("666f6f"));
        let message = hex!("03");
        let signature = Signature::from_bytes(&hex!(
            "d4f8f6131770dd46f40867d6fd5d5055
            de43541f8c5e35abbcd001b32a89f7d2
            151f7647f11d8ca2ae279fb842d60721
            7fce6e042f6815ea000c85741de5c8da
            1144a6a1aba7f96de42505d7a7298524
            fda538fccbbb754f578c1cad10d54d0d
            5428407e85dcbc98a49155c13764e66c
            3c00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());

        // bad context
        let bad_context: Option<&[u8]> = Some(&hex!("666f6e"));
        assert!(public_key
            .raw_verify::<Shake256U114>(bad_context, &message, &signature)
            .is_err());
    }

    #[test]
    fn raw_verify_11_octets() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "dcea9e78f35a1bf3499a831b10b86c90
            aac01cd84b67a0109b55a36e9328b1e3
            65fce161d71ce7131a543ea4cb5f7e9f
            1d8b00696447001400"
        ))
        .unwrap();
        let context = None;
        let message = hex!("0c3e544074ec63b0265e0c");
        let signature = Signature::from_bytes(&hex!(
            "1f0a8888ce25e8d458a21130879b840a
            9089d999aaba039eaf3e3afa090a09d3
            89dba82c4ff2ae8ac5cdfb7c55e94d5d
            961a29fe0109941e00b8dbdeea6d3b05
            1068df7254c0cdc129cbe62db2dc957d
            bb47b51fd3f213fb8698f064774250a5
            028961c9bf8ffd973fe5d5c206492b14
            0e00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());
    }

    #[test]
    fn raw_verify_12_octets() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "3ba16da0c6f2cc1f30187740756f5e79
            8d6bc5fc015d7c63cc9510ee3fd44adc
            24d8e968b6e46e6f94d19b945361726b
            d75e149ef09817f580"
        ))
        .unwrap();
        let context = None;
        let message = hex!("64a65f3cdedcdd66811e2915");
        let signature = Signature::from_bytes(&hex!(
            "7eeeab7c4e50fb799b418ee5e3197ff6
            bf15d43a14c34389b59dd1a7b1b85b4a
            e90438aca634bea45e3a2695f1270f07
            fdcdf7c62b8efeaf00b45c2c96ba457e
            b1a8bf075a3db28e5c24f6b923ed4ad7
            47c3c9e03c7079efb87cb110d3a99861
            e72003cbae6d6b8b827e4e6c143064ff
            3c00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());
    }

    #[test]
    fn raw_verify_13_octets() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "b3da079b0aa493a5772029f0467baebe
            e5a8112d9d3a22532361da294f7bb381
            5c5dc59e176b4d9f381ca0938e13c6c0
            7b174be65dfa578e80"
        ))
        .unwrap();
        let context = None;
        let message = hex!("64a65f3cdedcdd66811e2915e7");
        let signature = Signature::from_bytes(&hex!(
            "6a12066f55331b6c22acd5d5bfc5d712
            28fbda80ae8dec26bdd306743c5027cb
            4890810c162c027468675ecf645a8317
            6c0d7323a2ccde2d80efe5a1268e8aca
            1d6fbc194d3f77c44986eb4ab4177919
            ad8bec33eb47bbb5fc6e28196fd1caf5
            6b4e7e0ba5519234d047155ac727a105
            3100"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());
    }

    #[test]
    fn raw_verify_64_octets() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "df9705f58edbab802c7f8363cfe5560a
            b1c6132c20a9f1dd163483a26f8ac53a
            39d6808bf4a1dfbd261b099bb03b3fb5
            0906cb28bd8a081f00"
        ))
        .unwrap();
        let context = None;
        let message = hex!(
            "bd0f6a3747cd561bdddf4640a332461a
            4a30a12a434cd0bf40d766d9c6d458e5
            512204a30c17d1f50b5079631f64eb31
            12182da3005835461113718d1a5ef944"
        );
        let signature = Signature::from_bytes(&hex!(
            "554bc2480860b49eab8532d2a533b7d5
            78ef473eeb58c98bb2d0e1ce488a98b1
            8dfde9b9b90775e67f47d4a1c3482058
            efc9f40d2ca033a0801b63d45b3b722e
            f552bad3b4ccb667da350192b61c508c
            f7b6b5adadc2c8d9a446ef003fb05cba
            5f30e88e36ec2703b349ca229c267083
            3900"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());
    }

    #[test]
    fn raw_verify_256_octets() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "79756f014dcfe2079f5dd9e718be4171
            e2ef2486a08f25186f6bff43a9936b9b
            fe12402b08ae65798a3d81e22e9ec80e
            7690862ef3d4ed3a00"
        ))
        .unwrap();
        let context = None;
        let message = hex!(
            "15777532b0bdd0d1389f636c5f6b9ba7
            34c90af572877e2d272dd078aa1e567c
            fa80e12928bb542330e8409f31745041
            07ecd5efac61ae7504dabe2a602ede89
            e5cca6257a7c77e27a702b3ae39fc769
            fc54f2395ae6a1178cab4738e543072f
            c1c177fe71e92e25bf03e4ecb72f47b6
            4d0465aaea4c7fad372536c8ba516a60
            39c3c2a39f0e4d832be432dfa9a706a6
            e5c7e19f397964ca4258002f7c0541b5
            90316dbc5622b6b2a6fe7a4abffd9610
            5eca76ea7b98816af0748c10df048ce0
            12d901015a51f189f3888145c03650aa
            23ce894c3bd889e030d565071c59f409
            a9981b51878fd6fc110624dcbcde0bf7
            a69ccce38fabdf86f3bef6044819de11"
        );
        let signature = Signature::from_bytes(&hex!(
            "c650ddbb0601c19ca11439e1640dd931
            f43c518ea5bea70d3dcde5f4191fe53f
            00cf966546b72bcc7d58be2b9badef28
            743954e3a44a23f880e8d4f1cfce2d7a
            61452d26da05896f0a50da66a239a8a1
            88b6d825b3305ad77b73fbac0836ecc6
            0987fd08527c1a8e80d5823e65cafe2a
            3d00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());
    }

    #[test]
    fn raw_verify_1023_octets() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "a81b2e8a70a5ac94ffdbcc9badfc3feb
            0801f258578bb114ad44ece1ec0e799d
            a08effb81c5d685c0c56f64eecaef8cd
            f11cc38737838cf400"
        ))
        .unwrap();
        let context = None;
        let message = hex!(
            "6ddf802e1aae4986935f7f981ba3f035
            1d6273c0a0c22c9c0e8339168e675412
            a3debfaf435ed651558007db4384b650
            fcc07e3b586a27a4f7a00ac8a6fec2cd
            86ae4bf1570c41e6a40c931db27b2faa
            15a8cedd52cff7362c4e6e23daec0fbc
            3a79b6806e316efcc7b68119bf46bc76
            a26067a53f296dafdbdc11c77f7777e9
            72660cf4b6a9b369a6665f02e0cc9b6e
            dfad136b4fabe723d2813db3136cfde9
            b6d044322fee2947952e031b73ab5c60
            3349b307bdc27bc6cb8b8bbd7bd32321
            9b8033a581b59eadebb09b3c4f3d2277
            d4f0343624acc817804728b25ab79717
            2b4c5c21a22f9c7839d64300232eb66e
            53f31c723fa37fe387c7d3e50bdf9813
            a30e5bb12cf4cd930c40cfb4e1fc6225
            92a49588794494d56d24ea4b40c89fc0
            596cc9ebb961c8cb10adde976a5d602b
            1c3f85b9b9a001ed3c6a4d3b1437f520
            96cd1956d042a597d561a596ecd3d173
            5a8d570ea0ec27225a2c4aaff26306d1
            526c1af3ca6d9cf5a2c98f47e1c46db9
            a33234cfd4d81f2c98538a09ebe76998
            d0d8fd25997c7d255c6d66ece6fa56f1
            1144950f027795e653008f4bd7ca2dee
            85d8e90f3dc315130ce2a00375a318c7
            c3d97be2c8ce5b6db41a6254ff264fa6
            155baee3b0773c0f497c573f19bb4f42
            40281f0b1f4f7be857a4e59d416c06b4
            c50fa09e1810ddc6b1467baeac5a3668
            d11b6ecaa901440016f389f80acc4db9
            77025e7f5924388c7e340a732e554440
            e76570f8dd71b7d640b3450d1fd5f041
            0a18f9a3494f707c717b79b4bf75c984
            00b096b21653b5d217cf3565c9597456
            f70703497a078763829bc01bb1cbc8fa
            04eadc9a6e3f6699587a9e75c94e5bab
            0036e0b2e711392cff0047d0d6b05bd2
            a588bc109718954259f1d86678a579a3
            120f19cfb2963f177aeb70f2d4844826
            262e51b80271272068ef5b3856fa8535
            aa2a88b2d41f2a0e2fda7624c2850272
            ac4a2f561f8f2f7a318bfd5caf969614
            9e4ac824ad3460538fdc25421beec2cc
            6818162d06bbed0c40a387192349db67
            a118bada6cd5ab0140ee273204f628aa
            d1c135f770279a651e24d8c14d75a605
            9d76b96a6fd857def5e0b354b27ab937
            a5815d16b5fae407ff18222c6d1ed263
            be68c95f32d908bd895cd76207ae7264
            87567f9a67dad79abec316f683b17f2d
            02bf07e0ac8b5bc6162cf94697b3c27c
            d1fea49b27f23ba2901871962506520c
            392da8b6ad0d99f7013fbc06c2c17a56
            9500c8a7696481c1cd33e9b14e40b82e
            79a5f5db82571ba97bae3ad3e0479515
            bb0e2b0f3bfcd1fd33034efc6245eddd
            7ee2086ddae2600d8ca73e214e8c2b0b
            db2b047c6a464a562ed77b73d2d841c4
            b34973551257713b753632efba348169
            abc90a68f42611a40126d7cb21b58695
            568186f7e569d2ff0f9e745d0487dd2e
            b997cafc5abf9dd102e62ff66cba87"
        );
        let signature = Signature::from_bytes(&hex!(
            "e301345a41a39a4d72fff8df69c98075
            a0cc082b802fc9b2b6bc503f926b65bd
            df7f4c8f1cb49f6396afc8a70abe6d8a
            ef0db478d4c6b2970076c6a0484fe76d
            76b3a97625d79f1ce240e7c576750d29
            5528286f719b413de9ada3e8eb78ed57
            3603ce30d8bb761785dc30dbc320869e
            1a00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify::<Shake256U114>(context, &message, &signature)
            .is_ok());
    }

    #[cfg(feature = "digest")]
    #[test]
    fn raw_verify_prehashed_abc() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "259b71c19f83ef77a7abd26524cbdb31
            61b590a48f7d17de3ee0ba9c52beb743
            c09428a131d6b1b57303d90d8132c276
            d5ed3d5d01c0f53880"
        ))
        .unwrap();
        let context = None;
        let message = hex!("616263");
        let signature = Signature::from_bytes(&hex!(
            "822f6901f7480f3d5f562c592994d969
            3602875614483256505600bbc281ae38
            1f54d6bce2ea911574932f52a4e6cadd
            78769375ec3ffd1b801a0d9b3f4030cd
            433964b6457ea39476511214f97469b5
            7dd32dbc560a9a94d00bff07620464a3
            ad203df7dc7ce360c3cd3696d9d9fab9
            0f00"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify_prehashed::<Shake256U114, _>(
                context,
                Shake256U64::new_with_prefix(&message),
                &signature,
            )
            .is_ok());

        // bad public key
        let bad_public_key = VerifyingKey::from_bytes(&hex!(
            "a81b2e8a70a5ac94ffdbcc9badfc3feb
            0801f258578bb114ad44ece1ec0e799d
            a08effb81c5d685c0c56f64eecaef8cd
            f11cc38737838cf400"
        ))
        .unwrap();
        assert!(bad_public_key
            .raw_verify_prehashed::<Shake256U114, _>(
                context,
                Shake256U64::new_with_prefix(&message),
                &signature,
            )
            .is_err());

        // bad message
        let bad_message = hex!("616264");
        assert!(public_key
            .raw_verify_prehashed::<Shake256U114, _>(
                context,
                Shake256U64::new_with_prefix(&bad_message),
                &signature,
            )
            .is_err());

        // bad signature
        let bad_signature = Signature::from_bytes(&hex!(
            "c32299d46ec8ff02b54540982814dce9
            a05812f81962b649d528095916a2aa48
            1065b1580423ef927ecf0af5888f90da
            0f6a9a85ad5dc3f280d91224ba9911a3
            653d00e484e2ce232521481c8658df30
            4bb7745a73514cdb9bf3e15784ab7128
            4f8d0704a608c54a6b62d97beb511d13
            2100"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify_prehashed::<Shake256U114, _>(
                context,
                Shake256U64::new_with_prefix(&message),
                &bad_signature,
            )
            .is_err());
    }

    #[cfg(feature = "digest")]
    #[test]
    fn raw_verify_prehashed_abc_with_context() {
        let public_key = VerifyingKey::from_bytes(&hex!(
            "259b71c19f83ef77a7abd26524cbdb31
            61b590a48f7d17de3ee0ba9c52beb743
            c09428a131d6b1b57303d90d8132c276
            d5ed3d5d01c0f53880"
        ))
        .unwrap();
        let context: Option<&[u8]> = Some(&hex!("666f6f"));
        let message = hex!("616263");
        let signature = Signature::from_bytes(&hex!(
            "c32299d46ec8ff02b54540982814dce9
            a05812f81962b649d528095916a2aa48
            1065b1580423ef927ecf0af5888f90da
            0f6a9a85ad5dc3f280d91224ba9911a3
            653d00e484e2ce232521481c8658df30
            4bb7745a73514cdb9bf3e15784ab7128
            4f8d0704a608c54a6b62d97beb511d13
            2100"
        ))
        .unwrap();
        assert!(public_key
            .raw_verify_prehashed::<Shake256U114, _>(
                context,
                Shake256U64::new_with_prefix(&message),
                &signature,
            )
            .is_ok());

        // bad context
        let bad_context: Option<&[u8]> = Some(&hex!("666f6e"));
        assert!(public_key
            .raw_verify_prehashed::<Shake256U114, _>(
                bad_context,
                Shake256U64::new_with_prefix(&message),
                &signature,
            )
            .is_err());
    }
}
