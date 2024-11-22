//! Adapter for extendable output functions (XOFs) to make them
//! [`Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) with
//! a fixed output size.
//!
//! Unless you disable the "sha3" feature, the following type aliases are
//! defined for your convenience:
//! - [`Shake256U114`]: core hash function for Ed448
//! - [`Shake256U64`]: function for prehash calculation for Ed448

#[cfg(feature = "sha3")]
use digest::crypto_common::generic_array::typenum::{U114, U64};
use digest::{
    crypto_common::generic_array::ArrayLength, Digest, ExtendableOutput, FixedOutput,
    FixedOutputReset, Output, OutputSizeUser, Reset, Update, XofReader,
};
use std::marker::PhantomData;

/// Adapter for an extendable output function (XOF) to make it a
/// [`Digest`](https://docs.rs/digest/latest/digest/trait.Digest.html) with
/// a fixed output size.
pub struct XofDigest<T, OutputSize>
where
    T: ExtendableOutput,
    OutputSize: ArrayLength<u8> + 'static,
{
    xof: T,
    _output_size: PhantomData<OutputSize>,
}

impl<T, OutputSize> XofDigest<T, OutputSize>
where
    T: ExtendableOutput,
    OutputSize: ArrayLength<u8> + 'static,
{
    /// Makes a given XOF a [`Digest`].
    pub fn from_xof(xof: T) -> Self {
        Self {
            xof,
            _output_size: PhantomData,
        }
    }
}

impl<T, OutputSize> Digest for XofDigest<T, OutputSize>
where
    T: ExtendableOutput + Update + Default,
    OutputSize: ArrayLength<u8> + 'static,
{
    fn new() -> Self {
        Self {
            xof: T::default(),
            _output_size: PhantomData,
        }
    }

    fn new_with_prefix(data: impl AsRef<[u8]>) -> Self {
        let mut xof = T::default();
        xof.update(data.as_ref());
        Self {
            xof,
            _output_size: PhantomData,
        }
    }

    fn update(&mut self, data: impl AsRef<[u8]>) {
        <Self as Update>::update(self, data.as_ref());
        // self.xof.update(data.as_ref());
    }

    fn chain_update(mut self, data: impl AsRef<[u8]>) -> Self {
        Digest::update(&mut self, data);
        self
    }

    fn finalize(self) -> Output<Self> {
        let mut output = Output::<Self>::default();
        self.xof.finalize_xof().read(output.as_mut());
        output
    }

    fn finalize_into(self, out: &mut Output<Self>) {
        <Self as FixedOutput>::finalize_into(self, out);
        // self.xof.finalize_xof().read(out.as_mut());
    }

    fn finalize_reset(&mut self) -> Output<Self> {
        let xof = std::mem::take(&mut self.xof);
        let mut output = Output::<Self>::default();
        xof.finalize_xof().read(output.as_mut());
        output
    }

    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        let xof = std::mem::take(&mut self.xof);
        xof.finalize_xof().read(out.as_mut());
    }

    fn reset(&mut self) {
        <Self as Reset>::reset(self);
    }

    fn output_size() -> usize {
        OutputSize::to_usize()
    }

    fn digest(data: impl AsRef<[u8]>) -> Output<Self> {
        Self::new_with_prefix(data).finalize()
    }
}

impl<T, OutputSize> Update for XofDigest<T, OutputSize>
where
    T: ExtendableOutput + Update,
    OutputSize: ArrayLength<u8> + 'static,
{
    fn update(&mut self, data: &[u8]) {
        self.xof.update(data.as_ref());
    }
}

impl<T, OutputSize> Reset for XofDigest<T, OutputSize>
where
    T: ExtendableOutput + Default,
    OutputSize: ArrayLength<u8> + 'static,
{
    fn reset(&mut self) {
        self.xof = T::default();
    }
}

impl<T, OutputSize> FixedOutput for XofDigest<T, OutputSize>
where
    T: ExtendableOutput,
    OutputSize: ArrayLength<u8> + 'static,
{
    fn finalize_into(self, out: &mut Output<Self>) {
        self.xof.finalize_xof().read(out.as_mut());
    }
}

impl<T, OutputSize> FixedOutputReset for XofDigest<T, OutputSize>
where
    T: ExtendableOutput + Default,
    OutputSize: ArrayLength<u8> + 'static,
{
    fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
        <Self as Digest>::finalize_into_reset(self, out);
    }
}

impl<T, OutputSize> OutputSizeUser for XofDigest<T, OutputSize>
where
    T: ExtendableOutput,
    OutputSize: ArrayLength<u8> + 'static,
{
    type OutputSize = OutputSize;
}

/// Digest for Ed448.
#[cfg(feature = "sha3")]
pub type Shake256U114 = XofDigest<sha3::Shake256, U114>;

/// Prehash function for Ed448.
#[cfg(feature = "sha3")]
pub type Shake256U64 = XofDigest<sha3::Shake256, U64>;

#[cfg(all(test, feature = "sha3"))]
mod test {
    use super::*;

    use hex_literal::hex;

    // test vectors are downloaded from
    // https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing

    #[test]
    fn new_update_finalize() {
        // output size: 64 bytes
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        let mut digest = Shake256U64::new();
        Digest::update(&mut digest, input);
        assert_eq!(digest.finalize().as_slice(), output);

        // output size: 114 bytes
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        let mut digest = Shake256U114::new();
        Digest::update(&mut digest, input);
        assert_eq!(digest.finalize().as_slice(), output);
    }

    #[test]
    fn new_update_update_finalize() {
        // output size: 64 bytes
        let input = hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        let mut digest = Shake256U64::new();
        Digest::update(&mut digest, &input[0..16]);
        Digest::update(&mut digest, &input[16..]);
        assert_eq!(digest.finalize().as_slice(), output);

        // output size: 114 bytes
        let input = hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        let mut digest = Shake256U114::new();
        Digest::update(&mut digest, &input[0..16]);
        Digest::update(&mut digest, &input[16..]);
        assert_eq!(digest.finalize().as_slice(), output);
    }

    #[test]
    fn new_chain_update_finalize() {
        // output size: 64 bytes
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        assert_eq!(
            Shake256U64::new().chain_update(input).finalize().as_slice(),
            output,
        );

        // output size: 114 bytes
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        assert_eq!(
            Shake256U114::new()
                .chain_update(input)
                .finalize()
                .as_slice(),
            output,
        );
    }

    #[test]
    fn prefix_finalize() {
        // output size: 64 bytes
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        assert_eq!(
            Shake256U64::new_with_prefix(input).finalize().as_slice(),
            output
        );

        // output size: 114 bytes
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        assert_eq!(
            Shake256U114::new_with_prefix(input).finalize().as_slice(),
            output
        );
    }

    #[test]
    fn prefix_finalize_into() {
        // output size: 64 bytes
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let expected_output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        let mut output = Output::<Shake256U64>::default();
        Digest::finalize_into(Shake256U64::new_with_prefix(input), &mut output);
        assert_eq!(output.as_slice(), expected_output);

        // output size: 114 bytes
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let expected_output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        let mut output = Output::<Shake256U114>::default();
        Digest::finalize_into(Shake256U114::new_with_prefix(input), &mut output);
        assert_eq!(output.as_slice(), expected_output);
    }

    #[test]
    fn prefix_reset_update_finalize() {
        // output size: 64 bytes
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        let mut digest = Shake256U64::new_with_prefix(hex!("012345"));
        Digest::reset(&mut digest);
        Digest::update(&mut digest, input);
        assert_eq!(digest.finalize().as_slice(), output);

        // output size: 114 bytes
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        let mut digest = Shake256U114::new_with_prefix(hex!("012345"));
        Digest::reset(&mut digest);
        Digest::update(&mut digest, input);
        assert_eq!(digest.finalize().as_slice(), output);
    }

    #[test]
    fn prefix_reset_update_finalize_into() {
        // output size: 64 bytes
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let expected_output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        let mut digest = Shake256U64::new_with_prefix(hex!("012345"));
        Digest::reset(&mut digest);
        Digest::update(&mut digest, input);
        let mut output = Output::<Shake256U64>::default();
        Digest::finalize_into(digest, &mut output);
        assert_eq!(output.as_slice(), expected_output);

        // output size: 114 bytes
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let expected_output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        let mut digest = Shake256U114::new_with_prefix(hex!("012345"));
        Digest::reset(&mut digest);
        Digest::update(&mut digest, input);
        let mut output = Output::<Shake256U114>::default();
        Digest::finalize_into(digest, &mut output);
        assert_eq!(output.as_slice(), expected_output);
    }

    #[test]
    fn prefix_finalize_reset_update_finalize() {
        // output size: 64 bytes
        let input = &hex!("76891a7bcc6c04490035b743152f64a8dd2ea18ab472b8d36ecf45858d0b0046");
        let output = hex!("e8447df87d01beeb724c9a2a38ab00fcc24e9bd17860e673b021222d621a7810e5d3dcead3f6b72810ff1ad242bf79074d2fd63503cbe7a2ffe81b1c57566568");
        let mut digest = Shake256U64::new_with_prefix(input);
        assert_eq!(digest.finalize_reset().as_slice(), output);
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        Digest::update(&mut digest, input);
        assert_eq!(digest.finalize().as_slice(), output);

        // output size: 114 bytes
        let input = &hex!("445b17ce13727ae842b877c4750611a9eb79823bc5752da0a5e9d4e27bd40b94");
        let output = hex!("e7708cdc22f03b0bfaca03e5d11d46cac118fded60b64bf4acffb35b0b474fbe85d270e625b95d54157d6597eb4fbdfa482e636d4a44c9de13c71387654c1a254a85063dd7720ffd5c6fc50ab97914c67ce6f0da5ae14ec0f2c5cdad79c4d85415279d21e236519dc1422c5b6dd156ffe432");
        let mut digest = Shake256U114::new_with_prefix(input);
        assert_eq!(digest.finalize_reset().as_slice(), output);
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        Digest::update(&mut digest, input);
        assert_eq!(digest.finalize().as_slice(), output);
    }

    #[test]
    fn prefix_finalize_into_reset_update_finalize() {
        // output size: 64 bytes
        let input = &hex!("76891a7bcc6c04490035b743152f64a8dd2ea18ab472b8d36ecf45858d0b0046");
        let expected_output = hex!("e8447df87d01beeb724c9a2a38ab00fcc24e9bd17860e673b021222d621a7810e5d3dcead3f6b72810ff1ad242bf79074d2fd63503cbe7a2ffe81b1c57566568");
        let mut digest = Shake256U64::new_with_prefix(input);
        let mut output = Output::<Shake256U64>::default();
        Digest::finalize_into_reset(&mut digest, &mut output);
        assert_eq!(output.as_slice(), expected_output);
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let expected_output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        Digest::update(&mut digest, input);
        assert_eq!(digest.finalize().as_slice(), expected_output);

        // output size: 114 bytes
        let input = &hex!("445b17ce13727ae842b877c4750611a9eb79823bc5752da0a5e9d4e27bd40b94");
        let expected_output = hex!("e7708cdc22f03b0bfaca03e5d11d46cac118fded60b64bf4acffb35b0b474fbe85d270e625b95d54157d6597eb4fbdfa482e636d4a44c9de13c71387654c1a254a85063dd7720ffd5c6fc50ab97914c67ce6f0da5ae14ec0f2c5cdad79c4d85415279d21e236519dc1422c5b6dd156ffe432");
        let mut digest = Shake256U114::new_with_prefix(input);
        let mut output = Output::<Shake256U114>::default();
        Digest::finalize_into_reset(&mut digest, &mut output);
        assert_eq!(output.as_slice(), expected_output);
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let expected_output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        Digest::update(&mut digest, input);
        assert_eq!(digest.finalize().as_slice(), expected_output);
    }

    #[test]
    fn output_size() {
        assert_eq!(<Shake256U64 as Digest>::output_size(), 64);
        assert_eq!(<Shake256U114 as Digest>::output_size(), 114);
    }

    #[test]
    fn digest() {
        // output size: 64 bytes
        let input = &hex!("e3ef127eadfafaf40408cebb28705df30b68d99dfa1893507ef3062d85461715");
        let output = hex!("7314002948c057006d4fc21e3e19c258fb5bdd57728fe93c9c6ef265b6d9f559ca73da32c427e135ba0db900d9003b19c9cf116f542a760418b1a435ac75ed5a");
        assert_eq!(Shake256U64::digest(input).as_slice(), output);

        // output size: 114 bytes
        let input = &hex!("dc886df3f69c49513de3627e9481db5871e8ee88eb9f99611541930a8bc885e0");
        let output = hex!("00648afbc5e651649db1fd82936b00dbbc122fb4c877860d385c4950d56de7e096d613d7a3f27ed8f26334b0ccc1407b41dccb23dfaa529818d1125cd5348092524366b85fabb97c6cd1e6066f459bcc566da87ec9b7ba36792d118ac39a4ccef6192bbf3a54af18e57b0c146101f6aeaa82");
        assert_eq!(Shake256U114::digest(input).as_slice(), output)
    }
}
