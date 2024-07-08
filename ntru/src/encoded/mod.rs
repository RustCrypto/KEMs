mod encoding;
mod streamlined;

use crate::params::NtruCommon;
use hybrid_array::Array;
use rand_core::CryptoRngCore;

pub trait AsymEnc: NtruCommon + Sized {
    type Inputs;
    fn key_gen(
        rng: &mut impl CryptoRngCore,
    ) -> (
        Array<u8, Self::SecretKeyBytes>,
        Array<u8, Self::PublicKeyBytes>,
    );
    fn decrypt(
        c: &Array<u8, Self::CipherTextBytes>,
        sk: &Array<u8, Self::SecretKeyBytes>,
    ) -> Self::Inputs;
    fn encrypt(
        r: &Self::Inputs,
        pk: &Array<u8, Self::PublicKeyBytes>,
    ) -> Array<u8, Self::CipherTextBytes>;
    fn inputs_encode(f: &Self::Inputs, out: &mut [u8]);
    fn inputs_random(rng: &mut impl CryptoRngCore) -> Self::Inputs;
}
