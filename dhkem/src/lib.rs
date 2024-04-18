use kem::{Decapsulate, Encapsulate};
use rand_core::CryptoRngCore;

/// Newtype for a piece of data that may be encapsulated
pub struct Encapsulator<X>(X);
/// Newtype for a piece of data that may be decapsulated
pub struct Decapsulator<X>(X);
/// Newtype for a shared secret
pub struct SharedSecret<X>(X);
/// Newtype for an encapsulated key
pub struct EncapsulatedKey<X>(X);

#[cfg(test)]
pub trait SecretBytes {
    fn as_slice(&self) -> &[u8];
}

pub trait DhKem {
    type DecapsulatingKey: Decapsulate<Self::EncapsulatedKey, Self::SharedSecret>;
    type EncapsulatingKey: Encapsulate<Self::EncapsulatedKey, Self::SharedSecret>;
    type EncapsulatedKey;
    #[cfg(not(test))]
    type SharedSecret;

    #[cfg(test)]
    type SharedSecret: SecretBytes;

    fn random_keypair(
        rng: &mut impl CryptoRngCore,
    ) -> (Self::DecapsulatingKey, Self::EncapsulatingKey);
}

#[cfg(feature = "arithmetic")]
mod arithmetic;

#[cfg(feature = "x25519")]
mod x25519_kem;
#[cfg(feature = "x25519")]
pub use x25519_kem::X25519;

#[cfg(feature = "bign256")]
pub type BignP256 = arithmetic::ArithmeticKem<bign256::BignP256>;
#[cfg(feature = "k256")]
pub type Secp256k1 = arithmetic::ArithmeticKem<k256::Secp256k1>;
#[cfg(feature = "p192")]
pub type NistP192 = arithmetic::ArithmeticKem<p192::NistP192>;
#[cfg(feature = "p224")]
pub type NistP224 = arithmetic::ArithmeticKem<p224::NistP224>;
#[cfg(feature = "p256")]
pub type NistP256 = arithmetic::ArithmeticKem<p256::NistP256>;
// include an additional alias Secp256r1 = NistP256
#[cfg(feature = "p256")]
pub type Secp256r1 = arithmetic::ArithmeticKem<p256::NistP256>;
#[cfg(feature = "p384")]
pub type NistP384 = arithmetic::ArithmeticKem<p384::NistP384>;
#[cfg(feature = "p521")]
pub type NistP521 = arithmetic::ArithmeticKem<p521::NistP521>;
#[cfg(feature = "sm2")]
pub type Sm2 = arithmetic::ArithmeticKem<sm2::Sm2>;

#[cfg(test)]
mod tests;
