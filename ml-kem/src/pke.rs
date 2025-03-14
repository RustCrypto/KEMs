use hybrid_array::typenum::{U1, Unsigned};

use crate::algebra::{NttMatrix, NttVector, Polynomial, PolynomialVector};
use crate::compress::Compress;
use crate::crypto::{G, PRF};
use crate::encode::Encode;
use crate::param::{EncodedCiphertext, EncodedDecryptionKey, EncodedEncryptionKey, PkeParams};
use crate::util::B32;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// A `DecryptionKey` provides the ability to generate a new key pair, and decrypt an
/// encrypted value.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct DecryptionKey<P>
where
    P: PkeParams,
{
    s_hat: NttVector<P::K>,
}

#[cfg(feature = "zeroize")]
impl<P> Zeroize for DecryptionKey<P>
where
    P: PkeParams,
{
    fn zeroize(&mut self) {
        self.s_hat.zeroize();
    }
}

impl<P> DecryptionKey<P>
where
    P: PkeParams,
{
    /// Generate a new random decryption key according to the `K-PKE.KeyGen` procedure.
    // Algorithm 12. K-PKE.KeyGen()
    pub fn generate(d: &B32) -> (Self, EncryptionKey<P>) {
        // Generate random seeds
        let k = P::K::U8;
        let (rho, sigma) = G(&[&d[..], &[k]]);

        // Sample pseudo-random matrix and vectors
        let A_hat: NttMatrix<P::K> = NttMatrix::sample_uniform(&rho, false);
        let s: PolynomialVector<P::K> = PolynomialVector::sample_cbd::<P::Eta1>(&sigma, 0);
        let e: PolynomialVector<P::K> = PolynomialVector::sample_cbd::<P::Eta1>(&sigma, P::K::U8);

        // NTT the vectors
        let s_hat = s.ntt();
        let e_hat = e.ntt();

        // Compute the public value
        let t_hat = &(&A_hat * &s_hat) + &e_hat;

        // Assemble the keys
        let dk = DecryptionKey { s_hat };
        let ek = EncryptionKey { t_hat, rho };
        (dk, ek)
    }

    /// Decrypt ciphertext to obtain the encrypted value, according to the K-PKE.Decrypt procedure.
    // Algorithm 14. kK-PKE.Decrypt(dk_PKE, c)
    pub fn decrypt(&self, ciphertext: &EncodedCiphertext<P>) -> B32 {
        let (c1, c2) = P::split_ct(ciphertext);

        let mut u: PolynomialVector<P::K> = Encode::<P::Du>::decode(c1);
        u.decompress::<P::Du>();

        let mut v: Polynomial = Encode::<P::Dv>::decode(c2);
        v.decompress::<P::Dv>();

        let u_hat = u.ntt();
        let sTu = (&self.s_hat * &u_hat).ntt_inverse();
        let mut w = &v - &sTu;
        Encode::<U1>::encode(w.compress::<U1>())
    }

    /// Represent this decryption key as a byte array `(s_hat)`
    pub fn as_bytes(&self) -> EncodedDecryptionKey<P> {
        P::encode_u12(&self.s_hat)
    }

    /// Parse an decryption key from a byte array `(s_hat)`
    pub fn from_bytes(enc: &EncodedDecryptionKey<P>) -> Self {
        let s_hat = P::decode_u12(enc);
        Self { s_hat }
    }
}

/// An `EncryptionKey` provides the ability to encrypt a value so that it can only be
/// decrypted by the holder of the corresponding decapsulation key.
#[derive(Clone, Default, Debug, PartialEq)]
pub struct EncryptionKey<P>
where
    P: PkeParams,
{
    t_hat: NttVector<P::K>,
    rho: B32,
}

impl<P> EncryptionKey<P>
where
    P: PkeParams,
{
    /// Encrypt the specified message for the holder of the corresponding decryption key, using the
    /// provided randomness, according the `K-PKE.Encrypt` procedure.
    pub fn encrypt(&self, message: &B32, randomness: &B32) -> EncodedCiphertext<P> {
        let r = PolynomialVector::<P::K>::sample_cbd::<P::Eta1>(randomness, 0);
        let e1 = PolynomialVector::<P::K>::sample_cbd::<P::Eta2>(randomness, P::K::U8);

        let prf_output = PRF::<P::Eta2>(randomness, 2 * P::K::U8);
        let e2: Polynomial = Polynomial::sample_cbd::<P::Eta2>(&prf_output);

        let A_hat_t = NttMatrix::<P::K>::sample_uniform(&self.rho, true);
        let r_hat: NttVector<P::K> = r.ntt();
        let ATr: PolynomialVector<P::K> = (&A_hat_t * &r_hat).ntt_inverse();
        let mut u = ATr + e1;

        let mut mu: Polynomial = Encode::<U1>::decode(message);
        mu.decompress::<U1>();

        let tTr: Polynomial = (&self.t_hat * &r_hat).ntt_inverse();
        let mut v = &(&tTr + &e2) + &mu;

        let c1 = Encode::<P::Du>::encode(u.compress::<P::Du>());
        let c2 = Encode::<P::Dv>::encode(v.compress::<P::Dv>());
        P::concat_ct(c1, c2)
    }

    /// Represent this encryption key as a byte array `(t_hat || rho)`
    pub fn as_bytes(&self) -> EncodedEncryptionKey<P> {
        let t_hat = P::encode_u12(&self.t_hat);
        P::concat_ek(t_hat, self.rho.clone())
    }

    /// Parse an encryption key from a byte array `(t_hat || rho)`
    pub fn from_bytes(enc: &EncodedEncryptionKey<P>) -> Self {
        let (t_hat, rho) = P::split_ek(enc);
        let t_hat = P::decode_u12(t_hat);
        Self {
            t_hat,
            rho: rho.clone(),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::crypto::rand;
    use crate::{MlKem512Params, MlKem768Params, MlKem1024Params};

    fn round_trip_test<P>()
    where
        P: PkeParams,
    {
        let mut rng = rand::rng();
        let d: B32 = rand(&mut rng);
        let original = B32::default();
        let randomness = B32::default();

        let (dk, ek) = DecryptionKey::<P>::generate(&d);
        let encrypted = ek.encrypt(&original, &randomness);
        let decrypted = dk.decrypt(&encrypted);
        assert_eq!(original, decrypted);
    }

    #[test]
    fn round_trip() {
        round_trip_test::<MlKem512Params>();
        round_trip_test::<MlKem768Params>();
        round_trip_test::<MlKem1024Params>();
    }

    fn codec_test<P>()
    where
        P: PkeParams,
    {
        let mut rng = rand::rng();
        let d: B32 = rand(&mut rng);
        let (dk_original, ek_original) = DecryptionKey::<P>::generate(&d);

        let dk_encoded = dk_original.as_bytes();
        let dk_decoded = DecryptionKey::from_bytes(&dk_encoded);
        assert_eq!(dk_original, dk_decoded);

        let ek_encoded = ek_original.as_bytes();
        let ek_decoded = EncryptionKey::from_bytes(&ek_encoded);
        assert_eq!(ek_original, ek_decoded);
    }

    #[test]
    fn codec() {
        codec_test::<MlKem512Params>();
        codec_test::<MlKem768Params>();
        codec_test::<MlKem1024Params>();
    }
}
