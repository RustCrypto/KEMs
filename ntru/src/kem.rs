use crate::encoded::AsymEnc;
use crate::hashes::{hash_prefix, HashOps};
use alloc::vec::Vec;
use hybrid_array::{typenum::Unsigned, Array};
use rand_core::CryptoRngCore;
pub struct PublicKey<Params: AsymEnc>(pub Array<u8, Params::PublicKeyBytes>);

pub struct SecretKey<Params: AsymEnc> {
    sk: Array<u8, Params::SecretKeyBytes>,
    pk: Array<u8, Params::PublicKeyBytes>,
    rand: Array<u8, Params::InputsBytes>,
    digest: [u8; 32],
}
pub struct CihpherText<Params: AsymEnc> {
    c: Array<u8, Params::CipherTextBytes>,
    cache: [u8; 32],
}

impl<T: AsymEnc> CihpherText<T> {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.c);
        bytes.extend_from_slice(&self.cache);
        bytes
    }
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let c = bytes[..T::CipherTextBytes::USIZE].try_into().unwrap();
        let cache = bytes[T::CipherTextBytes::USIZE..].try_into().unwrap();
        CihpherText { c, cache }
    }
}

impl<T: AsymEnc> SecretKey<T> {
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.sk);
        bytes.extend_from_slice(&self.pk);
        bytes.extend_from_slice(&self.rand);
        bytes.extend_from_slice(&self.digest);
        bytes
    }
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut start = 0;
        let sk = bytes[start..T::SecretKeyBytes::USIZE].try_into().unwrap();
        start += T::SecretKeyBytes::USIZE;
        let pk = bytes[start..start + T::PublicKeyBytes::USIZE]
            .try_into()
            .unwrap();
        start += T::PublicKeyBytes::USIZE;
        let rand = bytes[start..start + T::InputsBytes::USIZE]
            .try_into()
            .unwrap();
        start += T::InputsBytes::USIZE;
        let digest = bytes[start..start + 32].try_into().unwrap();
        SecretKey {
            sk,
            pk,
            rand,
            digest,
        }
    }
}
pub fn key_gen<Params: AsymEnc + AsymEnc>(
    rng: &mut impl CryptoRngCore,
) -> (SecretKey<Params>, PublicKey<Params>) {
    let (sk, pk) = Params::key_gen(rng);
    let mut rand = Array::default();
    rng.fill_bytes(&mut rand);
    let digest = hash_prefix(4, &pk);
    (
        SecretKey {
            sk,
            pk: pk.clone(),
            rand,
            digest,
        },
        PublicKey(pk),
    )
}
fn hide<Params: AsymEnc + AsymEnc + HashOps>(
    r: &Params::Inputs,
    pk: &Array<u8, Params::PublicKeyBytes>,
    cache: &[u8; 32],
) -> (CihpherText<Params>, Array<u8, Params::InputsBytes>) {
    let mut r_enc = Array::default();
    Params::inputs_encode(r, &mut r_enc);
    let c = Params::encrypt(r, pk);
    let cache = Params::hash_confirm::<Params>(&r_enc, cache);
    (CihpherText { c, cache }, r_enc)
}

pub fn encap<Params: AsymEnc + AsymEnc + HashOps>(
    rng: &mut impl CryptoRngCore,
    pk: &PublicKey<Params>,
) -> (CihpherText<Params>, [u8; 32]) {
    let r = Params::inputs_random(rng);
    let cache = hash_prefix(4, &pk.0);
    let (c, r_enc) = hide::<Params>(&r, &pk.0, &cache);
    let parts: &[&[u8]] = &[&r_enc, &c.c, &c.cache];
    let k = Params::hash_session(1, parts);
    (c, k)
}

fn ciphertext_diff_mask(c: &[u8], c2: &[u8]) -> i32 {
    debug_assert_eq!(c.len(), c2.len());
    let mut differentbits = 0u16;
    for i in 0..c.len() {
        differentbits |= (c[i] ^ c2[i]) as u16;
    }
    (1 & ((differentbits as i32 - 1) >> 8)) - 1
}

pub fn decap<Params: AsymEnc + HashOps>(
    c: &CihpherText<Params>,
    sk: &SecretKey<Params>,
) -> [u8; 32] {
    let r = Params::decrypt(&c.c, &sk.sk);
    let (cnew, mut r_enc) = hide::<Params>(&r, &sk.pk, &sk.digest);
    let mask = ciphertext_diff_mask(&c.c, &cnew.c) as u8;
    for i in 0..Params::InputsBytes::USIZE {
        r_enc[i] ^= (mask as u8) & (r_enc[i] ^ sk.rand[i]);
    }
    let parts: &[&[u8]] = &[&r_enc, &c.c, &c.cache];
    Params::hash_session(mask.wrapping_add(1), parts)
}
