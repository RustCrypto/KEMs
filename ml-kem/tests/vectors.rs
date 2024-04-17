#![cfg(feature = "deterministic")]

use ::kem::Decapsulate;
use hybrid_array::Array;
use ml_kem::*;

pub struct GenerateVector {
    pub z: [u8; 32],
    pub d: [u8; 32],
    pub dk: &'static [u8],
    pub ek: &'static [u8],
}

impl GenerateVector {
    pub fn verify<K: KemCore>(&self) {
        let d = Array::from_slice(&self.d);
        let z = Array::from_slice(&self.z);
        let (dk, ek) = K::generate_deterministic(d, z);
        assert_eq!(dk.as_bytes().as_slice(), self.dk);
        assert_eq!(ek.as_bytes().as_slice(), self.ek);

        let dk_bytes = Encoded::<K::DecapsulationKey>::from_slice(self.dk);
        assert_eq!(dk, K::DecapsulationKey::from_bytes(dk_bytes));

        let ek_bytes = Encoded::<K::EncapsulationKey>::from_slice(self.ek);
        assert_eq!(ek, K::EncapsulationKey::from_bytes(ek_bytes));
    }
}

pub struct EncapsulateVector {
    pub ek: &'static [u8],
    pub m: [u8; 32],
    pub k: [u8; 32],
    pub c: &'static [u8],
}

impl EncapsulateVector {
    pub fn verify<K: KemCore>(&self) {
        let m = Array::from_slice(&self.m);
        let ek_bytes = Encoded::<K::EncapsulationKey>::from_slice(self.ek);
        let ek = K::EncapsulationKey::from_bytes(ek_bytes);
        let (c, k) = ek.encapsulate_deterministic(m).unwrap();
        assert_eq!(k.as_slice(), &self.k);
        assert_eq!(c.as_slice(), self.c);
    }
}

pub struct DecapsulateVector {
    pub dk: &'static [u8],
    pub c: &'static [u8],
    pub k: [u8; 32],
}

impl DecapsulateVector {
    pub fn verify<K: KemCore>(&self) {
        let dk_bytes = Encoded::<K::DecapsulationKey>::from_slice(self.dk);
        let dk = K::DecapsulationKey::from_bytes(dk_bytes);

        let c_bytes = Ciphertext::<K>::from_slice(self.c);
        let k = dk.decapsulate(c_bytes).unwrap();
        assert_eq!(k.as_slice(), &self.k);
    }
}
