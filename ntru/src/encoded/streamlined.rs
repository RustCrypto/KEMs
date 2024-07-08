use super::{
    encoding::{decode, encode},
    AsymEnc,
};
use crate::{
    algebra::{f3::Small, fq::Fq, r3::R3, rq::Rq},
    core::streamlined,
    params::{NtruCommon, Streamlined, StreamlinedNtru},
};
use hybrid_array::Array;
use hybrid_array::{typenum::Unsigned, ArraySize};
use rand_core::CryptoRngCore;

#[allow(non_snake_case)]
fn rq_encode<Params: NtruCommon>(r: &Rq<Params>, out: &mut [u8]) {
    let mut R: Array<u16, Params::P> = Array::default();
    let mut M: Array<u16, Params::P> = Array::default();
    for i in 0..Params::P::USIZE {
        R[i] = (*r.0[i] as u16).wrapping_add(Params::Q12);
    }
    for i in 0..Params::P::USIZE {
        M[i] = Params::Q;
    }
    encode(&R, &M, out);
}
#[allow(non_snake_case)]
fn rq_decode<Params: NtruCommon + StreamlinedNtru>(
    s: &Array<u8, Params::PublicKeyBytes>,
) -> Rq<Params> {
    let mut R: Array<u16, Params::P> = Array::default();
    let mut M: Array<u16, Params::P> = Array::default();
    for i in 0..Params::P::USIZE {
        M[i] = Params::Q;
    }
    decode(s, &M, &mut R);
    let mut r = Rq::<Params>::default();
    for i in 0..Params::P::USIZE {
        r.0[i] = Fq::new_i16(R[i].wrapping_sub(Params::Q12) as i16);
    }
    r
}
#[allow(non_snake_case)]
fn rounded_encode<Params: NtruCommon + StreamlinedNtru>(
    r: &Rq<Params>,
) -> Array<u8, Params::CipherTextBytes> {
    let mut R: Array<u16, Params::P> = Array::default();
    let mut M: Array<u16, Params::P> = Array::default();
    let mut out = Array::default();
    for i in 0..Params::P::USIZE {
        R[i] = ((*r.0[i] as u32)
            .wrapping_add(Params::Q12 as u32)
            .wrapping_mul(10923)
            >> 15) as u16;
    }
    for i in 0..Params::P::USIZE {
        M[i] = (Params::Q + 2) / 3;
    }
    encode(&R, &M, &mut out);
    out
}
#[allow(non_snake_case)]
fn rounded_decode<Params: NtruCommon + StreamlinedNtru>(
    s: &Array<u8, Params::CipherTextBytes>,
) -> Rq<Params> {
    let mut R: Array<u16, Params::P> = Array::default();
    let mut M: Array<u16, Params::P> = Array::default();
    for i in 0..Params::P::USIZE {
        M[i] = (Params::Q + 2) / 3;
    }
    decode(s, &M, &mut R);
    let mut r = Rq::<Params>::default();
    for i in 0..Params::P::USIZE {
        r.0[i] = Fq::new_i16(R[i].wrapping_mul(3).wrapping_sub(Params::Q12) as i16);
    }
    r
}

fn small_encode<Params: NtruCommon>(f: &R3<Params>, out: &mut [u8]) {
    let mut i = 0;
    let mut x;
    for _ in 0..Params::P::USIZE / 4 {
        x = (*f.0[i] + 1) as u8;
        x += ((*f.0[i + 1] + 1) as u8) << 2;
        x += ((*f.0[i + 2] + 1) as u8) << 4;
        x += ((*f.0[i + 3] + 1) as u8) << 6;
        out[i / 4] = x;
        i += 4;
    }
    x = (*f.0[i] + 1) as u8;
    out[i / 4] = x;
}

fn small_decode<Params: NtruCommon>(input: &[u8]) -> R3<Params> {
    let mut r = R3::default();
    for (i, x) in input.iter().enumerate().take(Params::P::USIZE / 4) {
        let mut x = *x;
        r.0[i * 4] = Small::new_i8((x & 3) as i8 - 1);
        x >>= 2;
        r.0[i * 4 + 1] = Small::new_i8((x & 3) as i8 - 1);
        x >>= 2;
        r.0[i * 4 + 2] = Small::new_i8((x & 3) as i8 - 1);
        x >>= 2;
        r.0[i * 4 + 3] = Small::new_i8((x & 3) as i8 - 1);
    }
    let x = input[Params::P::USIZE / 4];
    r.0[Params::P::USIZE - 1] = Small::new_i8((x & 3) as i8 - 1);
    r
}

impl<P> AsymEnc for Streamlined<P>
where
    P: ArraySize,
    Streamlined<P>: NtruCommon + StreamlinedNtru + Sized,
{
    type Inputs = R3<Self>;
    fn decrypt(
        c: &Array<u8, Self::CipherTextBytes>,
        sk: &Array<u8, Self::SecretKeyBytes>,
    ) -> R3<Self> {
        let f = small_decode(&sk[..Self::InputsBytes::USIZE]);
        let v = small_decode(&sk[Self::InputsBytes::USIZE..]);
        let c = rounded_decode(c);
        streamlined::decrypt(&c, &f, &v)
    }
    fn key_gen(
        rng: &mut impl CryptoRngCore,
    ) -> (
        Array<u8, Self::SecretKeyBytes>,
        Array<u8, Self::PublicKeyBytes>,
    ) {
        let (h, f, v) = streamlined::key_gen::<Self>(rng);
        let mut pk: Array<u8, Self::PublicKeyBytes> = Array::default();
        let mut sk: Array<u8, Self::SecretKeyBytes> = Array::default();
        rq_encode(&h, &mut pk);
        small_encode(&f, &mut sk[..Self::InputsBytes::USIZE]);
        small_encode(&v, &mut sk[Self::InputsBytes::USIZE..]);
        (sk, pk)
    }
    fn encrypt(
        r: &R3<Self>,
        pk: &Array<u8, Self::PublicKeyBytes>,
    ) -> Array<u8, Self::CipherTextBytes> {
        let h = rq_decode(pk);
        let c = streamlined::encrypt(r, &h);
        rounded_encode(&c)
    }
    fn inputs_encode(f: &R3<Self>, out: &mut [u8]) {
        small_encode(f, out);
    }

    fn inputs_random(rng: &mut impl CryptoRngCore) -> R3<Self> {
        R3::short_random(rng)
    }
}
