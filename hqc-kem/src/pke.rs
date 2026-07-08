/// HQC Public Key Encryption (PKE) operations.
///
/// v5.0.0 PKE:
/// - keygen: I(seed_pke) → (seed_dk, seed_ek), sample y,x via rej, s = x + h*y
/// - encrypt: sample r2,e,r1 via mod from theta, u = r1 + h*r2, v = encode(m) + s*r2 + e
/// - decrypt: y from seed_dk, v - u*y, decode
use crate::code;
use crate::params::{Buffer, HqcParams, SEED_BYTES};
use crate::poly;
use crate::sampling;
use crate::shake::{self, SeedExpander};
use zeroize::Zeroize;

/// PKE key generation from a PKE seed.
///
/// Returns (ek_pke, dk_pke) where:
/// - ek_pke = seed_pke_ek || s_bytes (PK_BYTES total)
/// - dk_pke = seed_pke_dk (SEED_BYTES)
pub(crate) fn pke_keygen<P: HqcParams>(seed_pke: &[u8]) -> (P::PkBuf, [u8; SEED_BYTES]) {
    let p = P::params();

    // I function: SHA3-512(seed_pke || 0x02) → 64 bytes
    let mut i_res = shake::hash_i(seed_pke);
    let seed_pke_dk = &i_res[..SEED_BYTES];
    let seed_pke_ek = &i_res[SEED_BYTES..2 * SEED_BYTES];

    // Sample y, x from dk seed using rejection sampling
    let mut ctx_dk = SeedExpander::new(seed_pke_dk);
    let mut y = P::VecN::zeroed();
    let mut x = P::VecN::zeroed();
    sampling::sample_fixed_wt_rej(&mut ctx_dk, y.as_mut(), p.w, p);
    sampling::sample_fixed_wt_rej(&mut ctx_dk, x.as_mut(), p.w, p);

    // Sample h from ek seed
    let mut ctx_ek = SeedExpander::new(seed_pke_ek);
    let mut h = P::VecN::zeroed();
    let mut rand_bytes = P::NBytesBuf::zeroed();
    sampling::sample_vect(&mut ctx_ek, h.as_mut(), rand_bytes.as_mut(), p);

    // s = x + h*y
    let mut s = P::VecN::zeroed();
    let mut tmp = P::VecN::zeroed();
    let mut prod = P::ProdBuf::zeroed();
    poly::vect_mul::<P>(tmp.as_mut(), y.as_ref(), h.as_ref(), prod.as_mut(), p);
    poly::vect_add(s.as_mut(), x.as_ref(), tmp.as_ref(), p.vec_n_size_64);

    // Zeroize secret vectors and secret-derived intermediates
    y.as_mut().zeroize();
    x.as_mut().zeroize();
    tmp.as_mut().zeroize();
    prod.as_mut().zeroize();

    // ek_pke = seed_pke_ek || s_bytes
    let mut ek_pke = P::PkBuf::zeroed();
    ek_pke.as_mut()[..SEED_BYTES].copy_from_slice(seed_pke_ek);
    poly::store8_arr(&mut ek_pke.as_mut()[SEED_BYTES..], s.as_ref());

    // dk_pke = seed_pke_dk
    let mut dk_pke = [0u8; SEED_BYTES];
    dk_pke.copy_from_slice(seed_pke_dk);

    // Zeroize I function result (contains secret dk seed)
    i_res.zeroize();

    (ek_pke, dk_pke)
}

/// PKE encryption.
///
/// Returns ciphertext bytes: u_bytes || v_bytes (n_bytes + n1n2_bytes).
pub(crate) fn pke_encrypt<P: HqcParams>(ek_pke: &[u8], m: &[u8], theta: &[u8]) -> P::CPkeBuf {
    let p = P::params();

    // Parse ek_pke
    let seed_pke_ek = &ek_pke[..SEED_BYTES];

    // Regenerate h from seed
    let mut ctx_ek = SeedExpander::new(seed_pke_ek);
    let mut h = P::VecN::zeroed();
    let mut rand_bytes = P::NBytesBuf::zeroed();
    sampling::sample_vect(&mut ctx_ek, h.as_mut(), rand_bytes.as_mut(), p);

    // Load s from ek_pke
    let mut s = P::VecN::zeroed();
    poly::load8_arr(s.as_mut(), &ek_pke[SEED_BYTES..]);

    // Sample r2, e, r1 from theta using mod sampling
    let mut ctx_th = SeedExpander::new(theta);
    let mut r2 = P::VecN::zeroed();
    let mut e = P::VecN::zeroed();
    let mut r1 = P::VecN::zeroed();
    sampling::sample_fixed_wt_mod(&mut ctx_th, r2.as_mut(), p.w_r, p);
    sampling::sample_fixed_wt_mod(&mut ctx_th, e.as_mut(), p.w_e, p);
    sampling::sample_fixed_wt_mod(&mut ctx_th, r1.as_mut(), p.w_r, p);

    // u = r1 + h*r2
    let mut u = P::VecN::zeroed();
    let mut tmp = P::VecN::zeroed();
    let mut prod = P::ProdBuf::zeroed();
    poly::vect_mul::<P>(tmp.as_mut(), r2.as_ref(), h.as_ref(), prod.as_mut(), p);
    poly::vect_add(u.as_mut(), r1.as_ref(), tmp.as_ref(), p.vec_n_size_64);

    // cm = encode(m) - encoded into n1n2 bits
    let mut cm = P::VecN1N2::zeroed();
    code::code_encode(cm.as_mut(), m, p);

    // v_full = cm + s*r2 + e (in n-bit space, then truncate to n1n2)
    let mut sr2 = P::VecN::zeroed();
    poly::vect_mul::<P>(sr2.as_mut(), r2.as_ref(), s.as_ref(), prod.as_mut(), p);

    // Work in n-bit space: extend cm and add
    let mut v_full = P::VecN::zeroed();
    // Copy cm into v_full (n1n2 <= n)
    poly::vect_resize(v_full.as_mut(), p.n, cm.as_ref(), p.n1n2);
    poly::vect_add_assign(v_full.as_mut(), sr2.as_ref(), p.vec_n_size_64);
    poly::vect_add_assign(v_full.as_mut(), e.as_ref(), p.vec_n_size_64);

    // Truncate v to n1n2 bits
    let mut v = P::VecN1N2::zeroed();
    poly::vect_resize(v.as_mut(), p.n1n2, v_full.as_ref(), p.n);

    // Serialize: u_bytes || v_bytes
    let mut ct = P::CPkeBuf::zeroed();
    poly::store8_arr(&mut ct.as_mut()[..p.n_bytes], u.as_ref());
    poly::store8_arr(&mut ct.as_mut()[p.n_bytes..], v.as_ref());

    // Zeroize secret sampling vectors and secret-derived intermediates
    // (v_full's bits above n1n2 hold sr2+e residue not present in the public v).
    r2.as_mut().zeroize();
    e.as_mut().zeroize();
    r1.as_mut().zeroize();
    tmp.as_mut().zeroize();
    sr2.as_mut().zeroize();
    cm.as_mut().zeroize();
    v_full.as_mut().zeroize();
    prod.as_mut().zeroize();

    ct
}

/// PKE decryption.
///
/// Returns decrypted message bytes (k bytes).
pub(crate) fn pke_decrypt<P: HqcParams>(dk_pke: &[u8], c_pke: &[u8]) -> P::KBuf {
    let p = P::params();

    // Regenerate y from dk seed
    let mut ctx_dk = SeedExpander::new(&dk_pke[..SEED_BYTES]);
    let mut y = P::VecN::zeroed();
    sampling::sample_fixed_wt_rej(&mut ctx_dk, y.as_mut(), p.w, p);

    // Parse ciphertext
    let mut u = P::VecN::zeroed();
    let mut v = P::VecN1N2::zeroed();
    poly::load8_arr(u.as_mut(), &c_pke[..p.n_bytes]);
    poly::load8_arr(v.as_mut(), &c_pke[p.n_bytes..p.n_bytes + p.n1n2_bytes]);

    // Compute v - u*y (XOR in GF(2))
    let mut uy = P::VecN::zeroed();
    let mut prod = P::ProdBuf::zeroed();
    poly::vect_mul::<P>(uy.as_mut(), y.as_ref(), u.as_ref(), prod.as_mut(), p);

    // Zeroize secret vector y — no longer needed
    y.as_mut().zeroize();

    // Extend v to n bits, XOR with uy, truncate back
    let mut v_full = P::VecN::zeroed();
    poly::vect_resize(v_full.as_mut(), p.n, v.as_ref(), p.n1n2);
    poly::vect_add_assign(v_full.as_mut(), uy.as_ref(), p.vec_n_size_64);

    // Truncate to n1n2 bits for decoding
    let mut cm = P::VecN1N2::zeroed();
    poly::vect_resize(cm.as_mut(), p.n1n2, v_full.as_ref(), p.n);

    // Decode
    let mut m = P::KBuf::zeroed();
    code::code_decode(m.as_mut(), cm.as_ref(), p);

    // Zeroize secret-derived intermediates
    uy.as_mut().zeroize();
    v_full.as_mut().zeroize();
    cm.as_mut().zeroize();
    prod.as_mut().zeroize();

    m
}
