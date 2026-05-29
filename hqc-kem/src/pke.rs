/// HQC Public Key Encryption (PKE) operations.
///
/// v5.0.0 PKE:
/// - keygen: I(seed_pke) → (seed_dk, seed_ek), sample y,x via rej, s = x + h*y
/// - encrypt: sample r2,e,r1 via mod from theta, u = r1 + h*r2, v = encode(m) + s*r2 + e
/// - decrypt: y from seed_dk, v - u*y, decode
use crate::code;
use crate::params::{HqcParameters, SEED_BYTES};
use crate::poly;
use crate::sampling;
use crate::shake::{self, SeedExpander};
use zeroize::Zeroize;

/// PKE key generation from a PKE seed.
///
/// Returns (ek_pke, dk_pke) where:
/// - ek_pke = seed_pke_ek || s_bytes (pk_bytes total)
/// - dk_pke = seed_pke_dk (SEED_BYTES)
pub(crate) fn pke_keygen(seed_pke: &[u8], p: &HqcParameters) -> (Vec<u8>, Vec<u8>) {
    // I function: SHA3-512(seed_pke || 0x02) → 64 bytes
    let mut i_res = shake::hash_i(seed_pke);
    let seed_pke_dk = &i_res[..SEED_BYTES];
    let seed_pke_ek = &i_res[SEED_BYTES..2 * SEED_BYTES];

    // Sample y, x from dk seed using rejection sampling
    let mut ctx_dk = SeedExpander::new(seed_pke_dk);
    let mut y = vec![0u64; p.vec_n_size_64];
    let mut x = vec![0u64; p.vec_n_size_64];
    sampling::sample_fixed_wt_rej(&mut ctx_dk, &mut y, p.w, p);
    sampling::sample_fixed_wt_rej(&mut ctx_dk, &mut x, p.w, p);

    // Sample h from ek seed
    let mut ctx_ek = SeedExpander::new(seed_pke_ek);
    let mut h = vec![0u64; p.vec_n_size_64];
    sampling::sample_vect(&mut ctx_ek, &mut h, p);

    // s = x + h*y
    let mut s = vec![0u64; p.vec_n_size_64];
    let mut tmp = vec![0u64; p.vec_n_size_64];
    poly::vect_mul(&mut tmp, &y, &h, p);
    poly::vect_add(&mut s, &x, &tmp, p.vec_n_size_64);

    // Zeroize secret vectors — no longer needed
    y.zeroize();
    x.zeroize();

    // ek_pke = seed_pke_ek || s_bytes
    let mut ek_pke = vec![0u8; p.pk_bytes];
    ek_pke[..SEED_BYTES].copy_from_slice(seed_pke_ek);
    poly::store8_arr(&mut ek_pke[SEED_BYTES..], &s);

    // dk_pke = seed_pke_dk
    let dk_pke = seed_pke_dk.to_vec();

    // Zeroize I function result (contains secret dk seed)
    i_res.zeroize();

    (ek_pke, dk_pke)
}

/// PKE encryption.
///
/// Returns ciphertext bytes: u_bytes || v_bytes (n_bytes + n1n2_bytes).
pub(crate) fn pke_encrypt(ek_pke: &[u8], m: &[u8], theta: &[u8], p: &HqcParameters) -> Vec<u8> {
    // Parse ek_pke
    let seed_pke_ek = &ek_pke[..SEED_BYTES];

    // Regenerate h from seed
    let mut ctx_ek = SeedExpander::new(seed_pke_ek);
    let mut h = vec![0u64; p.vec_n_size_64];
    sampling::sample_vect(&mut ctx_ek, &mut h, p);

    // Load s from ek_pke
    let mut s = vec![0u64; p.vec_n_size_64];
    poly::load8_arr(&mut s, &ek_pke[SEED_BYTES..]);

    // Sample r2, e, r1 from theta using mod sampling
    let mut ctx_th = SeedExpander::new(theta);
    let mut r2 = vec![0u64; p.vec_n_size_64];
    let mut e = vec![0u64; p.vec_n_size_64];
    let mut r1 = vec![0u64; p.vec_n_size_64];
    sampling::sample_fixed_wt_mod(&mut ctx_th, &mut r2, p.w_r, p);
    sampling::sample_fixed_wt_mod(&mut ctx_th, &mut e, p.w_e, p);
    sampling::sample_fixed_wt_mod(&mut ctx_th, &mut r1, p.w_r, p);

    // u = r1 + h*r2
    let mut u = vec![0u64; p.vec_n_size_64];
    let mut tmp = vec![0u64; p.vec_n_size_64];
    poly::vect_mul(&mut tmp, &r2, &h, p);
    poly::vect_add(&mut u, &r1, &tmp, p.vec_n_size_64);

    // cm = encode(m) - encoded into n1n2 bits
    let mut cm = vec![0u64; p.vec_n1n2_size_64];
    code::code_encode(&mut cm, m, p);

    // v_full = cm + s*r2 + e (in n-bit space, then truncate to n1n2)
    let mut sr2 = vec![0u64; p.vec_n_size_64];
    poly::vect_mul(&mut sr2, &r2, &s, p);

    // Work in n-bit space: extend cm and add
    let mut v_full = vec![0u64; p.vec_n_size_64];
    // Copy cm into v_full (n1n2 <= n)
    poly::vect_resize(&mut v_full, p.n, &cm, p.n1n2);
    poly::vect_add_assign(&mut v_full, &sr2, p.vec_n_size_64);
    poly::vect_add_assign(&mut v_full, &e, p.vec_n_size_64);

    // Truncate v to n1n2 bits
    let mut v = vec![0u64; p.vec_n1n2_size_64];
    poly::vect_resize(&mut v, p.n1n2, &v_full, p.n);

    // Serialize: u_bytes || v_bytes
    let mut ct = vec![0u8; p.n_bytes + p.n1n2_bytes];
    poly::store8_arr(&mut ct[..p.n_bytes], &u);
    poly::store8_arr(&mut ct[p.n_bytes..], &v);

    ct
}

/// PKE decryption.
///
/// Returns decrypted message bytes (k bytes).
pub(crate) fn pke_decrypt(dk_pke: &[u8], c_pke: &[u8], p: &HqcParameters) -> Vec<u8> {
    // Regenerate y from dk seed
    let mut ctx_dk = SeedExpander::new(&dk_pke[..SEED_BYTES]);
    let mut y = vec![0u64; p.vec_n_size_64];
    sampling::sample_fixed_wt_rej(&mut ctx_dk, &mut y, p.w, p);

    // Parse ciphertext
    let mut u = vec![0u64; p.vec_n_size_64];
    let mut v = vec![0u64; p.vec_n1n2_size_64];
    poly::load8_arr(&mut u, &c_pke[..p.n_bytes]);
    poly::load8_arr(&mut v, &c_pke[p.n_bytes..p.n_bytes + p.n1n2_bytes]);

    // Compute v - u*y (XOR in GF(2))
    let mut uy = vec![0u64; p.vec_n_size_64];
    poly::vect_mul(&mut uy, &y, &u, p);

    // Zeroize secret vector y — no longer needed
    y.zeroize();

    // Extend v to n bits, XOR with uy, truncate back
    let mut v_full = vec![0u64; p.vec_n_size_64];
    poly::vect_resize(&mut v_full, p.n, &v, p.n1n2);
    poly::vect_add_assign(&mut v_full, &uy, p.vec_n_size_64);

    // Truncate to n1n2 bits for decoding
    let mut cm = vec![0u64; p.vec_n1n2_size_64];
    poly::vect_resize(&mut cm, p.n1n2, &v_full, p.n);

    // Decode
    let mut m = vec![0u8; p.k];
    code::code_decode(&mut m, &cm, p);
    m
}
