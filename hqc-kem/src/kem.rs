/// HQC Key Encapsulation Mechanism with Fujisaki-Okamoto transform.
///
/// v5.0.0 KEM:
/// - keygen: XOF(seed_kem) → seed_pke, sigma; pke_keygen(seed_pke)
/// - encaps: m, salt from RNG; H(ek), G(H||m||salt) → kk, theta; encrypt(ek, m, theta)
/// - decaps: decrypt → m'; re-encrypt; constant-time comparison; implicit rejection
use crate::params::{HqcParameters, SALT_BYTES, SEED_BYTES, SS_BYTES};
use crate::pke;
use crate::poly;
use crate::shake::{self, SeedExpander};
use rand::CryptoRng;
use zeroize::Zeroize;

/// Deterministic KEM key generation from a 32-byte seed.
///
/// Returns (pk_bytes, sk_bytes) where:
/// - pk = ek_pke (seed_pke_ek || s_bytes)
/// - sk = ek_pke || dk_pke || sigma || seed_kem
#[cfg(feature = "kgen")]
pub(crate) fn keygen_deterministic(
    seed_kem: &[u8; SEED_BYTES],
    p: &HqcParameters,
) -> (Vec<u8>, Vec<u8>) {
    // XOF(seed_kem || 0x01) → raw read seed_pke + sigma
    let mut ctx_kem = SeedExpander::new(seed_kem);
    let mut seed_pke = [0u8; SEED_BYTES];
    let mut sigma = vec![0u8; p.k];
    ctx_kem.read_raw(&mut seed_pke);
    ctx_kem.read_raw(&mut sigma);

    // PKE keygen
    let (ek_pke, dk_pke) = pke::pke_keygen(&seed_pke, p);

    // Zeroize intermediate seed_pke — no longer needed after pke_keygen
    seed_pke.zeroize();

    // pk = ek_pke
    let pk = ek_pke.clone();

    // sk = ek_pke || dk_pke || sigma || seed_kem
    let mut sk = Vec::with_capacity(p.sk_bytes);
    sk.extend_from_slice(&ek_pke);
    sk.extend_from_slice(&dk_pke);
    sk.extend_from_slice(&sigma);
    sk.extend_from_slice(seed_kem);

    // Zeroize sigma intermediate — now copied into sk
    sigma.zeroize();

    (pk, sk)
}

/// KEM key generation.
///
/// Samples a random seed, then delegates to [`keygen_deterministic`].
#[cfg(feature = "kgen")]
pub(crate) fn keygen(p: &HqcParameters, rng: &mut impl CryptoRng) -> (Vec<u8>, Vec<u8>) {
    let mut seed_kem = [0u8; SEED_BYTES];
    rng.fill_bytes(&mut seed_kem);
    let result = keygen_deterministic(&seed_kem, p);
    seed_kem.zeroize();
    result
}

/// Deterministic KEM encapsulation from a message and salt.
///
/// Returns (shared_secret, ciphertext).
#[cfg(feature = "ecap")]
pub(crate) fn encaps_deterministic(
    ek_kem: &[u8],
    m: &[u8],
    salt: &[u8; SALT_BYTES],
    p: &HqcParameters,
) -> (Vec<u8>, Vec<u8>) {
    // H(ek_kem || 0x01) → 32-byte hash of public key
    let tmp_h = shake::hash_h(ek_kem);

    // G(H || m || salt || 0x00) → 64 bytes: kk || theta
    let mut g_input = Vec::with_capacity(32 + m.len() + SALT_BYTES);
    g_input.extend_from_slice(&tmp_h);
    g_input.extend_from_slice(m);
    g_input.extend_from_slice(salt);
    let mut tmp_g = shake::hash_g(&g_input);
    g_input.zeroize();

    let kk = tmp_g[..SS_BYTES].to_vec();
    let theta = tmp_g[SS_BYTES..2 * SS_BYTES].to_vec();

    // Encrypt
    let c_pke = pke::pke_encrypt(ek_kem, m, &theta, p);

    // Zeroize intermediates
    tmp_g.zeroize();

    // Ciphertext = c_pke || salt
    let mut ct = Vec::with_capacity(p.ct_bytes);
    ct.extend_from_slice(&c_pke);
    ct.extend_from_slice(salt);

    (kk, ct)
}

/// KEM encapsulation.
///
/// Samples random message and salt, then delegates to [`encaps_deterministic`].
#[cfg(feature = "ecap")]
pub(crate) fn encaps(
    ek_kem: &[u8],
    p: &HqcParameters,
    rng: &mut (impl CryptoRng + ?Sized),
) -> (Vec<u8>, Vec<u8>) {
    let mut m = vec![0u8; p.k];
    let mut salt = [0u8; SALT_BYTES];
    rng.fill_bytes(&mut m);
    rng.fill_bytes(&mut salt);
    let result = encaps_deterministic(ek_kem, &m, &salt, p);
    m.zeroize();
    salt.zeroize();
    result
}

/// KEM decapsulation with implicit rejection.
///
/// Returns shared secret (SS_BYTES).
#[cfg(feature = "dcap")]
pub(crate) fn decaps(dk_kem: &[u8], c_kem: &[u8], p: &HqcParameters) -> Vec<u8> {
    // Parse secret key: ek_kem || dk_pke || sigma || seed_kem
    let ek_kem = &dk_kem[..p.pk_bytes];
    let dk_pke = &dk_kem[p.pk_bytes..p.pk_bytes + SEED_BYTES];
    let sigma = &dk_kem[p.pk_bytes + SEED_BYTES..p.pk_bytes + SEED_BYTES + p.k];

    // Parse ciphertext: c_pke || salt
    let c_pke_len = p.n_bytes + p.n1n2_bytes;
    let c_pke = &c_kem[..c_pke_len];
    let salt = &c_kem[c_pke_len..c_pke_len + SALT_BYTES];

    // Decrypt
    let mut m_prime = pke::pke_decrypt(dk_pke, c_pke, p);

    // Re-derive theta
    let tmp_h = shake::hash_h(ek_kem);

    let mut g_input = Vec::with_capacity(32 + p.k + SALT_BYTES);
    g_input.extend_from_slice(&tmp_h);
    g_input.extend_from_slice(&m_prime);
    g_input.extend_from_slice(salt);
    let mut tmp_g = shake::hash_g(&g_input);
    g_input.zeroize();

    let kk_prime = &tmp_g[..SS_BYTES];
    let theta_prime = &tmp_g[SS_BYTES..2 * SS_BYTES];

    // Re-encrypt
    let c_pke_prime = pke::pke_encrypt(ek_kem, &m_prime, theta_prime, p);

    // Zeroize decrypted message — no longer needed
    m_prime.zeroize();

    // Ciphertext for comparison: c_pke_prime || salt
    let mut c_kem_prime = Vec::with_capacity(p.ct_bytes);
    c_kem_prime.extend_from_slice(&c_pke_prime);
    c_kem_prime.extend_from_slice(salt);

    // J function for rejection key: SHA3-256(H || sigma || c_kem || 0x03)
    let mut j_input = Vec::with_capacity(32 + p.k + p.ct_bytes);
    j_input.extend_from_slice(&tmp_h);
    j_input.extend_from_slice(sigma);
    j_input.extend_from_slice(c_kem);
    let mut k_rej = shake::hash_j(&j_input);
    j_input.zeroize();

    // Constant-time comparison of ciphertexts
    let cmp_result = poly::vect_compare(&c_kem[..c_pke_len + SALT_BYTES], &c_kem_prime);

    // Select between kk_prime and k_rej in constant time
    // cmp_result is 0 if equal (use kk_prime), non-zero if different (use k_rej)
    let mask = 0u8.wrapping_sub(cmp_result); // 0xFF if mismatch, 0x00 if match
    let mut ss = vec![0u8; SS_BYTES];
    for i in 0..SS_BYTES {
        ss[i] = (kk_prime[i] & !mask) | (k_rej[i] & mask);
    }

    // Zeroize remaining sensitive intermediates
    tmp_g.zeroize();
    k_rej.zeroize();

    ss
}
