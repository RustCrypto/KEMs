/// HQC Key Encapsulation Mechanism with Fujisaki-Okamoto transform.
///
/// v5.0.0 KEM:
/// - keygen: XOF(seed_kem) → seed_pke, sigma; pke_keygen(seed_pke)
/// - encaps: m, salt from RNG; H(ek), G(H||m||salt) → kk, theta; encrypt(ek, m, theta)
/// - decaps: decrypt → m'; re-encrypt; constant-time comparison; implicit rejection
use crate::params::{Buffer, HqcParams, SALT_BYTES, SEED_BYTES, SS_BYTES};
use crate::pke;
use crate::shake::{self, SeedExpander};
#[cfg(any(feature = "kgen", feature = "ecap"))]
use rand::CryptoRng;
use zeroize::Zeroize;

/// Deterministic KEM key generation from a 32-byte seed.
///
/// Returns (pk_bytes, sk_bytes) where:
/// - pk = ek_pke (seed_pke_ek || s_bytes)
/// - sk = ek_pke || dk_pke || sigma || seed_kem
#[cfg(feature = "kgen")]
pub(crate) fn keygen_deterministic<P: HqcParams>(
    seed_kem: &[u8; SEED_BYTES],
) -> (P::PkBuf, P::SkBuf) {
    let p = P::params();

    // XOF(seed_kem || 0x01) → raw read seed_pke + sigma
    let mut ctx_kem = SeedExpander::new(seed_kem);
    let mut seed_pke = [0u8; SEED_BYTES];
    let mut sigma = P::KBuf::zeroed();
    ctx_kem.get_bytes(&mut seed_pke);
    ctx_kem.get_bytes(sigma.as_mut());

    // PKE keygen
    let (ek_pke, mut dk_pke) = pke::pke_keygen::<P>(&seed_pke);

    // Zeroize intermediate seed_pke — no longer needed after pke_keygen
    seed_pke.zeroize();

    // pk = ek_pke
    let pk = ek_pke.clone();

    // sk = ek_pke || dk_pke || sigma || seed_kem
    let mut sk = P::SkBuf::zeroed();
    {
        let sk = sk.as_mut();
        sk[..p.pk_bytes].copy_from_slice(ek_pke.as_ref());
        sk[p.pk_bytes..p.pk_bytes + SEED_BYTES].copy_from_slice(&dk_pke);
        sk[p.pk_bytes + SEED_BYTES..p.pk_bytes + SEED_BYTES + p.k].copy_from_slice(sigma.as_ref());
        sk[p.pk_bytes + SEED_BYTES + p.k..].copy_from_slice(seed_kem);
    }

    // Zeroize intermediates — now copied into sk
    dk_pke.zeroize();
    sigma.as_mut().zeroize();

    (pk, sk)
}

/// KEM key generation.
///
/// Samples a random seed, then delegates to [`keygen_deterministic`].
#[cfg(feature = "kgen")]
pub(crate) fn keygen<P: HqcParams>(rng: &mut impl CryptoRng) -> (P::PkBuf, P::SkBuf) {
    let mut seed_kem = [0u8; SEED_BYTES];
    rng.fill_bytes(&mut seed_kem);
    let result = keygen_deterministic::<P>(&seed_kem);
    seed_kem.zeroize();
    result
}

/// Deterministic KEM encapsulation from a message and salt.
///
/// Returns (shared_secret, ciphertext).
#[cfg(feature = "ecap")]
pub(crate) fn encaps_deterministic<P: HqcParams>(
    ek_kem: &[u8],
    m: &[u8],
    salt: &[u8; SALT_BYTES],
) -> ([u8; SS_BYTES], P::CtBuf) {
    let p = P::params();

    // H(ek_kem || 0x01) → 32-byte hash of public key
    let tmp_h = shake::hash_h(ek_kem);

    // G(H || m || salt || 0x00) → 64 bytes: kk || theta
    let mut tmp_g = shake::hash_g(&[&tmp_h, m, salt]);

    let mut kk = [0u8; SS_BYTES];
    kk.copy_from_slice(&tmp_g[..SS_BYTES]);
    let mut theta = [0u8; SS_BYTES];
    theta.copy_from_slice(&tmp_g[SS_BYTES..2 * SS_BYTES]);

    // Encrypt
    let c_pke = pke::pke_encrypt::<P>(ek_kem, m, &theta);

    // Zeroize intermediates
    tmp_g.zeroize();
    theta.zeroize();

    // Ciphertext = c_pke || salt
    let mut ct = P::CtBuf::zeroed();
    {
        let ct = ct.as_mut();
        ct[..p.ct_bytes - SALT_BYTES].copy_from_slice(c_pke.as_ref());
        ct[p.ct_bytes - SALT_BYTES..].copy_from_slice(salt);
    }

    (kk, ct)
}

/// KEM encapsulation.
///
/// Samples random message and salt, then delegates to [`encaps_deterministic`].
#[cfg(feature = "ecap")]
pub(crate) fn encaps<P: HqcParams>(
    ek_kem: &[u8],
    rng: &mut (impl CryptoRng + ?Sized),
) -> ([u8; SS_BYTES], P::CtBuf) {
    let mut m = P::KBuf::zeroed();
    let mut salt = [0u8; SALT_BYTES];
    rng.fill_bytes(m.as_mut());
    rng.fill_bytes(&mut salt);
    let result = encaps_deterministic::<P>(ek_kem, m.as_ref(), &salt);
    m.as_mut().zeroize();
    salt.zeroize();
    result
}

/// KEM decapsulation with implicit rejection.
///
/// Returns shared secret (SS_BYTES).
#[cfg(feature = "dcap")]
pub(crate) fn decaps<P: HqcParams>(dk_kem: &[u8], c_kem: &[u8]) -> [u8; SS_BYTES] {
    let p = P::params();

    // Parse secret key: ek_kem || dk_pke || sigma || seed_kem
    let ek_kem = &dk_kem[..p.pk_bytes];
    let dk_pke = &dk_kem[p.pk_bytes..p.pk_bytes + SEED_BYTES];
    let sigma = &dk_kem[p.pk_bytes + SEED_BYTES..p.pk_bytes + SEED_BYTES + p.k];

    // Parse ciphertext: c_pke || salt
    let c_pke_len = p.n_bytes + p.n1n2_bytes;
    let c_pke = &c_kem[..c_pke_len];
    let salt = &c_kem[c_pke_len..c_pke_len + SALT_BYTES];

    // Decrypt
    let mut m_prime = pke::pke_decrypt::<P>(dk_pke, c_pke);

    // Re-derive theta
    let tmp_h = shake::hash_h(ek_kem);

    // G(H || m' || salt || 0x00) → 64 bytes: kk' || theta'
    let mut tmp_g = shake::hash_g(&[&tmp_h, m_prime.as_ref(), salt]);

    let kk_prime = &tmp_g[..SS_BYTES];
    let theta_prime = &tmp_g[SS_BYTES..2 * SS_BYTES];

    // Re-encrypt
    let c_pke_prime = pke::pke_encrypt::<P>(ek_kem, m_prime.as_ref(), theta_prime);

    // Zeroize decrypted message — no longer needed
    m_prime.as_mut().zeroize();

    // J function for rejection key: SHA3-256(H || sigma || c_kem || 0x03)
    let mut k_rej = shake::hash_j(&[&tmp_h, sigma, c_kem]);

    // Constant-time comparison of ciphertexts (the received salt is compared
    // against its own copy implicitly and is always equal, so comparing the
    // c_pke halves is output-identical to comparing full ciphertexts).
    let equal = {
        use ctutils::CtEq;
        c_pke.ct_eq(c_pke_prime.as_ref())
    };

    // Implicit rejection: k_rej unless the re-encryption matched, selected
    // per byte in constant time.
    let mut ss = [0u8; SS_BYTES];
    for i in 0..SS_BYTES {
        use ctutils::CtSelect;
        ss[i] = k_rej[i].ct_select(&kk_prime[i], equal);
    }

    // Zeroize remaining sensitive intermediates (c_pke_prime derives from the
    // secret m' whenever the FO comparison fails).
    let mut c_pke_prime = c_pke_prime;
    c_pke_prime.as_mut().zeroize();
    tmp_g.zeroize();
    k_rej.zeroize();

    ss
}
