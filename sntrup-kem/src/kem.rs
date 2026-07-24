//! Internal KEM operations for Streamlined NTRU Prime.
//!
//! Top-level keygen/encaps/decaps functions that delegate to `utils` for
//! the core cryptographic operations.

use crate::params::SntrupParameters;
use crate::{r3, utils, zx};
use rand::CryptoRng;
use zeroize::Zeroize;

/// Generate a Streamlined NTRU Prime key pair.
///
/// Returns `(pk_bytes, sk_bytes)` as `Vec<u8>`.
#[cfg(feature = "kgen")]
pub(crate) fn keygen(params: &SntrupParameters, rng: &mut impl CryptoRng) -> (Vec<u8>, Vec<u8>) {
    let p = params.p;

    // Generate g and its reciprocal in R3
    let mut g = vec![0i8; p];
    let mut gr = loop {
        zx::random::random_small(&mut g, rng);
        let (mask, mut gr) = r3::reciprocal(&g, p);
        if mask == 0 {
            break gr;
        }
        // Rejected reciprocal is still derived from the secret g — wipe it.
        gr.zeroize();
    };

    // Generate f with Hamming weight w
    let mut f = vec![0i8; p];
    zx::random::random_tsmall(&mut f, p, params.w, rng);

    // Generate random rho for implicit rejection (raw random bytes, per PQClean)
    let mut rho = vec![0u8; params.small_encode_size];
    rng.fill_bytes(&mut rho);

    let result = utils::derive_key(&f, &g, &gr, &rho, params);

    // Zeroize secret intermediates
    f.zeroize();
    g.zeroize();
    gr.zeroize();
    rho.zeroize();

    result
}

/// Encapsulate with a public key.
///
/// Returns `(ciphertext_bytes, shared_secret_bytes)`.
#[cfg(feature = "ecap")]
pub(crate) fn encaps(
    pk: &[u8],
    params: &SntrupParameters,
    rng: &mut impl CryptoRng,
) -> (Vec<u8>, Vec<u8>) {
    let p = params.p;

    // Generate random r with Hamming weight w
    let mut r = vec![0i8; p];
    zx::random::random_tsmall(&mut r, p, params.w, rng);

    let (ct, ss) = utils::create_cipher(&r, pk, params);

    // Zeroize secret intermediate
    r.zeroize();

    (ct, ss.to_vec())
}

/// Decapsulate with a secret key.
///
/// Returns shared secret bytes.
#[cfg(feature = "dcap")]
pub(crate) fn decaps(sk: &[u8], ct: &[u8], params: &SntrupParameters) -> Vec<u8> {
    let ss = utils::decapsulate_inner(ct, sk, params);
    ss.to_vec()
}
