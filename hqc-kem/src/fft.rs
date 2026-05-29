/// Additive FFT for GF(2^8) polynomial evaluation.
///
/// Used by Reed-Solomon decoding to find roots of the error locator polynomial.
/// Based on Gao-Mateer with Bernstein-Chou-Schwabe improvements.
use crate::gf256::{GF_LOG, gf_inverse, gf_mul, gf_square};
use crate::params::PARAM_M;

/// Compute FFT betas (basis elements).
fn compute_fft_betas(betas: &mut [u16]) {
    for (i, beta) in betas.iter_mut().enumerate().take(PARAM_M - 1) {
        *beta = 1 << (PARAM_M - 1 - i);
    }
}

/// Compute subset sums of a set.
fn compute_subset_sums(subset_sums: &mut [u16], set: &[u16], set_size: usize) {
    subset_sums[0] = 0;
    for i in 0..set_size {
        for j in 0..(1 << i) {
            subset_sums[(1 << i) + j] = set[i] ^ subset_sums[j];
        }
    }
}

/// Radix conversion for small sizes (hardcoded cases).
fn radix(f0: &mut [u16], f1: &mut [u16], f: &[u16], m_f: usize) {
    match m_f {
        1 => {
            f0[0] = f[0];
            f1[0] = f[1];
        }
        2 => {
            f0[0] = f[0];
            f0[1] = f[2] ^ f[3];
            f1[0] = f[1] ^ f0[1];
            f1[1] = f[3];
        }
        3 => {
            f0[0] = f[0];
            f0[2] = f[4] ^ f[6];
            f0[3] = f[6] ^ f[7];
            f1[1] = f[3] ^ f[5] ^ f[7];
            f1[2] = f[5] ^ f[6];
            f1[3] = f[7];
            f0[1] = f[2] ^ f0[2] ^ f1[1];
            f1[0] = f[1] ^ f0[1];
        }
        4 => {
            f0[4] = f[8] ^ f[12];
            f0[6] = f[12] ^ f[14];
            f0[7] = f[14] ^ f[15];
            f1[5] = f[11] ^ f[13];
            f1[6] = f[13] ^ f[14];
            f1[7] = f[15];
            f0[5] = f[10] ^ f[12] ^ f1[5];
            f1[4] = f[9] ^ f[13] ^ f0[5];

            f0[0] = f[0];
            f1[3] = f[7] ^ f[11] ^ f[15];
            f0[3] = f[6] ^ f[10] ^ f[14] ^ f1[3];
            f0[2] = f[4] ^ f0[4] ^ f0[3] ^ f1[3];
            f1[1] = f[3] ^ f[5] ^ f[9] ^ f[13] ^ f1[3];
            f1[2] = f[3] ^ f1[1] ^ f0[3];
            f0[1] = f[2] ^ f0[2] ^ f1[1];
            f1[0] = f[1] ^ f0[1];
        }
        _ => {
            radix_big(f0, f1, f, m_f);
        }
    }
}

/// Radix conversion for larger sizes.
fn radix_big(f0: &mut [u16], f1: &mut [u16], f: &[u16], m_f: usize) {
    let n = 1usize << (m_f - 2);
    let mut q = vec![0u16; 2 * n + 1];
    let mut r = vec![0u16; 4 * n];
    let mut q0 = vec![0u16; n];
    let mut q1 = vec![0u16; n];
    let mut r0 = vec![0u16; n];
    let mut r1 = vec![0u16; n];

    q[..n].copy_from_slice(&f[3 * n..4 * n]);
    q[n..2 * n].copy_from_slice(&f[3 * n..4 * n]);
    r[..4 * n].copy_from_slice(&f[..4 * n]);

    for i in 0..n {
        q[i] ^= f[2 * n + i];
        r[n + i] ^= q[i];
    }

    radix(&mut q0, &mut q1, &q, m_f - 1);
    radix(&mut r0, &mut r1, &r, m_f - 1);

    f0[..n].copy_from_slice(&r0[..n]);
    f0[n..2 * n].copy_from_slice(&q0[..n]);
    f1[..n].copy_from_slice(&r1[..n]);
    f1[n..2 * n].copy_from_slice(&q1[..n]);
}

/// Recursive FFT evaluation.
fn fft_rec(w: &mut [u16], f: &mut [u16], f_coeffs: usize, m: usize, m_f: usize, betas: &[u16]) {
    if m_f == 1 {
        let mut tmp = [0u16; PARAM_M];
        for i in 0..m {
            tmp[i] = gf_mul(betas[i], f[1]);
        }
        w[0] = f[0];
        let mut x = 1usize;
        for tmp_j in tmp.iter().take(m) {
            for k in 0..x {
                w[x + k] = w[k] ^ tmp_j;
            }
            x <<= 1;
        }
        return;
    }

    let half_size = 1 << (m_f - 1);
    let mut f0 = vec![0u16; half_size];
    let mut f1 = vec![0u16; half_size];

    // Step 2: twist by beta_m
    if betas[m - 1] != 1 {
        let mut beta_pow = 1u16;
        let x = 1usize << m_f;
        for i in 1..x.min(f.len()) {
            beta_pow = gf_mul(beta_pow, betas[m - 1]);
            f[i] = gf_mul(beta_pow, f[i]);
        }
    }

    // Step 3: radix
    radix(&mut f0, &mut f1, f, m_f);

    // Step 4: compute gammas and deltas
    let mut gammas = vec![0u16; m];
    let mut deltas = vec![0u16; m];
    let inv_beta_m = gf_inverse(betas[m - 1]);
    for i in 0..m - 1 {
        gammas[i] = gf_mul(betas[i], inv_beta_m);
        deltas[i] = gf_square(gammas[i]) ^ gammas[i];
    }

    // Compute gamma sums
    let mut gammas_sums = vec![0u16; 1 << (m - 1)];
    compute_subset_sums(&mut gammas_sums, &gammas, m - 1);

    // Step 5: recurse
    let k = 1usize << (m - 1);
    let mut u = vec![0u16; k];
    fft_rec(
        &mut u,
        &mut f0,
        f_coeffs.div_ceil(2),
        m - 1,
        m_f - 1,
        &deltas,
    );

    if f_coeffs <= 3 {
        // f1 is constant
        w[0] = u[0];
        w[k] = u[0] ^ f1[0];
        for i in 1..k {
            w[i] = u[i] ^ gf_mul(gammas_sums[i], f1[0]);
            w[k + i] = w[i] ^ f1[0];
        }
    } else {
        let mut v = vec![0u16; k];
        fft_rec(&mut v, &mut f1, f_coeffs / 2, m - 1, m_f - 1, &deltas);

        // Step 6: combine
        w[k..k + k].copy_from_slice(&v[..k]);
        w[0] = u[0];
        w[k] ^= u[0];
        for i in 1..k {
            w[i] = u[i] ^ gf_mul(gammas_sums[i], v[i]);
            w[k + i] ^= w[i];
        }
    }
}

/// Evaluate polynomial at all 2^M field elements using additive FFT.
///
/// `f` has `f_coeffs` coefficients. `w` receives 2^M evaluations.
pub(crate) fn fft(w: &mut [u16; 256], f: &[u16], f_coeffs: usize, fft_param: usize) {
    let mut betas = [0u16; PARAM_M - 1];
    compute_fft_betas(&mut betas);

    let mut betas_sums = [0u16; 1 << (PARAM_M - 1)];
    compute_subset_sums(&mut betas_sums, &betas, PARAM_M - 1);

    let fft_size = 1 << fft_param;
    let mut f_padded = vec![0u16; fft_size];
    f_padded[..f_coeffs.min(fft_size)].copy_from_slice(&f[..f_coeffs.min(fft_size)]);

    let half = fft_size >> 1;
    let mut f0 = vec![0u16; half];
    let mut f1 = vec![0u16; half];
    radix(&mut f0, &mut f1, &f_padded, fft_param);

    let mut deltas = [0u16; PARAM_M - 1];
    for i in 0..(PARAM_M - 1) {
        deltas[i] = gf_square(betas[i]) ^ betas[i];
    }

    let k = 1usize << (PARAM_M - 1);
    let mut u = vec![0u16; k];
    let mut v = vec![0u16; k];

    fft_rec(
        &mut u,
        &mut f0,
        f_coeffs.div_ceil(2),
        PARAM_M - 1,
        fft_param - 1,
        &deltas,
    );
    fft_rec(
        &mut v,
        &mut f1,
        f_coeffs / 2,
        PARAM_M - 1,
        fft_param - 1,
        &deltas,
    );

    w[k..k + k].copy_from_slice(&v[..k]);
    w[0] = u[0];
    w[k] ^= u[0];
    for i in 1..k {
        w[i] = u[i] ^ gf_mul(betas_sums[i], v[i]);
        w[k + i] ^= w[i];
    }
}

/// Retrieve error polynomial from FFT evaluations.
///
/// `error[i] = 1` if `w[alpha^(-i)] == 0`, i.e., alpha^(-i) is a root of sigma.
pub(crate) fn fft_retrieve_error_poly(error: &mut [u8; 256], w: &[u16; 256]) {
    let mut gammas = [0u16; PARAM_M - 1];
    compute_fft_betas(&mut gammas);

    let mut gammas_sums = [0u16; 1 << (PARAM_M - 1)];
    compute_subset_sums(&mut gammas_sums, &gammas, PARAM_M - 1);

    let k = 1usize << (PARAM_M - 1);

    // Check if 0 is root
    error[0] ^= 1 ^ ((0u16.wrapping_sub(w[0])) >> 15) as u8;
    // Check if 1 is root
    error[0] ^= 1 ^ ((0u16.wrapping_sub(w[k])) >> 15) as u8;

    for i in 1..k {
        let idx1 = 255 - GF_LOG[gammas_sums[i] as usize] as usize;
        error[idx1] ^= 1 ^ ((0u16.wrapping_sub(w[i])) >> 15) as u8;

        let idx2 = 255 - GF_LOG[(gammas_sums[i] ^ 1) as usize] as usize;
        error[idx2] ^= 1 ^ ((0u16.wrapping_sub(w[k + i])) >> 15) as u8;
    }
}
