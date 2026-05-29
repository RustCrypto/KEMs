/// Reed-Solomon encoding and decoding over GF(2^8).
///
/// Systematic RS(n1, k) with error correction capability delta = (n1-k)/2.
/// Generator polynomial roots: alpha^1, ..., alpha^(2*delta).
use crate::fft;
use crate::gf256::{GF_EXP, gf_inverse, gf_mul};
use crate::params::{HqcParameters, MAX_DELTA, MAX_N1};

/// Encode message into RS codeword (systematic).
///
/// Message bytes are placed at positions [n1-k..n1-1] (high end).
/// Parity bytes at positions [0..n1-k-1] (low end).
pub(crate) fn reed_solomon_encode(cdw: &mut [u8], msg: &[u8], p: &HqcParameters) {
    // Clear output
    cdw[..p.n1].fill(0);

    for i in 0..p.k {
        let gate_value = msg[p.k - 1 - i] ^ cdw[p.n1 - p.k - 1];

        // Shift register: shift right by 1 and XOR with gate_value * g[k]
        for k_idx in (1..p.n1 - p.k).rev() {
            cdw[k_idx] =
                cdw[k_idx - 1] ^ (gf_mul(gate_value as u16, p.rs_poly[k_idx] as u16) as u8);
        }
        cdw[0] = gf_mul(gate_value as u16, p.rs_poly[0] as u16) as u8;
    }

    // Copy message to high positions
    cdw[p.n1 - p.k..p.n1].copy_from_slice(&msg[..p.k]);
}

/// Compute 2*delta syndromes.
#[allow(clippy::needless_range_loop)] // indices used in arithmetic matching FIPS spec
fn compute_syndromes(syndromes: &mut [u16], cdw: &[u8], p: &HqcParameters) {
    for i in 0..(2 * p.delta) {
        syndromes[i] = 0;
        for j in 1..p.n1 {
            // alpha^((i+1)*j)
            let pow = ((i + 1) * j) % 255;
            syndromes[i] ^= gf_mul(cdw[j] as u16, GF_EXP[pow]);
        }
        syndromes[i] ^= cdw[0] as u16;
    }
}

/// Berlekamp algorithm: compute error locator polynomial sigma.
///
/// Constant-time implementation using mask-based updates.
/// Returns degree of sigma.
fn compute_elp(sigma: &mut [u16], syndromes: &[u16], p: &HqcParameters) -> u16 {
    let max_delta = p.delta;
    let mut deg_sigma: u16 = 0;
    let mut deg_sigma_p: u16 = 0;
    let mut sigma_copy = [0u16; MAX_DELTA + 1];
    let mut x_sigma_p = [0u16; MAX_DELTA + 1];
    x_sigma_p[1] = 1;
    let mut pp: u16 = 0u16.wrapping_sub(1); // -1 in u16
    let mut d_p: u16 = 1;
    let mut d: u16 = syndromes[0];

    sigma[0] = 1;

    for mu in 0..(2 * max_delta) {
        // Save sigma
        let deg_sigma_copy_val = deg_sigma;
        sigma_copy[..max_delta].copy_from_slice(&sigma[..max_delta]);

        let dd = gf_mul(d, gf_inverse(d_p));

        for i in 1..=(mu + 1).min(max_delta) {
            sigma[i] ^= gf_mul(dd, x_sigma_p[i]);
        }

        let deg_x = (mu as u16).wrapping_sub(pp);
        let deg_x_sigma_p = deg_x.wrapping_add(deg_sigma_p);

        // mask1 = 0xFFFF if d != 0
        let mask1 = 0u16.wrapping_sub((0u16.wrapping_sub(d)) >> 15);
        // mask2 = 0xFFFF if deg_x_sigma_p > deg_sigma
        let mask2 = 0u16.wrapping_sub(deg_sigma.wrapping_sub(deg_x_sigma_p) >> 15);
        let mask12 = mask1 & mask2;

        deg_sigma ^= mask12 & (deg_x_sigma_p ^ deg_sigma);

        if mu == 2 * max_delta - 1 {
            break;
        }

        pp ^= mask12 & ((mu as u16) ^ pp);
        d_p ^= mask12 & (d ^ d_p);

        for i in (1..=max_delta).rev() {
            x_sigma_p[i] = (mask12 & sigma_copy[i - 1]) ^ (!mask12 & x_sigma_p[i - 1]);
        }
        x_sigma_p[0] = 0;

        deg_sigma_p ^= mask12 & (deg_sigma_copy_val ^ deg_sigma_p);

        d = syndromes[mu + 1];
        for i in 1..=(mu + 1).min(max_delta) {
            d ^= gf_mul(sigma[i], syndromes[mu + 1 - i]);
        }
    }

    deg_sigma
}

/// Compute z polynomial for error value computation.
fn compute_z_poly(z: &mut [u16], sigma: &[u16], degree: u16, syndromes: &[u16], delta: usize) {
    z[0] = 1;

    for i in 1..=delta {
        let mask = 0u16.wrapping_sub(((i as u16).wrapping_sub(degree.wrapping_add(1))) >> 15);
        z[i] = mask & sigma[i];
    }

    z[1] ^= syndromes[0];

    for i in 2..=delta {
        let mask = 0u16.wrapping_sub(((i as u16).wrapping_sub(degree.wrapping_add(1))) >> 15);
        z[i] ^= mask & syndromes[i - 1];
        for j in 1..i {
            z[i] ^= mask & gf_mul(sigma[j], syndromes[i - j - 1]);
        }
    }
}

/// Compute error values using Forney's algorithm.
#[allow(clippy::needless_range_loop)] // constant-time mask operations indexed across multiple arrays
fn compute_error_values(error_values: &mut [u16], z: &[u16], error: &[u8; 256], p: &HqcParameters) {
    let mut beta_j = [0u16; MAX_DELTA];
    let mut e_j = [0u16; MAX_DELTA];

    // Compute beta values (error locator field elements)
    let mut delta_counter: u16 = 0;
    for i in 0..p.n1 {
        let found_mask =
            0u16.wrapping_sub(((0i32.wrapping_sub(error[i] as i32)) as u32 >> 31) as u16);
        let mut local_found: u16 = 0;

        for j in 0..p.delta {
            // Proper constant-time eq: both are u16
            let diff = (j as u16) ^ delta_counter;
            let zero_mask =
                0u16.wrapping_sub(((diff as u32 | diff.wrapping_neg() as u32) >> 31) as u16);
            let eq_mask2 = !zero_mask; // 0xFFFF if j == delta_counter

            beta_j[j] ^= found_mask & eq_mask2 & GF_EXP[i];
            local_found = local_found.wrapping_add(found_mask & eq_mask2 & 1);
        }
        delta_counter = delta_counter.wrapping_add(local_found);
    }
    let delta_real_value = delta_counter;

    // Compute error values
    for i in 0..p.delta {
        let mut tmp1: u16 = 1;
        let mut tmp2: u16 = 1;
        let inverse = gf_inverse(beta_j[i]);
        let mut inverse_power_j: u16 = 1;

        for j in 1..=p.delta {
            inverse_power_j = gf_mul(inverse_power_j, inverse);
            tmp1 ^= gf_mul(inverse_power_j, z[j]);
        }

        for k in 1..p.delta {
            let idx = (i + k) % p.delta;
            tmp2 = gf_mul(tmp2, 1 ^ gf_mul(inverse, beta_j[idx]));
        }

        // mask1 = 0xFFFF if i < delta_real_value
        let mask1 = 0u16.wrapping_sub(((i as u16).wrapping_sub(delta_real_value)) >> 15);
        e_j[i] = mask1 & gf_mul(tmp1, gf_inverse(tmp2));
    }

    // Place error values at correct positions
    delta_counter = 0;
    for i in 0..p.n1 {
        error_values[i] = 0;
        let found_mask =
            0u16.wrapping_sub(((0i32.wrapping_sub(error[i] as i32)) as u32 >> 31) as u16);
        let mut local_found: u16 = 0;

        for j in 0..p.delta {
            let diff = (j as u16) ^ delta_counter;
            let zero_mask =
                0u16.wrapping_sub(((diff as u32 | diff.wrapping_neg() as u32) >> 31) as u16);
            let eq_mask = !zero_mask;

            error_values[i] ^= found_mask & eq_mask & e_j[j];
            local_found = local_found.wrapping_add(found_mask & eq_mask & 1);
        }
        delta_counter = delta_counter.wrapping_add(local_found);
    }
}

/// Decode RS codeword, correcting up to delta errors.
///
/// Modifies `cdw` in place, then extracts message from positions [2*delta..n1-1].
pub(crate) fn reed_solomon_decode(msg: &mut [u8], cdw: &mut [u8], p: &HqcParameters) {
    let mut syndromes = [0u16; 2 * MAX_DELTA];
    let mut sigma = [0u16; 1 << 5]; // 2^MAX_FFT
    let mut error = [0u8; 256]; // 2^PARAM_M
    let mut z = [0u16; MAX_N1];
    let mut error_values = [0u16; MAX_N1];

    // Compute syndromes
    compute_syndromes(&mut syndromes, cdw, p);

    // Compute error locator polynomial
    let deg = compute_elp(&mut sigma, &syndromes, p);

    // Find roots via FFT
    let mut w = [0u16; 256];
    fft::fft(&mut w, &sigma, p.delta + 1, p.fft);
    fft::fft_retrieve_error_poly(&mut error, &w);

    // Compute z polynomial
    compute_z_poly(&mut z, &sigma, deg, &syndromes, p.delta);

    // Compute error values
    compute_error_values(&mut error_values, &z, &error, p);

    // Correct errors
    for i in 0..p.n1 {
        cdw[i] ^= error_values[i] as u8;
    }

    // Extract message (positions after parity bytes)
    let parity_len = 2 * p.delta;
    msg[..p.k].copy_from_slice(&cdw[parity_len..parity_len + p.k]);
}
