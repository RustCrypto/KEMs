#![allow(non_snake_case)]

use crate::const_time::{u32_divmod_u14, u32_mod_u14};
use alloc::vec;
pub fn encode(R: &[u16], M: &[u16], out: &mut [u8]) {
    if M.is_empty() {
        return;
    }
    if M.len() == 1 {
        let mut r = R[0];
        let mut m = M[0];
        let mut i = 0;
        while m > 1 {
            out[i] = r as u8;
            i += 1;
            r >>= 8;
            m = m.wrapping_add(255) >> 8;
        }
        return;
    }
    let mut R2 = vec![0u16; (M.len() + 1) / 2];
    let mut M2 = vec![0u16; (M.len() + 1) / 2];
    let mut idx = 0;
    let mut i = 0;
    while i < M.len() - 1 {
        let m0 = M[i] as u32;
        let mut r = R[i] as u32 + R[i + 1] as u32 * m0;
        let mut m = M[i + 1] as u32 * m0;
        while m >= 16384 {
            out[idx] = r as u8;
            idx += 1;
            r >>= 8;
            m = m.wrapping_add(255) >> 8;
        }
        R2[i / 2] = r as u16;
        M2[i / 2] = m as u16;
        i += 2;
    }
    if i < M.len() {
        R2[i / 2] = R[i];
        M2[i / 2] = M[i];
    }
    encode(&R2, &M2, &mut out[idx..]);
}

pub fn decode(S: &[u8], M: &[u16], out: &mut [u16]) {
    if M.is_empty() {
        return;
    }
    if M.len() == 1 {
        if M[0] == 1 {
            out[0] = 0;
        } else if M[0] < 256 {
            out[0] = u32_mod_u14(S[0] as u32, M[0]);
        } else {
            out[0] = u32_mod_u14(S[0] as u32 + ((S[1] as u16) << 8) as u32, M[0]);
        }
        return;
    }
    let mut R2 = vec![0u16; (M.len() + 1) / 2];
    let mut M2 = vec![0u16; (M.len() + 1) / 2];
    let mut bottomr = vec![0u16; M.len() / 2];
    let mut bottomt = vec![0u32; M.len() / 2];
    let mut i = 0;
    let mut s_idx = 0;
    while i < M.len() - 1 {
        let m = M[i] as u32 * M[i + 1] as u32;
        if m > 256 * 16383 {
            bottomt[i / 2] = 256 * 256;
            bottomr[i / 2] = S[s_idx] as u16 + 256 * S[s_idx + 1] as u16;
            s_idx += 2;
            M2[i / 2] = ((((m + 255) >> 8) + 255) >> 8) as u16;
        } else if m >= 16384 {
            bottomt[i / 2] = 256;
            bottomr[i / 2] = S[s_idx] as u16;
            s_idx += 1;
            M2[i / 2] = ((m + 255) >> 8) as u16;
        } else {
            bottomt[i / 2] = 1;
            bottomr[i / 2] = 0;
            M2[i / 2] = m as u16;
        }
        i += 2;
    }
    if i < M.len() {
        M2[i / 2] = M[i];
    }
    decode(&S[s_idx..], &M2, &mut R2);
    let mut i = 0;
    let mut out_idx = 0;
    while i < M.len() - 1 {
        let mut r = bottomr[i / 2] as u32;
        r += bottomt[i / 2] * R2[i / 2] as u32;
        let (r1, r0) = u32_divmod_u14(r, M[i]);
        let r1 = u32_mod_u14(r1, M[i + 1]);
        out[out_idx] = r0;
        out[out_idx + 1] = r1;
        out_idx += 2;
        i += 2;
    }
    if i < M.len() {
        out[out_idx] = R2[i / 2];
    }
}
