//! Shared x86_64 SIMD helpers for the multiply kernels in `rq` and `r3`.
//!
//! The two row-major schoolbook kernels differ only in how they accumulate
//! `i16×i16` dot-product terms into i32 lanes. These helpers isolate that step so
//! one kernel body (expanded per feature level by a macro in each module) serves
//! both instruction sets:
//!
//! - [`mac_madd`]: plain AVX2 — `vpmaddwd` then a separate `vpaddd`.
//! - [`mac_vnni`]: AVX-VNNI — a single fused `vpdpwssd` (Zen 5, Alder Lake+),
//!   removing one instruction and one dependency per 16 multiply-accumulates.
#![allow(unsafe_code)]

use core::arch::x86_64::{__m256i, _mm256_add_epi32, _mm256_madd_epi16};

/// `acc + Σ_pairs(a·b)` via `vpmaddwd` + `vpaddd`.
#[inline]
#[target_feature(enable = "avx2")]
pub(crate) fn mac_madd(acc: __m256i, a: __m256i, b: __m256i) -> __m256i {
    _mm256_add_epi32(acc, _mm256_madd_epi16(a, b))
}

/// `acc + Σ_pairs(a·b)` via the fused `vpdpwssd`.
#[inline]
#[target_feature(enable = "avx2,avxvnni")]
pub(crate) fn mac_vnni(acc: __m256i, a: __m256i, b: __m256i) -> __m256i {
    core::arch::x86_64::_mm256_dpwssd_avx_epi32(acc, a, b)
}
