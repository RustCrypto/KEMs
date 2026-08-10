//! Runtime detection of AVX2 support, cached after the first check.
//!
//! The AVX2 kernels throughout this crate are marked `#[target_feature(enable = "avx2")]`,
//! which lets them compile regardless of the crate's ambient compilation flags. Whether to
//! *call* them is decided here, at runtime, so a default `cargo build --release` uses AVX2 on
//! any capable x86_64 host instead of silently falling back to scalar unless the caller passes
//! `RUSTFLAGS="-C target-feature=+avx2"` (or `target-cpu=native`).
//!
//! aarch64 needs no equivalent: NEON is a baseline guarantee of the architecture.

#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
static AVX2_STATE: AtomicU8 = AtomicU8::new(0);

#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
static AVXVNNI_STATE: AtomicU8 = AtomicU8::new(0);

#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
static AVX512_STATE: AtomicU8 = AtomicU8::new(0);

/// Returns `true` if the host CPU supports AVX2.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[inline]
pub(crate) fn has_avx2() -> bool {
    match AVX2_STATE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let detected = std::is_x86_feature_detected!("avx2");
            AVX2_STATE.store(if detected { 1 } else { 2 }, Ordering::Relaxed);
            detected
        }
    }
}

/// Returns `true` if the host CPU supports AVX-VNNI (the VEX-encoded `vpdpwssd`
/// family — Zen 5, Alder Lake and later).
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[inline]
pub(crate) fn has_avxvnni() -> bool {
    match AVXVNNI_STATE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let detected = std::is_x86_feature_detected!("avxvnni");
            AVXVNNI_STATE.store(if detected { 1 } else { 2 }, Ordering::Relaxed);
            detected
        }
    }
}

/// Returns `true` if the host CPU supports the AVX-512 subsets the 512-bit
/// kernels use: `F` for the base instruction set, `BW` for 16-bit lane
/// arithmetic and `VL` so 256-bit forms remain available alongside.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[inline]
pub(crate) fn has_avx512() -> bool {
    match AVX512_STATE.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let detected = std::is_x86_feature_detected!("avx512f")
                && std::is_x86_feature_detected!("avx512bw")
                && std::is_x86_feature_detected!("avx512vl");
            AVX512_STATE.store(if detected { 1 } else { 2 }, Ordering::Relaxed);
            detected
        }
    }
}

#[cfg(all(test, target_arch = "x86_64", not(feature = "force-scalar")))]
mod tests {
    use super::*;

    #[test]
    fn detection_is_cached_and_consistent() {
        let first = has_avx2();
        for _ in 0..8 {
            assert_eq!(has_avx2(), first);
        }
        let first = has_avxvnni();
        for _ in 0..8 {
            assert_eq!(has_avxvnni(), first);
        }
        let first = has_avx512();
        for _ in 0..8 {
            assert_eq!(has_avx512(), first);
        }
    }
}
