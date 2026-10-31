//! Runtime CPU feature detection for x86-64 SIMD dispatch.
//!
//! AVX2 kernels are compiled with `#[target_feature(enable = "avx2")]` even
//! when AVX2 is not enabled for the crate as a whole. Every call to one of
//! those kernels must therefore be guarded by [`has_avx2`].

use core::sync::atomic::{AtomicU8, Ordering};

// 0 is unknown, 1 is supported, and 2 is unsupported.
static AVX2_STATE: AtomicU8 = AtomicU8::new(0);

/// Returns whether the host CPU supports AVX2.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_is_cached_and_consistent() {
        let first = has_avx2();
        assert_eq!(first, std::is_x86_feature_detected!("avx2"));
        for _ in 0..8 {
            assert_eq!(has_avx2(), first);
        }
    }
}
