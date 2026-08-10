//! Fast volatile wiping of plain-integer scratch buffers.

use zeroize::{DefaultIsZeroes, Zeroize};

/// Wipe a plain-integer buffer with volatile stores, as wide as the platform
/// allows.
///
/// [`Zeroize`] on a slice issues one volatile store *per element*, which the
/// compiler is not permitted to merge or vectorize. Across the multi-kilobyte
/// scratch buffers the SIMD kernels use, that granularity — not the wiping
/// itself — dominated the cost: measured at roughly 18% of decapsulation for the
/// NTT multiply alone.
///
/// Re-viewing the buffer at a wider integer width keeps the volatile guarantee
/// exactly — any unaligned head and tail are still wiped, just at their own
/// width — while issuing proportionally fewer stores. `u64` is the portable
/// floor; on x86_64 a 32-byte store cuts it by a further factor of four, which
/// matters because the reference implementations wipe nothing at all and this
/// is cost they simply do not pay.
#[inline]
pub(crate) fn wipe<T: Zeroize + DefaultIsZeroes>(buf: &mut [T]) {
    #[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
    if crate::cpu::has_avx2() {
        // SAFETY: AVX2 confirmed present at runtime, which implies AVX.
        unsafe {
            wipe_avx(buf);
        }
        return;
    }
    wipe_u64(buf);
}

/// 32-byte volatile stores over the aligned interior.
#[cfg(all(target_arch = "x86_64", not(feature = "force-scalar")))]
#[target_feature(enable = "avx")]
unsafe fn wipe_avx<T: Zeroize + DefaultIsZeroes>(buf: &mut [T]) {
    use core::arch::x86_64::__m256i;
    // SAFETY: `T` is a plain integer with no padding and no invalid bit
    // patterns, so viewing the buffer's bytes as `__m256i` is valid.
    // `align_to_mut` guarantees the middle is correctly aligned for a volatile
    // store of that width and hands back whatever head and tail are not.
    unsafe {
        let (head, mid, tail) = buf.align_to_mut::<__m256i>();
        head.zeroize();
        let zero: __m256i = core::mem::zeroed();
        for slot in mid {
            core::ptr::write_volatile(slot, zero);
        }
        tail.zeroize();
    }
}

/// Portable eight-byte-at-a-time form.
fn wipe_u64<T: Zeroize + DefaultIsZeroes>(buf: &mut [T]) {
    // SAFETY: as above, at `u64` width.
    unsafe {
        let (head, mid, tail) = buf.align_to_mut::<u64>();
        head.zeroize();
        mid.zeroize();
        tail.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every byte must be cleared regardless of where the wide interior starts,
    /// so exercise every offset and length across an alignment period.
    #[test]
    fn clears_every_byte_at_every_alignment_and_length() {
        let mut backing = [0i16; 96];
        for off in 0..16usize {
            for len in 0..64usize {
                backing.fill(-1);
                wipe(&mut backing[off..off + len]);
                assert!(
                    backing[off..off + len].iter().all(|&x| x == 0),
                    "not cleared at off={off} len={len}"
                );
                assert!(
                    backing[..off].iter().all(|&x| x == -1)
                        && backing[off + len..].iter().all(|&x| x == -1),
                    "wiped outside the slice at off={off} len={len}"
                );
            }
        }
    }

    #[test]
    fn both_widths_agree_on_byte_data() {
        let mut a = [0u8; 200];
        let mut b = [0u8; 200];
        for off in 0..8usize {
            a.fill(0xAA);
            b.fill(0xAA);
            wipe(&mut a[off..]);
            wipe_u64(&mut b[off..]);
            assert_eq!(a, b, "widths disagree at off={off}");
        }
    }
}
