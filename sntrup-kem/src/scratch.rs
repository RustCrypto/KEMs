//! Stack scratch buffers that skip Rust's implicit zero-fill.
//!
//! The SIMD kernels work out of multi-kilobyte fixed-size stack arrays that are
//! written in full before anything reads them. Declaring those as `[0i16; N]`
//! makes the compiler emit a `memset` it cannot then eliminate — the producers
//! are opaque `#[target_feature]` calls, so LLVM cannot prove the overwrite.
//! Measured at 5.9% of a decapsulation (roughly 61 KB zeroed per call), against
//! a reference implementation that pays none of it.
//!
//! The obligation this trades for is real: every element must be written before
//! it is read. Rather than leave that as a comment, debug builds fill the buffer
//! with [`POISON`] instead of leaving it indeterminate, so a producer that skips
//! an element produces visibly wrong output in the differential and KAT suites
//! instead of silent nondeterminism. Release builds skip the fill entirely,
//! which is the point.

use core::mem::MaybeUninit;

/// Debug-build fill byte for scratch declared through [`uninit`].
///
/// `0x5A5A` as an `i16` is 23130 — outside every coefficient range in the
/// crate by a wide margin, and not a plausible near-miss for zero.
const POISON: u8 = 0x5A;

/// Views owned, uninitialized stack storage as the array it will become.
///
/// # Safety
/// `T` must be a plain integer type, for which every bit pattern is a valid
/// value. The caller must write every element of the returned buffer before
/// reading any element of it.
#[inline(always)]
pub(crate) unsafe fn uninit<T, const N: usize>(slot: &mut MaybeUninit<[T; N]>) -> &mut [T; N] {
    if cfg!(debug_assertions) {
        // SAFETY: `slot` is owned, properly aligned storage of exactly this
        // size, and `T` admits every bit pattern, so filling it with bytes
        // produces valid (if deliberately absurd) values.
        unsafe {
            core::ptr::write_bytes(slot.as_mut_ptr().cast::<u8>(), POISON, size_of::<[T; N]>());
        }
    }
    // SAFETY: debug builds initialized the storage above. Release builds rely on
    // the caller's documented contract that every element is written before any
    // read; `T` has no invalid bit patterns, so forming the reference itself is
    // well-defined regardless.
    unsafe { slot.assume_init_mut() }
}

/// Declares a stack scratch buffer without the implicit zero-fill.
///
/// Expands to `let $name: &mut [$t; $n]`. Each use site must justify, in a
/// `SAFETY:` comment, that every element is written before it is read — see
/// the module documentation for how debug builds check that claim.
///
/// This form introduces its own `unsafe` block, so it is for callers in safe
/// code. Code already inside an `unsafe` block — the SIMD kernels — calls
/// [`uninit`] directly instead, to avoid a redundant nested block.
macro_rules! uninit_scratch {
    ($name:ident: [$t:ty; $n:expr]) => {
        let mut $name = core::mem::MaybeUninit::<[$t; $n]>::uninit();
        let $name = unsafe { $crate::scratch::uninit(&mut $name) };
    };
}

pub(crate) use uninit_scratch;

#[cfg(test)]
mod tests {
    use super::POISON;

    #[test]
    fn debug_builds_poison_and_release_builds_do_not_fill() {
        uninit_scratch!(buf: [i16; 64]);
        if cfg!(debug_assertions) {
            assert!(
                buf.iter().all(|&x| x == 0x5A5A),
                "debug builds must poison so a missed write is visible"
            );
        }
        // The contract is write-before-read; writing in full is always sound.
        buf.fill(7);
        assert!(buf.iter().all(|&x| x == 7));
    }

    #[test]
    fn poison_is_outside_every_coefficient_range() {
        // A poison value that could pass for a real coefficient would let a
        // missed write survive the differential suites, so tie the check to the
        // actual parameter sets rather than to a hardcoded bound.
        use crate::params::SntrupParams;
        let widest = [
            crate::params::Sntrup653Params::params(),
            crate::params::Sntrup761Params::params(),
            crate::params::Sntrup857Params::params(),
            crate::params::Sntrup953Params::params(),
            crate::params::Sntrup1013Params::params(),
            crate::params::Sntrup1277Params::params(),
        ]
        .iter()
        .map(|p| p.q12)
        .max()
        .unwrap_or(i32::MAX);
        let poison = i16::from_ne_bytes([POISON, POISON]);
        assert!(
            i32::from(poison) > widest,
            "poison {poison} is inside the +/-{widest} coefficient range"
        );
    }
}
