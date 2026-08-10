/// Barrett reduction: freezes `a` into the canonical range [-(q-1)/2, (q-1)/2].
///
/// `barrett1` = floor(2^20 / q), `barrett2` = floor(2^28 / q).
///
/// The two Barrett steps alone can land up to ±3 outside the canonical range for
/// a few thousand inputs per parameter set (exhaustively scanned over the live
/// |a| ≤ (q-1)/2 + ((q-1)/2)^2 window). A non-canonical coefficient wraps
/// negative in `rq_encode`'s `+ q12` bias and corrupts the variable-radix
/// encoding, so a final branchless correction makes the output strictly
/// canonical — matching the reference implementation's exact freeze. Every SIMD
/// freeze implementation applies the same correction so all paths produce
/// byte-identical results.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub fn freeze(a: i32, q: i32, barrett1: i32, barrett2: i32) -> i16 {
    let mut b = a;
    b -= q * ((barrett1 * b) >> 20);
    b -= q * ((barrett2 * b + 134_217_728) >> 28);
    let hq = (q - 1) >> 1;
    b -= q & ((hq - b) >> 31); // b > hq  → subtract q
    b += q & ((b + hq) >> 31); // b < -hq → add q
    b as i16
}

#[inline(always)]
pub fn product(a: i16, b: i16, q: i32, b1: i32, b2: i32) -> i16 {
    freeze(a as i32 * b as i32, q, b1, b2)
}

/// The two Barrett steps without the strict-canonical correction: output may land
/// up to ±3 outside ±(q-1)/2, but is always the correct residue and maps a zero
/// residue to literal 0 (exhaustively scanned per parameter set). Used only for
/// intermediate chain values inside [`reciprocal`], where the serial dependency
/// makes the correction's latency expensive and a later strict [`freeze`]
/// canonicalizes anything that escapes.
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
fn freeze_loose(a: i32, q: i32, barrett1: i32, barrett2: i32) -> i16 {
    let mut b = a;
    b -= q * ((barrett1 * b) >> 20);
    b -= q * ((barrett2 * b + 134_217_728) >> 28);
    b as i16
}

#[inline(always)]
fn product_loose(a: i16, b: i16, q: i32, b1: i32, b2: i32) -> i16 {
    freeze_loose(a as i32 * b as i32, q, b1, b2)
}

#[inline(always)]
fn square_loose(a: i16, q: i32, b1: i32, b2: i32) -> i16 {
    let a32 = a as i32;
    freeze_loose(a32 * a32, q, b1, b2)
}

/// Compute `a1^(q-2) mod q` via Fermat's little theorem using binary
/// exponentiation (square-and-multiply). This is constant-time because
/// `q` is a public parameter.
#[inline(always)]
pub fn reciprocal(a1: i16, q: i32, b1: i32, b2: i32) -> i16 {
    #[allow(clippy::cast_sign_loss)]
    let exp = (q - 2) as u32;
    // Find the highest set bit position
    let bits = 32 - exp.leading_zeros(); // number of significant bits

    // Square-and-multiply from the second-highest bit down. Chain values stay in
    // the loose (residue-correct, near-canonical) domain; callers that need a
    // canonical result apply a strict freeze afterwards (quotient's final
    // product does).
    let mut result = a1;
    for i in (0..(bits - 1)).rev() {
        result = square_loose(result, q, b1, b2);
        if (exp >> i) & 1 == 1 {
            result = product_loose(result, a1, q, b1, b2);
        }
    }
    result
}

#[inline(always)]
pub fn quotient(a: i16, b: i16, q: i32, b1: i32, b2: i32) -> i16 {
    product(a, reciprocal(b, q, b1, b2), q, b1, b2)
}

#[inline(always)]
pub fn minus_product(a: i16, b: i16, c: i16, q: i32, b1: i32, b2: i32) -> i16 {
    freeze(a as i32 - (b as i32 * c as i32), q, b1, b2)
}

/// Constant-time: returns -1 if x != 0, 0 if x == 0.
#[inline(always)]
#[allow(clippy::cast_sign_loss)]
pub fn mask_set(x: i16) -> isize {
    let mut r = (x as u16) as i32;
    r = -r;
    r >>= 31;
    r as isize
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Strict canonical-range property over the live input window, all six
    /// parameter sets. The pre-fix two-step Barrett freeze violated this for a
    /// few thousand inputs per set (up to ±3 outside canonical), which wraps
    /// negative in `rq_encode`'s bias and corrupts the variable-radix encoding —
    /// this test fails against that implementation and pins the fix.
    #[test]
    fn freeze_is_strictly_canonical_and_residue_correct() {
        for &(q, b1, b2) in &[
            (4621i32, 226i32, 58084i32),
            (4591, 228, 58464),
            (5167, 202, 51948),
            (6343, 165, 42324),
            (7177, 146, 37410),
            (7879, 133, 34073),
        ] {
            let hq = (q - 1) / 2;
            let lim = hq + hq * hq;
            // Exhaustive canonical-range check over the full live window — the
            // pre-fix freeze's violations are scattered through the interior, so
            // sampling would miss them.
            let mut a = -lim;
            while a <= lim {
                let r = i32::from(freeze(a, q, b1, b2));
                assert!(
                    (-hq..=hq).contains(&r),
                    "freeze({a}) = {r} outside canonical ±{hq} for q={q}"
                );
                a += 1;
            }
            // Residue correctness on a strided sample (division is the slow part).
            let mut a = -lim;
            while a <= lim {
                let r = i32::from(freeze(a, q, b1, b2));
                assert_eq!((r - a).rem_euclid(q), 0, "wrong residue for q={q} a={a}");
                a += 997;
            }
            // Every zero-residue input must freeze to literal 0 (mask_set relies on it).
            let mut a = -(lim / q) * q;
            while a <= lim {
                assert_eq!(freeze(a, q, b1, b2), 0, "freeze({a}) != 0 for q={q}");
                a += q;
            }
        }
    }
}
