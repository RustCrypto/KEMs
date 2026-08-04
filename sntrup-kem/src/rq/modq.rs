/// Barrett reduction: freezes `a` into the range (-q/2, q/2).
///
/// `barrett1` = floor(2^20 / q), `barrett2` = floor(2^28 / q).
#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub fn freeze(a: i32, q: i32, barrett1: i32, barrett2: i32) -> i16 {
    let mut b = a;
    b -= q * ((barrett1 * b) >> 20);
    b -= q * ((barrett2 * b + 134_217_728) >> 28);
    b as i16
}

#[inline(always)]
pub fn product(a: i16, b: i16, q: i32, b1: i32, b2: i32) -> i16 {
    freeze(a as i32 * b as i32, q, b1, b2)
}

#[inline(always)]
pub fn square(a: i16, q: i32, b1: i32, b2: i32) -> i16 {
    let a32 = a as i32;
    freeze(a32 * a32, q, b1, b2)
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

    // Square-and-multiply from the second-highest bit down
    let mut result = a1;
    for i in (0..(bits - 1)).rev() {
        result = square(result, q, b1, b2);
        if (exp >> i) & 1 == 1 {
            result = product(result, a1, q, b1, b2);
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
