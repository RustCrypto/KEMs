#[inline(always)]
#[allow(clippy::cast_possible_truncation)]
pub fn freeze(a: i32) -> i8 {
    let b = a - (3 * ((10923 * a) >> 15));
    let c = b - (3 * ((89_478_485 * b + 134_217_728) >> 28));
    c as i8
}

#[inline(always)]
pub fn product(a: i8, b: i8) -> i8 {
    a * b
}

#[inline(always)]
pub fn reciprocal(a: i8) -> i8 {
    a
}

#[inline(always)]
pub fn quotient(a: i8, b: i8) -> i8 {
    product(a, reciprocal(b))
}

#[inline(always)]
pub fn minus_product(a: i8, b: i8, c: i8) -> i8 {
    freeze(a as i32 - b as i32 * c as i32)
}

#[inline(always)]
pub fn mask_set(x: i8) -> isize {
    (-x * x) as isize
}
