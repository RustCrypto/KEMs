//! sorting with data independent timing behavior

/// returns a tuple of two sorted elements such
/// that the first is always less or equal to the
/// second
fn minmax(xi: u32, yi: u32) -> (u32, u32) {
    let xy = xi ^ yi;
    let mut c = yi.wrapping_sub(xi);
    c ^= xy & (c ^ yi ^ 0x8000_0000);
    c >>= 31;
    c = (!c).wrapping_add(1);
    c &= xy;
    (xi ^ c, yi ^ c)
}

/// This function sorts a list in place taking the same
/// amount of time only depending on the size of the list.
pub fn crypto_sort_u32(list: &mut [u32]) {
    let n = list.len() as i32;
    if n < 2 {
        return;
    }
    let mut top = 1i32;
    while top < n.wrapping_sub(top) {
        top += top;
    }
    let mut p = top;
    while p > 0 {
        for i in 0..n.wrapping_sub(p) {
            if i & p == 0 {
                let (xi, yi) = minmax(list[i as usize], list[(i + p) as usize]);
                list[i as usize] = xi;
                list[(i + p) as usize] = yi;
            }
        }
        let mut q = top;
        while q > p {
            for i in 0..n.wrapping_sub(q) {
                if i & p == 0 {
                    let (xi, yi) = minmax(list[(i + p) as usize], list[(i + q) as usize]);
                    list[(i + p) as usize] = xi;
                    list[(i + q) as usize] = yi;
                }
            }
            q >>= 1;
        }
        p >>= 1;
    }
}

#[cfg(test)]
mod test {
    use super::{crypto_sort_u32, minmax};
    #[test]
    fn test_minmax_zero() {
        assert_eq!(minmax(0, 0), (0, 0));
    }
    #[test]
    fn test_minmax_sorted() {
        assert_eq!(minmax(1, 2), (1, 2));
    }
    #[test]
    fn test_minmax_unsorted() {
        assert_eq!(minmax(2, 1), (1, 2));
    }
    #[test]
    fn test_minmax_identical() {
        assert_eq!(minmax(1, 1), (1, 1));
    }
    #[test]
    fn test_minmax_large_sorted() {
        assert_eq!(minmax(u32::MAX - 1, u32::MAX), (u32::MAX - 1, u32::MAX));
    }
    #[test]
    fn test_minmax_large_unsorted() {
        assert_eq!(minmax(u32::MAX, u32::MAX - 1), (u32::MAX - 1, u32::MAX));
    }
    #[test]
    fn test_minmax_large_identical() {
        assert_eq!(minmax(u32::MAX, u32::MAX), (u32::MAX, u32::MAX));
    }
    #[test]
    fn test_one_item_sort() {
        let mut v = vec![1];
        crypto_sort_u32(&mut v);
        assert_eq!(v, [1]);
    }
    #[test]
    fn test_minmax_large_small() {
        assert_eq!(minmax(u32::MAX - 1, 4), (4, u32::MAX - 1));
    }
    #[test]
    fn test_minmax_small_large() {
        assert_eq!(minmax(4, u32::MAX), (4, u32::MAX));
    }
    #[test]
    fn test_empty_item_sort() {
        let mut v = vec![];
        crypto_sort_u32(&mut v);
        assert_eq!(v, []);
    }

    #[test]
    fn test_two_item_sort() {
        let mut v = vec![1, 2];
        crypto_sort_u32(&mut v);
        assert_eq!(v, [1, 2]);
        let mut v = vec![2, 1];
        crypto_sort_u32(&mut v);
        assert_eq!(v, [1, 2]);
    }
    #[test]
    fn test_sort_zeros() {
        let mut v = vec![0; 100];
        crypto_sort_u32(&mut v);
        assert_eq!(v, &[0; 100]);
    }
    #[test]
    fn test_sort_ordered() {
        let mut v: Vec<_> = (0..100).collect();
        crypto_sort_u32(&mut v);
        assert_eq!(v, (0..100).collect::<Vec<u32>>());
    }

    #[test]
    fn test_sort_rev() {
        let mut v: Vec<_> = (0..100).rev().collect();
        crypto_sort_u32(&mut v);
        assert_eq!(v, (0..100).collect::<Vec<u32>>());
    }
    #[test]
    fn test_sort_large() {
        let mut v: Vec<_> = (u32::MAX - 10000..u32::MAX).rev().collect();
        crypto_sort_u32(&mut v);
        assert_eq!(v, (u32::MAX - 10000..u32::MAX).collect::<Vec<u32>>());
    }

    #[test]
    fn test_sort_long() {
        let mut v: Vec<_> = (0..1000000).rev().collect();
        crypto_sort_u32(&mut v);
        assert_eq!(v, (0..1000000).collect::<Vec<u32>>());
    }
}
