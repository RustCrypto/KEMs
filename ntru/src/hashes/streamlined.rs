use super::{hash_prefix, hash_prefix_many, HashOps};
use crate::params::{Streamlined, StreamlinedNtru};
use hybrid_array::{Array, ArraySize};

impl<P> HashOps for Streamlined<P>
where
    P: ArraySize,
    Streamlined<P>: StreamlinedNtru + Sized,
{
    fn hash_session(b: u8, y: &[&[u8]]) -> [u8; 32] {
        let x = hash_prefix(3, y[0]);
        hash_prefix_many(b, &x, &y[1..])
    }

    fn hash_confirm<Params: crate::encoded::AsymEnc>(
        r: &Array<u8, Params::InputsBytes>,
        cache: &[u8; 32],
    ) -> [u8; 32] {
        let x = hash_prefix(3, r);
        hash_prefix_many(2, &x, &[cache])
    }
}
