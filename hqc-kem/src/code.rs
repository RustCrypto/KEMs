/// Concatenated code: Reed-Solomon then Reed-Muller.
use crate::params::HqcParameters;
use crate::reed_muller;
use crate::reed_solomon;

/// Encode message: RS encode then RM encode.
pub(crate) fn code_encode(em: &mut [u64], m: &[u8], p: &HqcParameters) {
    let mut tmp = vec![0u8; p.n1];
    reed_solomon::reed_solomon_encode(&mut tmp, m, p);
    reed_muller::reed_muller_encode(em, &tmp, p);
}

/// Decode codeword: RM decode then RS decode.
pub(crate) fn code_decode(m: &mut [u8], em: &[u64], p: &HqcParameters) {
    let mut tmp = vec![0u8; p.n1];
    reed_muller::reed_muller_decode(&mut tmp, em, p);
    reed_solomon::reed_solomon_decode(m, &mut tmp, p);
}
