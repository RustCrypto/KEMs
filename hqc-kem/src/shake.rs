/// SHAKE256-based seed expander and domain-separated hash functions.
///
/// v5.0.0 domain bytes:
/// - 0x00: G function (SHA3-512), KAT PRNG
/// - 0x01: H function (SHA3-256), XOF seed expander
/// - 0x02: I function (SHA3-512, PKE keygen)
/// - 0x03: J function (SHA3-256, rejection key)
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Sha3_512, Shake256};

/// Domain separation bytes.
pub(crate) const DOMAIN_G: u8 = 0x00;
pub(crate) const DOMAIN_H: u8 = 0x01;
pub(crate) const DOMAIN_I: u8 = 0x02;
pub(crate) const DOMAIN_J: u8 = 0x03;
pub(crate) const DOMAIN_XOF: u8 = 0x01;

/// SHAKE256-based seed expander with 8-byte aligned reads.
pub(crate) struct SeedExpander {
    reader: <Shake256 as ExtendableOutput>::Reader,
}

impl SeedExpander {
    /// Initialize: SHAKE256(seed || domain_byte), then finalize for squeezing.
    pub(crate) fn new(seed: &[u8]) -> Self {
        let mut hasher = Shake256::default();
        hasher.update(seed);
        hasher.update(&[DOMAIN_XOF]);
        Self {
            reader: hasher.finalize_xof(),
        }
    }

    /// Read `sz` bytes with 8-byte alignment waste.
    ///
    /// After reading `sz` bytes, discards `(8 - sz%8) % 8` bytes to maintain
    /// 8-byte alignment of the XOF stream. This matches the v5.0.0 `xof_get_bytes`.
    pub(crate) fn get_bytes(&mut self, output: &mut [u8]) {
        self.reader.read(output);
        let remainder = output.len() % 8;
        if remainder != 0 {
            let mut waste = [0u8; 8];
            self.reader.read(&mut waste[..8 - remainder]);
        }
    }

    /// Raw squeeze without alignment waste. Used in KEM keygen for seed_pke and sigma.
    pub(crate) fn read_raw(&mut self, output: &mut [u8]) {
        self.reader.read(output);
    }
}

/// G function: SHA3-512(data || 0x00). Returns 64 bytes.
pub(crate) fn hash_g(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::default();
    Update::update(&mut hasher, data);
    Update::update(&mut hasher, &[DOMAIN_G]);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// H function: SHA3-256(data || 0x01). Returns 32 bytes.
pub(crate) fn hash_h(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::default();
    Update::update(&mut hasher, data);
    Update::update(&mut hasher, &[DOMAIN_H]);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// I function: SHA3-512(data || 0x02). Returns 64 bytes.
pub(crate) fn hash_i(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha3_512::default();
    Update::update(&mut hasher, data);
    Update::update(&mut hasher, &[DOMAIN_I]);
    let result = hasher.finalize();
    let mut out = [0u8; 64];
    out.copy_from_slice(&result);
    out
}

/// J function: SHA3-256(data || 0x03). Returns 32 bytes.
pub(crate) fn hash_j(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::default();
    Update::update(&mut hasher, data);
    Update::update(&mut hasher, &[DOMAIN_J]);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}
