//! Random number generator for testing
//! AES-CTR DRBG
use aes::{
    Aes256Enc, Block,
    cipher::{BlockEncrypt, KeyInit},
};
use hybrid_array::{Array, typenum::U48};
use rand_core::{CryptoRng, Error, RngCore, SeedableRng};

/// Seed type for the AES-CTR DRBG
pub type RngSeed = Array<u8, U48>;

/// AES-CTR DRBG
#[derive(Debug, Default, Copy, Clone)]
pub struct AesCtrDrbg {
    reseed_counter: usize,
    key: [u8; 32],
    counter: [u8; 16],
}

impl SeedableRng for AesCtrDrbg {
    type Seed = RngSeed;

    fn from_seed(seed: Self::Seed) -> Self {
        let mut rng = Self::default();
        rng.update(Some(&seed));
        rng.reseed_counter = 1;
        rng
    }
}

impl RngCore for AesCtrDrbg {
    fn next_u32(&mut self) -> u32 {
        let mut int = [0u8; 4];
        self.fill_bytes(&mut int);
        u32::from_le_bytes(int)
    }

    fn next_u64(&mut self) -> u64 {
        let mut int = [0u8; 8];
        self.fill_bytes(&mut int);
        u64::from_le_bytes(int)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut in_block = Block::default();
        let mut out_block = Block::default();
        let enc = Aes256Enc::new_from_slice(&self.key).unwrap();
        let chunks = dest.len() / 16;
        let leftover = dest.len() % 16;

        for i in 0..chunks {
            self.increment_counter();
            in_block.copy_from_slice(&self.counter);
            enc.encrypt_block_b2b(&in_block, &mut out_block);
            dest[16 * i..16 * (i + 1)].copy_from_slice(&out_block);
        }
        if leftover != 0 {
            self.increment_counter();
            in_block.copy_from_slice(&self.counter);
            enc.encrypt_block_b2b(&in_block, &mut out_block);
            dest[16 * chunks..].copy_from_slice(&out_block[..leftover]);
        }

        self.update(None);
        self.reseed_counter += 1;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for AesCtrDrbg {}

impl AesCtrDrbg {
    /// Reseed the DRBG with a new seed
    pub fn reseed(&mut self, seed: &RngSeed) {
        self.counter.iter_mut().for_each(|c| *c = 0);
        self.key.iter_mut().for_each(|k| *k = 0);

        self.update(Some(seed));
        self.reseed_counter = 1;
    }

    fn update(&mut self, provided_data: Option<&RngSeed>) {
        let mut in_block = Block::default();
        let mut out_block = Block::default();
        let enc = Aes256Enc::new_from_slice(&self.key).unwrap();

        let mut temp = [0u8; 48];

        for i in 0..3 {
            self.increment_counter();
            in_block.copy_from_slice(&self.counter);
            enc.encrypt_block_b2b(&in_block, &mut out_block);
            temp[16 * i..16 * (i + 1)].copy_from_slice(&out_block);
        }
        if let Some(provided_data) = provided_data {
            for (t, pd) in temp.iter_mut().zip(provided_data.iter()) {
                *t ^= pd;
            }
        }
        self.key.copy_from_slice(&temp[..32]);
        self.counter.copy_from_slice(&temp[32..]);
    }

    fn increment_counter(&mut self) {
        for j in (0..=15).rev() {
            if self.counter[j] == 0xff {
                self.counter[j] = 0x00;
            } else {
                self.counter[j] += 1;
                break;
            }
        }
    }
}
