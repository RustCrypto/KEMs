//! Checking that our NTRU-Prime is generating same output when compared to nist submission

use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit},
    Aes256,
};
use hybrid_array::sizes::{U1013, U1277, U16, U32, U653, U761, U857, U953};
use itertools::{izip, Itertools};
use ntru::{
    encoded::AsymEnc,
    hashes::HashOps,
    kem::{decap, encap, key_gen},
    params::Streamlined,
};
use rand_core::{CryptoRng, RngCore, SeedableRng};

fn aes256_ecb(
    key: &GenericArray<u8, U32>,
    crt: &GenericArray<u8, U16>,
    buffer: &mut GenericArray<u8, U16>,
) {
    let cipher = Aes256::new(key);
    cipher.encrypt_block_b2b(crt, buffer);
}
struct AesDrbg {
    key: GenericArray<u8, U32>,
    v: GenericArray<u8, U16>,
}
impl AesDrbg {
    fn update(&mut self, seed_material: Option<&[u8; 48]>) {
        let mut tmp: [GenericArray<u8, U16>; 3] = Default::default();
        for i in 0..3 {
            for j in (1..=15).rev() {
                if self.v[j] == 0xff {
                    self.v[j] = 0x00;
                } else {
                    self.v[j] += 1;
                    break;
                }
            }
            aes256_ecb(&self.key, &self.v, &mut tmp[i]);
        }
        if let Some(seed) = seed_material {
            for i in 0..48 {
                tmp[i / 16][i % 16] ^= seed[i];
            }
        }
        self.key[..16].copy_from_slice(&tmp[0]);
        self.key[16..].copy_from_slice(&tmp[1]);
        self.v.copy_from_slice(&tmp[2]);
    }
}
impl CryptoRng for AesDrbg {}

struct U8L48([u8; 48]);

impl Default for U8L48 {
    fn default() -> Self {
        U8L48([0; 48])
    }
}

impl AsMut<[u8]> for U8L48 {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}
impl AsRef<[u8]> for U8L48 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl SeedableRng for AesDrbg {
    type Seed = U8L48;

    fn from_seed(seed: Self::Seed) -> Self {
        let entropy_input = seed.0;
        let mut drbg = AesDrbg {
            key: GenericArray::default(),
            v: GenericArray::default(),
        };
        drbg.update(Some(&entropy_input));
        drbg
    }
}

impl RngCore for AesDrbg {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        unimplemented!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let mut block = GenericArray::<u8, U16>::default();
        let mut i = 0;
        let mut xlen = dest.len();
        while xlen > 0 {
            for j in (1..=15).rev() {
                if self.v[j] == 0xff {
                    self.v[j] = 0x00;
                } else {
                    self.v[j] += 1;
                    break;
                }
            }
            aes256_ecb(&self.key, &self.v, &mut block);
            if xlen > 15 {
                dest[i..i + 16].copy_from_slice(&block);
                i += 16;
                xlen -= 16;
            } else {
                dest[i..i + xlen].copy_from_slice(&block[..xlen]);
                xlen = 0;
            }
        }
        self.update(None)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

fn seed_builder(max: usize) -> Vec<U8L48> {
    let mut seeds = Vec::with_capacity(100);
    let mut entropy = [0u8; 48];
    for i in 0u8..48 {
        entropy[i as usize] = i;
    }
    let mut rng = AesDrbg::from_seed(U8L48(entropy));
    for _ in 0..max {
        let mut s = U8L48::default();
        rng.fill_bytes(&mut s.0);
        seeds.push(s)
    }
    seeds
}

struct TestEntry {
    seed: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

impl TestEntry {
    fn from_file(path: &str) -> Vec<TestEntry> {
        let file = File::open(path).unwrap();
        let mut ret = Vec::with_capacity(100);
        for mut lines in &BufReader::new(file)
            .lines()
            .flatten()
            .filter(|x| !(x.is_empty() || x.starts_with('#')))
            .chunks(6)
        {
            lines.next(); // we ignore the count line
            let seed = hex::decode(lines.next().unwrap().split(" ").last().unwrap()).unwrap();
            let pk = hex::decode(lines.next().unwrap().split(" ").last().unwrap()).unwrap();
            let sk = hex::decode(lines.next().unwrap().split(" ").last().unwrap()).unwrap();
            let ct = hex::decode(lines.next().unwrap().split(" ").last().unwrap()).unwrap();
            let ss = hex::decode(lines.next().unwrap().split(" ").last().unwrap()).unwrap();
            ret.push(TestEntry {
                seed,
                pk,
                sk,
                ct,
                ss,
            });
        }
        assert_eq!(ret.len(), 100);
        ret
    }
}

#[test]
fn test_rng() {
    let seeds = seed_builder(100);
    let tests = TestEntry::from_file("test_data/ntrulpr653.rsp");
    for i in 0..100 {
        assert_eq!(seeds[i].as_ref(), &tests[i].seed)
    }
}

fn test_config<T: AsymEnc + HashOps>(config: &str) {
    let seeds = seed_builder(100);
    let path = format!("test_data/{config}.rsp");
    let tests = TestEntry::from_file(&path);
    for (seed, test) in izip!(seeds, tests) {
        let mut rng = AesDrbg::from_seed(seed);
        let (sk, pk) = key_gen::<T>(&mut rng);
        assert_eq!(&pk.0 as &[u8], &test.pk);
        assert_eq!(sk.to_bytes(), test.sk);
        let (ct, ss) = encap(&mut rng, &pk);
        assert_eq!(ct.to_bytes(), test.ct);
        assert_eq!(&ss as &[u8], &test.ss);
        let ss2: [u8; 32] = decap(&ct, &sk);
        assert_eq!(&ss2 as &[u8], &test.ss);
    }
}

#[test]
fn test_sntrup1013() {
    test_config::<Streamlined<U1013>>("sntrup1013");
}
#[test]
fn test_sntrup1277() {
    test_config::<Streamlined<U1277>>("sntrup1277");
}
#[test]
fn test_sntrup653() {
    test_config::<Streamlined<U653>>("sntrup653");
}
#[test]
fn test_sntrup761() {
    test_config::<Streamlined<U761>>("sntrup761");
}
#[test]
fn test_sntrup857() {
    test_config::<Streamlined<U857>>("sntrup857");
}
#[test]
fn test_sntrup953() {
    test_config::<Streamlined<U953>>("sntrup953");
}
