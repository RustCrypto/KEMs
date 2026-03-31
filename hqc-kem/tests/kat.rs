//! Known Answer Tests for HQC-KEM.
//!
//! Tests use the KAT PRNG (SHAKE256 with domain byte 0x00) to generate
//! deterministic randomness matching the v5.0.0 reference implementation.

use hqc_kem::{hqc128, hqc192, hqc256};

/// KAT PRNG: wraps the internal SHAKE256-based PRNG.
/// Implements rand TryRng + TryCryptoRng (rand 0.10) for use with the API.
struct KatRng {
    reader: sha3::digest::core_api::XofReaderCoreWrapper<sha3::Shake256ReaderCore>,
}

impl KatRng {
    fn new(seed: &[u8]) -> Self {
        use sha3::digest::{ExtendableOutput, Update};
        let mut hasher = sha3::Shake256::default();
        hasher.update(seed);
        hasher.update(&[0x00]); // KAT PRNG domain byte
        Self {
            reader: hasher.finalize_xof(),
        }
    }
}

impl rand::TryRng for KatRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut buf = [0u8; 4];
        self.try_fill_bytes(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut buf = [0u8; 8];
        self.try_fill_bytes(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        use sha3::digest::XofReader;
        self.reader.read(dest);
        Ok(())
    }
}

impl rand::TryCryptoRng for KatRng {}

/// Parse a KAT .rsp file and extract the first test vector.
fn parse_kat(content: &str) -> (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) {
    let mut seed = Vec::new();
    let mut pk = Vec::new();
    let mut sk = Vec::new();
    let mut ct = Vec::new();
    let mut ss = Vec::new();

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("seed = ") {
            seed = hex::decode(&line[7..]).expect("invalid hex in seed");
        } else if line.starts_with("pk = ") {
            pk = hex::decode(&line[5..]).expect("invalid hex in pk");
        } else if line.starts_with("sk = ") {
            sk = hex::decode(&line[5..]).expect("invalid hex in sk");
        } else if line.starts_with("ct = ") {
            ct = hex::decode(&line[5..]).expect("invalid hex in ct");
        } else if line.starts_with("ss = ") {
            ss = hex::decode(&line[5..]).expect("invalid hex in ss");
        }
    }

    (seed, pk, sk, ct, ss)
}

#[test]
fn test_hqc128_kat() {
    let content = include_str!("../kat/hqc-1.rsp");
    let (seed, expected_pk, expected_sk, expected_ct, expected_ss) = parse_kat(content);

    // Initialize KAT PRNG with the seed
    let mut rng = KatRng::new(&seed);

    // Key generation
    let (ek, dk) = hqc128::generate_key(&mut rng);

    // Check public key
    assert_eq!(ek.as_ref(), &expected_pk[..], "HQC-128 public key mismatch");

    // Check secret key
    assert_eq!(dk.as_ref(), &expected_sk[..], "HQC-128 secret key mismatch");

    // Encapsulation (uses same RNG)
    let (ct, ss) = ek.encapsulate(&mut rng);

    // Check ciphertext
    assert_eq!(ct.as_ref(), &expected_ct[..], "HQC-128 ciphertext mismatch");

    // Check shared secret
    assert_eq!(
        ss.as_ref(),
        &expected_ss[..],
        "HQC-128 shared secret mismatch"
    );

    // Decapsulation
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss.as_ref(), ss2.as_ref(), "HQC-128 decapsulation mismatch");
}

#[test]
fn test_hqc192_kat() {
    let content = include_str!("../kat/hqc-3.rsp");
    let (seed, expected_pk, expected_sk, expected_ct, expected_ss) = parse_kat(content);
    let mut rng = KatRng::new(&seed);
    let (ek, dk) = hqc192::generate_key(&mut rng);
    assert_eq!(ek.as_ref(), &expected_pk[..], "HQC-192 public key mismatch");
    assert_eq!(dk.as_ref(), &expected_sk[..], "HQC-192 secret key mismatch");
    let (ct, ss) = ek.encapsulate(&mut rng);
    assert_eq!(ct.as_ref(), &expected_ct[..], "HQC-192 ciphertext mismatch");
    assert_eq!(
        ss.as_ref(),
        &expected_ss[..],
        "HQC-192 shared secret mismatch"
    );
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss.as_ref(), ss2.as_ref(), "HQC-192 decapsulation mismatch");
}

#[test]
fn test_hqc256_kat() {
    let content = include_str!("../kat/hqc-5.rsp");
    let (seed, expected_pk, expected_sk, expected_ct, expected_ss) = parse_kat(content);
    let mut rng = KatRng::new(&seed);
    let (ek, dk) = hqc256::generate_key(&mut rng);
    assert_eq!(ek.as_ref(), &expected_pk[..], "HQC-256 public key mismatch");
    assert_eq!(dk.as_ref(), &expected_sk[..], "HQC-256 secret key mismatch");
    let (ct, ss) = ek.encapsulate(&mut rng);
    assert_eq!(ct.as_ref(), &expected_ct[..], "HQC-256 ciphertext mismatch");
    assert_eq!(
        ss.as_ref(),
        &expected_ss[..],
        "HQC-256 shared secret mismatch"
    );
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss.as_ref(), ss2.as_ref(), "HQC-256 decapsulation mismatch");
}

#[test]
fn test_hqc128_roundtrip() {
    let mut rng = rand::rng();
    let (ek, dk) = hqc128::generate_key(&mut rng);
    let (ct, ss1) = ek.encapsulate(&mut rng);
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss1, ss2, "HQC-128 roundtrip failed");
}

#[test]
fn test_hqc192_roundtrip() {
    let mut rng = rand::rng();
    let (ek, dk) = hqc192::generate_key(&mut rng);
    let (ct, ss1) = ek.encapsulate(&mut rng);
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss1, ss2, "HQC-192 roundtrip failed");
}

#[test]
fn test_hqc256_roundtrip() {
    let mut rng = rand::rng();
    let (ek, dk) = hqc256::generate_key(&mut rng);
    let (ct, ss1) = ek.encapsulate(&mut rng);
    let ss2 = dk.decapsulate(&ct);
    assert_eq!(ss1, ss2, "HQC-256 roundtrip failed");
}
