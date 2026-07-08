//! Known Answer Tests for HQC-KEM.
//!
//! Tests use the KAT PRNG (SHAKE256 with domain byte 0x00) to generate
//! deterministic randomness matching the official reference implementation
//! at commit 161cd4f (2026-02-10). All 100 vectors per level are verified.
#![cfg(all(feature = "kgen", feature = "ecap", feature = "dcap"))]

use hqc_kem::{hqc128, hqc192, hqc256};

/// KAT PRNG: wraps the internal SHAKE256-based PRNG.
/// Implements rand TryRng + TryCryptoRng (rand 0.10) for use with the API.
struct KatRng {
    reader: shake::Shake256Reader,
}

impl KatRng {
    fn new(seed: &[u8]) -> Self {
        use shake::{ExtendableOutput, Update};
        let mut hasher = shake::Shake256::default();
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
        use shake::XofReader;
        self.reader.read(dest);
        Ok(())
    }
}

impl rand::TryCryptoRng for KatRng {}

struct KatVector {
    count: usize,
    seed: Vec<u8>,
    pk: Vec<u8>,
    sk: Vec<u8>,
    ct: Vec<u8>,
    ss: Vec<u8>,
}

/// Parse a KAT .rsp file into all of its test vectors.
fn parse_kat(content: &str) -> Vec<KatVector> {
    let mut vectors = Vec::new();
    let mut current: Option<KatVector> = None;

    for line in content.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("count = ") {
            if let Some(v) = current.take() {
                vectors.push(v);
            }
            current = Some(KatVector {
                count: val.parse().expect("invalid count"),
                seed: Vec::new(),
                pk: Vec::new(),
                sk: Vec::new(),
                ct: Vec::new(),
                ss: Vec::new(),
            });
        } else if let Some(v) = current.as_mut() {
            if let Some(val) = line.strip_prefix("seed = ") {
                v.seed = hex::decode(val).expect("invalid hex in seed");
            } else if let Some(val) = line.strip_prefix("pk = ") {
                v.pk = hex::decode(val).expect("invalid hex in pk");
            } else if let Some(val) = line.strip_prefix("sk = ") {
                v.sk = hex::decode(val).expect("invalid hex in sk");
            } else if let Some(val) = line.strip_prefix("ct = ") {
                v.ct = hex::decode(val).expect("invalid hex in ct");
            } else if let Some(val) = line.strip_prefix("ss = ") {
                v.ss = hex::decode(val).expect("invalid hex in ss");
            }
        }
    }
    if let Some(v) = current.take() {
        vectors.push(v);
    }
    vectors
}

#[test]
fn test_hqc128_kat() {
    let content = include_str!("../kat/hqc-1.rsp");
    let kats = parse_kat(content);
    assert_eq!(kats.len(), 100, "expected the full official vector set");
    for kat in &kats {
        let c = kat.count;
        let mut rng = KatRng::new(&kat.seed);
        let (ek, dk) = hqc128::generate_key(&mut rng);
        assert_eq!(ek.as_ref(), &kat.pk[..], "HQC-128 pk mismatch at count {c}");
        assert_eq!(dk.as_ref(), &kat.sk[..], "HQC-128 sk mismatch at count {c}");
        let (ct, ss) = ek.encapsulate(&mut rng);
        assert_eq!(ct.as_ref(), &kat.ct[..], "HQC-128 ct mismatch at count {c}");
        assert_eq!(ss.as_ref(), &kat.ss[..], "HQC-128 ss mismatch at count {c}");
        let ss2 = dk.decapsulate(&ct);
        assert_eq!(
            ss.as_ref(),
            ss2.as_ref(),
            "HQC-128 decaps mismatch at count {c}"
        );
    }
}

#[test]
fn test_hqc192_kat() {
    let content = include_str!("../kat/hqc-3.rsp");
    let kats = parse_kat(content);
    assert_eq!(kats.len(), 100, "expected the full official vector set");
    for kat in &kats {
        let c = kat.count;
        let mut rng = KatRng::new(&kat.seed);
        let (ek, dk) = hqc192::generate_key(&mut rng);
        assert_eq!(ek.as_ref(), &kat.pk[..], "HQC-192 pk mismatch at count {c}");
        assert_eq!(dk.as_ref(), &kat.sk[..], "HQC-192 sk mismatch at count {c}");
        let (ct, ss) = ek.encapsulate(&mut rng);
        assert_eq!(ct.as_ref(), &kat.ct[..], "HQC-192 ct mismatch at count {c}");
        assert_eq!(ss.as_ref(), &kat.ss[..], "HQC-192 ss mismatch at count {c}");
        let ss2 = dk.decapsulate(&ct);
        assert_eq!(
            ss.as_ref(),
            ss2.as_ref(),
            "HQC-192 decaps mismatch at count {c}"
        );
    }
}

#[test]
fn test_hqc256_kat() {
    let content = include_str!("../kat/hqc-5.rsp");
    let kats = parse_kat(content);
    assert_eq!(kats.len(), 100, "expected the full official vector set");
    for kat in &kats {
        let c = kat.count;
        let mut rng = KatRng::new(&kat.seed);
        let (ek, dk) = hqc256::generate_key(&mut rng);
        assert_eq!(ek.as_ref(), &kat.pk[..], "HQC-256 pk mismatch at count {c}");
        assert_eq!(dk.as_ref(), &kat.sk[..], "HQC-256 sk mismatch at count {c}");
        let (ct, ss) = ek.encapsulate(&mut rng);
        assert_eq!(ct.as_ref(), &kat.ct[..], "HQC-256 ct mismatch at count {c}");
        assert_eq!(ss.as_ref(), &kat.ss[..], "HQC-256 ss mismatch at count {c}");
        let ss2 = dk.decapsulate(&ct);
        assert_eq!(
            ss.as_ref(),
            ss2.as_ref(),
            "HQC-256 decaps mismatch at count {c}"
        );
    }
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
