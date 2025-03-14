//! Reader for Frodo KAT files and test vectors
use frodo_kem::*;
use hybrid_array::{Array, typenum::U48};
use std::path::Path;
use std::{
    fs::File,
    io::{BufRead, BufReader, Lines},
};

type RngSeed = Array<u8, U48>;

/// "count = ".len()
const COUNT_PREFIX: usize = 8;
/// "seed = ".len()
const SEED_PREFIX: usize = 7;
/// "pk = ".len()
const PK_PREFIX: usize = 5;
/// "sk = ".len()
const SK_PREFIX: usize = 5;
/// "ct = ".len()
const CT_PREFIX: usize = 5;
/// "ss = ".len()
const SS_PREFIX: usize = 5;

/// Reader for Frodo KAT files
#[derive(Debug)]
pub struct RspReader {
    lines: Lines<BufReader<File>>,
    scheme: Algorithm,
}

impl RspReader {
    /// Create a new RspReader from a file
    pub fn new<P: AsRef<Path>>(file: P) -> Self {
        let path = file.as_ref();
        assert!(
            path.is_file(),
            "File not found: {}",
            path.file_name().unwrap().to_str().unwrap()
        );
        let file = File::open(path).unwrap();
        let mut buf_reader = BufReader::new(file);
        let mut line = String::new();
        // Scheme
        buf_reader.read_line(&mut line).unwrap();
        let scheme = line.trim()[2..].parse::<Algorithm>().unwrap();
        line.clear();
        buf_reader.read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "");

        let lines = buf_reader.lines();
        Self { lines, scheme }
    }
}

impl Iterator for RspReader {
    type Item = RspData;

    fn next(&mut self) -> Option<RspData> {
        let count_line = self.lines.next()?.unwrap();
        if count_line.trim().is_empty() {
            return None;
        }
        let count = count_line[COUNT_PREFIX..].parse::<usize>().unwrap();
        let seed_line = self.lines.next()?.unwrap();
        let seed_bytes = hex::decode(seed_line[SEED_PREFIX..].trim_end()).unwrap();
        assert_eq!(seed_bytes.len(), 48);
        let seed = RngSeed::from_iter(seed_bytes.iter().copied());
        let pk_line = self.lines.next()?.unwrap();
        let pk_bytes = hex::decode(pk_line[PK_PREFIX..].trim_end()).unwrap();
        let pk = self.scheme.encryption_key_from_bytes(&pk_bytes).unwrap();
        let sk_line = self.lines.next()?.unwrap();
        let sk_bytes = hex::decode(sk_line[SK_PREFIX..].trim_end()).unwrap();
        let sk = self.scheme.decryption_key_from_bytes(&sk_bytes).unwrap();
        let ct_line = self.lines.next()?.unwrap();
        let ct_bytes = hex::decode(ct_line[CT_PREFIX..].trim_end()).unwrap();
        let ct = self.scheme.ciphertext_from_bytes(&ct_bytes).unwrap();
        let ss_line = self.lines.next()?.unwrap();
        let ss_bytes = hex::decode(ss_line[SS_PREFIX..].trim_end()).unwrap();
        let ss = self.scheme.shared_secret_from_bytes(&ss_bytes).unwrap();
        let space = self.lines.next()?.unwrap();
        assert_eq!(space.trim(), "");
        Some(RspData {
            scheme: self.scheme,
            count,
            seed,
            pk,
            sk,
            ct,
            ss,
        })
    }
}

/// Test vector data
#[derive(Debug, Clone, Default)]
pub struct RspData {
    /// Algorithm used in the test vector
    pub scheme: Algorithm,
    /// Test vector number
    pub count: usize,
    /// RNG seed
    pub seed: Array<u8, U48>,
    /// Public key
    pub pk: EncryptionKey,
    /// Secret key
    pub sk: DecryptionKey,
    /// Ciphertext
    pub ct: Ciphertext,
    /// Shared secret
    pub ss: SharedSecret,
}
