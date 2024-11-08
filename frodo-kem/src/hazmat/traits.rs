use crate::hazmat::{
    Ciphertext, CiphertextRef, DecryptionKey, DecryptionKeyRef, EncryptionKey, EncryptionKeyRef,
    SharedSecret,
};
use rand_core::CryptoRngCore;
use sha3::digest::{ExtendableOutput, ExtendableOutputReset, Update};
use subtle::{Choice, ConditionallySelectable};
use zeroize::Zeroize;

/// Trait for implementing the FrodoKEM sampling algorithm
///
/// See Algorithm 5 and 6 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
/// or Algorithm 7.4 and 7.5 in [iso](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf).
pub trait Sample: Default {
    /// The method used to sample.
    ///
    /// s is the input that will be modified in place with the noise
    fn sample(&self, s: &mut [u16]);
}

/// Trait for implementing equivalents to
/// Algorithm 7 and 8 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
/// or Algorithm 7.6 in [iso](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf).
///
/// Expand the seed to produce the matrix A
pub trait Expanded: Default {
    /// The method used to expand the seed
    const METHOD: &'static str;
    /// Expand the seed to produce the matrix A
    /// Generate matrix A (N x N) column-wise
    fn expand_a(&self, seed_a: &[u8], a: &mut [u16]);
}

/// The base FrodoKEM parameters for either eFrodo or Frodo
pub trait Params: Sized + Default {
    /// The SHAKE method
    type Shake: Default + ExtendableOutput + ExtendableOutputReset + Update;
    /// The number of elements in the ring
    const N: usize;
    /// The number of rows in the matrix
    const N_BAR: usize = 8;
    /// The log of the modulus
    const LOG_Q: usize;
    /// The number of bits to extract when packing/unpacking
    /// encoding/decoding
    const EXTRACTED_BITS: usize;
    /// The number of steps for striping
    const STRIPE_STEP: usize = 8;
    /// The number of bytes in the seed for generating the matrix A
    const BYTES_SEED_A: usize = 16;
    /// The number of bytes in the public key hash
    const BYTES_PK_HASH: usize = Self::SHARED_SECRET_LENGTH;
    /// The CDF table
    const CDF_TABLE: &'static [u16];
    /// The claimed NIST level
    const CLAIMED_NIST_LEVEL: usize;
    /// The length of the shared secret
    const SHARED_SECRET_LENGTH: usize;
    /// The number of bytes in µ
    const BYTES_MU: usize = (Self::EXTRACTED_BITS * Self::N_BAR_X_N_BAR) / 8;
    /// The number of bytes in seedSE
    const BYTES_SEED_SE: usize = 2 * Self::SHARED_SECRET_LENGTH;
    /// The number of bytes in the salt
    const BYTES_SALT: usize = 2 * Self::SHARED_SECRET_LENGTH;
    /// = len(s) + len(seedSE) + len(z)
    const KEY_SEED_SIZE: usize =
        Self::SHARED_SECRET_LENGTH + Self::BYTES_SEED_A + Self::BYTES_SEED_SE;
    /// 2 * N
    const TWO_N: usize = 2 * Self::N;
    /// 2 + SEED_A
    const TWO_PLUS_BYTES_SEED_A: usize = 2 + Self::BYTES_SEED_A;
    /// N * N
    const N_X_N: usize = Self::N * Self::N;
    /// N * N_BAR
    const N_X_N_BAR: usize = Self::N * Self::N_BAR;
    /// N_BAR * N
    const N_BAR_X_N: usize = Self::N_BAR * Self::N;
    /// N_BAR * N_BAR
    const N_BAR_X_N_BAR: usize = Self::N_BAR * Self::N_BAR;
    /// 2 * N * N_BAR
    const TWO_N_X_N_BAR: usize = 2 * Self::N_X_N_BAR;
    /// The number of bits to extract
    const EXTRACTED_BITS_MASK: u16 = (1 << Self::EXTRACTED_BITS) - 1;
    /// The number of bits to shift when encoding and decoding
    const SHIFT: usize = Self::LOG_Q - Self::EXTRACTED_BITS;
    /// The modulus
    const Q: usize = 1 << Self::LOG_Q;
    /// The mask for the modulus
    const Q_MASK: u16 = (Self::Q - 1) as u16;
    /// LOG_Q * N * N_BAR / 8
    const LOG_Q_X_N_X_N_BAR_DIV_8: usize = (Self::LOG_Q * Self::N_X_N_BAR) / 8;
    /// The public key length
    const PUBLIC_KEY_LENGTH: usize = Self::LOG_Q_X_N_X_N_BAR_DIV_8 + Self::BYTES_SEED_A;
    /// The secret key length
    const SECRET_KEY_LENGTH: usize = Self::PUBLIC_KEY_LENGTH
        + Self::TWO_N_X_N_BAR
        + Self::BYTES_PK_HASH
        + Self::SHARED_SECRET_LENGTH;
    /// The ciphertext length
    const CIPHERTEXT_LENGTH: usize =
        Self::LOG_Q_X_N_X_N_BAR_DIV_8 + (Self::LOG_Q * Self::N_BAR_X_N_BAR) / 8 + Self::BYTES_SALT;
}

/// The base FrodoKEM methods
pub trait Kem: Params + Expanded + Sample {
    /// The name of the frodoKEM algorithm
    const NAME: &'static str;

    /// Generate a keypair
    ///
    /// See Algorithm 12 in [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
    /// Algorithm 8.1 in [iso](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf).
    /// Algorithm 1 in [annex](https://frodokem.org/files/FrodoKEM-annex-20230418.pdf)
    fn generate_keypair(
        &self,
        mut rng: impl CryptoRngCore,
    ) -> (EncryptionKey<Self>, DecryptionKey<Self>) {
        let mut sk = DecryptionKey::default();
        let mut pk = EncryptionKey::default();
        let mut randomness = vec![0u8; Self::KEY_SEED_SIZE];
        rng.fill_bytes(&mut randomness);

        sk.random_s_mut()
            .copy_from_slice(&randomness[..Self::SHARED_SECRET_LENGTH]);
        let randomness_seed_se = &randomness
            [Self::SHARED_SECRET_LENGTH..Self::SHARED_SECRET_LENGTH + Self::BYTES_SEED_SE];
        let randomness_z = &randomness[Self::SHARED_SECRET_LENGTH + Self::BYTES_SEED_SE..];

        let mut shake = Self::Shake::default();
        shake.update(randomness_z);
        shake.finalize_xof_reset_into(pk.seed_a_mut());

        shake.update(&[0x5F]);
        shake.update(randomness_seed_se);
        // 1st half is matrix S
        // 2nd half is matrix E
        let mut bytes_se = vec![0u16; Self::TWO_N_X_N_BAR];
        {
            let bytes_se = unsafe {
                std::slice::from_raw_parts_mut(bytes_se.as_mut_ptr() as *mut u8, bytes_se.len() * 2)
            };
            shake.finalize_xof_reset_into(bytes_se);
        }
        #[cfg(target_endian = "big")]
        {
            for b in bytes_se.iter_mut() {
                *b = b.to_be();
            }
        }

        self.sample(&mut bytes_se);

        let mut a_matrix = vec![0u16; Self::N_X_N];
        self.expand_a(pk.seed_a(), &mut a_matrix);

        let mut matrix_b = vec![0u16; Self::N_X_N_BAR];
        self.mul_add_as_plus_e(
            &a_matrix,
            &bytes_se[..Self::N_X_N_BAR],
            &bytes_se[Self::N_X_N_BAR..],
            &mut matrix_b,
        );

        self.pack(&matrix_b, pk.matrix_b_mut());

        {
            let matrix_s = sk.matrix_s_mut();
            for (i, b) in bytes_se[..Self::N_X_N_BAR].iter().enumerate() {
                let bb = b.to_le_bytes();
                matrix_s[i * 2] = bb[0];
                matrix_s[i * 2 + 1] = bb[1];
            }
        }

        shake.update(&pk.0);
        shake.finalize_xof_into(sk.hpk_mut());
        sk.public_key_mut().copy_from_slice(&pk.0);

        bytes_se.zeroize();
        randomness.zeroize();

        (pk, sk)
    }

    /// Encapsulate a random message into a ciphertext.
    ///
    /// See Algorithm 13 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
    /// Algorithm 8.2 in [iso](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf).
    /// Algorithm 2 in [annex](https://frodokem.org/files/FrodoKEM-annex-20230418.pdf)
    fn encapsulate_with_rng<'a, P: Into<EncryptionKeyRef<'a, Self>>>(
        &self,
        public_key: P,
        mut rng: impl CryptoRngCore,
    ) -> (Ciphertext<Self>, SharedSecret<Self>) {
        let mut mu = vec![0u8; Self::BYTES_MU + Self::BYTES_SALT];
        rng.fill_bytes(&mut mu);
        let res = self.encapsulate(public_key, &mu[..Self::BYTES_MU], &mu[Self::BYTES_MU..]);
        mu.zeroize();
        res
    }

    /// Encapsulate a message into a ciphertext.
    ///
    /// See Algorithm 13 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
    /// Algorithm 8.2 in [iso](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf).
    /// Algorithm 2 in [annex](https://frodokem.org/files/FrodoKEM-annex-20230418.pdf)
    fn encapsulate<'a, P: Into<EncryptionKeyRef<'a, Self>>>(
        &self,
        public_key: P,
        mu: &[u8],
        salt: &[u8],
    ) -> (Ciphertext<Self>, SharedSecret<Self>) {
        assert_eq!(mu.len(), Self::BYTES_MU);
        assert_eq!(salt.len(), Self::BYTES_SALT);
        let public_key = public_key.into();
        let mut ct = Ciphertext::default();
        let mut ss = SharedSecret::default();

        let mut shake = Self::Shake::default();
        let mut g2_in = vec![0u8; Self::BYTES_PK_HASH + Self::BYTES_MU + Self::BYTES_SALT];

        shake.update(public_key.0);
        shake.finalize_xof_reset_into(&mut g2_in[..Self::BYTES_PK_HASH]);
        g2_in[Self::BYTES_PK_HASH..Self::BYTES_PK_HASH + Self::BYTES_MU].copy_from_slice(mu);
        g2_in[Self::BYTES_PK_HASH + Self::BYTES_MU..].copy_from_slice(salt);
        let mut g2_out = vec![0u8; Self::SHARED_SECRET_LENGTH + Self::BYTES_SEED_SE];
        shake.update(&g2_in);
        shake.finalize_xof_reset_into(&mut g2_out);

        let mut sp = vec![0u16; (2 * Self::N + Self::N_BAR) * Self::N_BAR];
        shake.update(&[0x96]);
        shake.update(&g2_out[..Self::BYTES_SEED_SE]);
        {
            let bytes_sp =
                unsafe { std::slice::from_raw_parts_mut(sp.as_mut_ptr() as *mut u8, sp.len() * 2) };
            shake.finalize_xof_reset_into(bytes_sp);
        }
        #[cfg(target_endian = "big")]
        {
            for b in sp.iter_mut() {
                *b = b.to_be();
            }
        }

        self.sample(&mut sp);

        let s = &sp[..Self::N_X_N_BAR];
        let ep = &sp[Self::N_X_N_BAR..2 * Self::N_X_N_BAR];
        let epp = &sp[2 * Self::N_X_N_BAR..];

        let mut matrix_a = vec![0u16; Self::N_X_N];
        self.expand_a(public_key.seed_a(), &mut matrix_a);

        let mut matrix_b = vec![0u16; Self::N_X_N_BAR];
        self.mul_add_sa_plus_e(s, &matrix_a, ep, &mut matrix_b);

        self.pack(&matrix_b, ct.c1_mut());

        let mut pk_matrix_b = vec![0u16; Self::N_X_N_BAR];
        self.unpack(public_key.matrix_b(), &mut pk_matrix_b);

        let mut matrix_v = vec![0u16; Self::N_BAR_X_N_BAR];
        self.mul_add_sb_plus_e(s, &pk_matrix_b, epp, &mut matrix_v);

        let mut matrix_c = vec![0u16; Self::N_BAR_X_N_BAR];

        self.encode_message(
            &g2_in[Self::BYTES_PK_HASH..Self::BYTES_PK_HASH + Self::BYTES_MU],
            &mut matrix_c,
        );

        self.add(&matrix_v, &mut matrix_c);

        self.pack(&matrix_c, ct.c2_mut());

        ct.salt_mut()
            .copy_from_slice(&g2_in[g2_in.len() - Self::BYTES_SALT..]);

        shake.update(&ct.0);
        shake.update(&g2_out[Self::BYTES_SEED_SE..]);
        shake.finalize_xof_into(&mut ss.0);

        matrix_v.zeroize();
        sp.zeroize();
        g2_in[Self::BYTES_PK_HASH..].zeroize();
        g2_out.zeroize();

        (ct, ss)
    }

    /// Decapsulate the ciphertext into a shared secret.
    ///
    /// See Algorithm 14 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
    /// Algorithm 8.3 in [iso](https://frodokem.org/files/FrodoKEM-standard_proposal-20230314.pdf).
    /// Algorithm 3 in [annex](https://frodokem.org/files/FrodoKEM-annex-20230418.pdf)
    fn decapsulate<
        'a,
        'b,
        S: Into<DecryptionKeyRef<'a, Self>>,
        C: Into<CiphertextRef<'b, Self>>,
    >(
        &self,
        secret_key: S,
        ciphertext: C,
    ) -> (SharedSecret<Self>, Vec<u8>) {
        let secret_key = secret_key.into();
        let ciphertext = ciphertext.into();

        let mut ss = SharedSecret::default();
        let mut matrix_s = vec![0u16; Self::N_X_N_BAR];
        let pk = EncryptionKeyRef::<Self>::from_slice(secret_key.public_key())
            .expect("Invalid public key");

        for (i, b) in matrix_s.iter_mut().enumerate() {
            let bb = [
                secret_key.matrix_s()[i * 2],
                secret_key.matrix_s()[i * 2 + 1],
            ];
            *b = u16::from_le_bytes(bb);
        }

        let mut matrix_bp = vec![0u16; Self::N_X_N_BAR];
        self.unpack(ciphertext.c1(), &mut matrix_bp);

        let mut matrix_c = vec![0u16; Self::N_BAR_X_N_BAR];
        self.unpack(ciphertext.c2(), &mut matrix_c);

        // W = C - Bp*S mod q
        let mut matrix_w = vec![0u16; Self::N_BAR_X_N_BAR];
        self.mul_bs(&matrix_bp, &matrix_s, &mut matrix_w);
        self.sub(&matrix_c, &mut matrix_w);

        let mut g2_in = vec![0u8; Self::BYTES_PK_HASH + Self::BYTES_MU + Self::BYTES_SALT];
        let mut g2_out = vec![0u8; Self::SHARED_SECRET_LENGTH + Self::BYTES_SEED_SE];

        g2_in[..Self::BYTES_PK_HASH].copy_from_slice(secret_key.hpk());
        // µ'
        self.decode_message(
            &matrix_w,
            &mut g2_in[Self::BYTES_PK_HASH..Self::BYTES_PK_HASH + Self::BYTES_MU],
        );
        g2_in[Self::BYTES_PK_HASH + Self::BYTES_MU..].copy_from_slice(ciphertext.salt());

        let mut shake = Self::Shake::default();
        shake.update(&g2_in);
        shake.finalize_xof_reset_into(&mut g2_out);

        let mut sp = vec![0u16; (2 * Self::N + Self::N_BAR) * Self::N_BAR];
        shake.update(&[0x96]);
        shake.update(&g2_out[..Self::BYTES_SEED_SE]);
        {
            let bytes_sp =
                unsafe { std::slice::from_raw_parts_mut(sp.as_mut_ptr() as *mut u8, sp.len() * 2) };
            shake.finalize_xof_reset_into(bytes_sp);
        }
        #[cfg(target_endian = "big")]
        {
            for b in sp.iter_mut() {
                *b = b.to_be();
            }
        }

        self.sample(&mut sp);

        let s = &sp[..Self::N_X_N_BAR];
        let ep = &sp[Self::N_X_N_BAR..2 * Self::N_X_N_BAR];
        let epp = &sp[2 * Self::N_X_N_BAR..];

        let mut matrix_a = vec![0u16; Self::N_X_N];
        self.expand_a(pk.seed_a(), &mut matrix_a);

        let mut matrix_bpp = vec![0u16; Self::N_X_N_BAR];
        self.mul_add_sa_plus_e(s, &matrix_a, ep, &mut matrix_bpp);
        // BB mod q
        matrix_bpp.iter_mut().for_each(|b| *b &= Self::Q_MASK);

        let mut matrix_b = vec![0u16; Self::N_X_N_BAR];
        self.unpack(pk.matrix_b(), &mut matrix_b);

        // W = Sp*B + Epp
        self.mul_add_sb_plus_e(s, &matrix_b, epp, &mut matrix_w);

        // CC = W + enc(µ') mod q
        let mut matrix_cc = vec![0u16; Self::N_BAR_X_N_BAR];
        self.encode_message(
            &g2_in[Self::BYTES_PK_HASH..Self::BYTES_PK_HASH + Self::BYTES_MU],
            &mut matrix_cc,
        );
        self.add(&matrix_w, &mut matrix_cc);

        shake.update(ciphertext.0);
        // If (Bp == BBp & C == CC) then ss = F(ct || k'), else ss = F(ct || s)
        // Needs to avoid branching on secret data as per:
        //     Qian Guo, Thomas Johansson, Alexander Nilsson. A key-recovery timing attack on post-quantum
        //     primitives using the Fujisaki-Okamoto transformation and its application on FrodoKEM. In CRYPTO 2020.
        let choice =
            self.ct_verify(&matrix_bp, &matrix_bpp) & self.ct_verify(&matrix_c, &matrix_cc);

        let mut fin_k = vec![0u8; Self::SHARED_SECRET_LENGTH];
        // Take k if choice == 0, otherwise take s
        self.ct_select(
            choice,
            &g2_out[Self::BYTES_SEED_SE..],
            secret_key.random_s(),
            &mut fin_k,
        );

        shake.update(&fin_k);
        shake.finalize_xof_into(&mut ss.0);
        let mu_prime = g2_in[Self::BYTES_PK_HASH..Self::BYTES_PK_HASH + Self::BYTES_MU].to_vec();

        matrix_s.zeroize();
        matrix_w.zeroize();
        sp.zeroize();
        g2_out.zeroize();
        g2_in[Self::BYTES_PK_HASH..Self::BYTES_PK_HASH + Self::BYTES_MU].zeroize();

        (ss, mu_prime)
    }

    /// Get the algorithm name
    fn algorithm(&self) -> String {
        format!("{}-{}-{}", Self::NAME, Self::N, Self::METHOD)
    }

    /// Multiply by s on the right.
    ///
    /// Uses matrix A row-wise
    /// Inputs: s, e (N x N_BAR)
    /// Output: out = A*s + e (N x N_BAR)
    fn mul_add_as_plus_e(&self, a: &[u16], s: &[u16], e: &[u16], b: &mut [u16]) {
        debug_assert_eq!(a.len(), Self::N_X_N);
        debug_assert_eq!(s.len(), Self::N_X_N_BAR);
        debug_assert_eq!(e.len(), Self::N_X_N_BAR);
        debug_assert_eq!(b.len(), Self::N_X_N_BAR);

        for i in 0..Self::N {
            let i_bar = i * Self::N_BAR;
            let i_n = i * Self::N;
            for k in 0..Self::N_BAR {
                let mut sum = e[i_bar + k];
                for j in 0..Self::N {
                    sum = sum.wrapping_add(a[i_n + j].wrapping_mul(s[k * Self::N + j]));
                }
                b[i_bar + k] = b[i_bar + k].wrapping_add(sum);
            }
        }
    }

    /// Multiply by s' on the left.
    ///
    /// Uses matrix A column-wise
    /// Inputs: s', e' (N_BAR x N)
    /// Output: out = s'*A + e' (N_BAR x N)
    fn mul_add_sa_plus_e(&self, s: &[u16], a: &[u16], e: &[u16], out: &mut [u16]) {
        debug_assert_eq!(a.len(), Self::N_X_N);
        debug_assert_eq!(s.len(), Self::N_X_N_BAR);
        debug_assert_eq!(e.len(), Self::N_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N);

        // Reference implementation
        // for i in 0..Self::N {
        //     for k in 0..Self::N_BAR {
        //         let mut sum = e[k * Self::N + i];
        //         let k_n = k * Self::N;
        //         for j in 0..Self::N {
        //             sum = sum.wrapping_add(a[j * Self::N + i].wrapping_mul(s[k_n + j]));
        //         }
        //         out[k_n + i] = out[k_n + i].wrapping_add(sum);
        //     }
        // }

        // Unroll to process 8 columns at a time
        for i in (0..Self::N).step_by(8) {
            for k in 0..Self::N_BAR {
                let k_n = k * Self::N;
                let mut sum = [
                    e[k_n + i],
                    e[k_n + i + 1],
                    e[k_n + i + 2],
                    e[k_n + i + 3],
                    e[k_n + i + 4],
                    e[k_n + i + 5],
                    e[k_n + i + 6],
                    e[k_n + i + 7],
                ];

                for j in 0..Self::N {
                    let sp = s[k_n + j];
                    sum[0] = sum[0].wrapping_add(a[j * Self::N + i].wrapping_mul(sp));
                    sum[1] = sum[1].wrapping_add(a[j * Self::N + i + 1].wrapping_mul(sp));
                    sum[2] = sum[2].wrapping_add(a[j * Self::N + i + 2].wrapping_mul(sp));
                    sum[3] = sum[3].wrapping_add(a[j * Self::N + i + 3].wrapping_mul(sp));
                    sum[4] = sum[4].wrapping_add(a[j * Self::N + i + 4].wrapping_mul(sp));
                    sum[5] = sum[5].wrapping_add(a[j * Self::N + i + 5].wrapping_mul(sp));
                    sum[6] = sum[6].wrapping_add(a[j * Self::N + i + 6].wrapping_mul(sp));
                    sum[7] = sum[7].wrapping_add(a[j * Self::N + i + 7].wrapping_mul(sp));
                }

                out[k_n + i] = out[k_n + i].wrapping_add(sum[0]);
                out[k_n + i + 1] = out[k_n + i + 1].wrapping_add(sum[1]);
                out[k_n + i + 2] = out[k_n + i + 2].wrapping_add(sum[2]);
                out[k_n + i + 3] = out[k_n + i + 3].wrapping_add(sum[3]);
                out[k_n + i + 4] = out[k_n + i + 4].wrapping_add(sum[4]);
                out[k_n + i + 5] = out[k_n + i + 5].wrapping_add(sum[5]);
                out[k_n + i + 6] = out[k_n + i + 6].wrapping_add(sum[6]);
                out[k_n + i + 7] = out[k_n + i + 7].wrapping_add(sum[7]);
            }
        }
    }

    /// Multiply by s on the left
    /// Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
    /// Output: out = s*b + e (N_BAR x N_BAR)
    fn mul_add_sb_plus_e(&self, s: &[u16], b: &[u16], e: &[u16], out: &mut [u16]) {
        debug_assert_eq!(b.len(), Self::N_X_N_BAR);
        debug_assert_eq!(s.len(), Self::N_BAR_X_N);
        debug_assert_eq!(e.len(), Self::N_BAR_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N_BAR);

        // Reference implementation
        // for k in 0..Self::N_BAR {
        //     let k_n = k * Self::N;
        //     let k_bar = k * Self::N_BAR;
        //     for i in 0..Self::N_BAR {
        //         let mut sum = e[k_bar + i];
        //         for j in 0..Self::N {
        //             sum = sum.wrapping_add(s[k_n + j].wrapping_mul(b[j * Self::N_BAR + i]));
        //         }
        //         out[k_bar + i] = sum & Self::Q_MASK;
        //     }
        // }

        // Unroll to process 8 columns at a time
        for k in 0..Self::N_BAR {
            let k_n = k * Self::N;
            let k_bar = k * Self::N_BAR;

            let mut sum = [
                e[k_bar],
                e[k_bar + 1],
                e[k_bar + 2],
                e[k_bar + 3],
                e[k_bar + 4],
                e[k_bar + 5],
                e[k_bar + 6],
                e[k_bar + 7],
            ];

            for j in 0..Self::N {
                let sp = s[k_n + j];
                sum[0] = sum[0].wrapping_add(sp.wrapping_mul(b[j * Self::N_BAR]));
                sum[1] = sum[1].wrapping_add(sp.wrapping_mul(b[j * Self::N_BAR + 1]));
                sum[2] = sum[2].wrapping_add(sp.wrapping_mul(b[j * Self::N_BAR + 2]));
                sum[3] = sum[3].wrapping_add(sp.wrapping_mul(b[j * Self::N_BAR + 3]));
                sum[4] = sum[4].wrapping_add(sp.wrapping_mul(b[j * Self::N_BAR + 4]));
                sum[5] = sum[5].wrapping_add(sp.wrapping_mul(b[j * Self::N_BAR + 5]));
                sum[6] = sum[6].wrapping_add(sp.wrapping_mul(b[j * Self::N_BAR + 6]));
                sum[7] = sum[7].wrapping_add(sp.wrapping_mul(b[j * Self::N_BAR + 7]));
            }

            out[k_bar] = sum[0] & Self::Q_MASK;
            out[k_bar + 1] = sum[1] & Self::Q_MASK;
            out[k_bar + 2] = sum[2] & Self::Q_MASK;
            out[k_bar + 3] = sum[3] & Self::Q_MASK;
            out[k_bar + 4] = sum[4] & Self::Q_MASK;
            out[k_bar + 5] = sum[5] & Self::Q_MASK;
            out[k_bar + 6] = sum[6] & Self::Q_MASK;
            out[k_bar + 7] = sum[7] & Self::Q_MASK;
        }
    }

    /// Matrix multiply B on the lhs and S on the rhs
    fn mul_bs(&self, b: &[u16], s: &[u16], out: &mut [u16]) {
        debug_assert_eq!(b.len(), Self::N_BAR_X_N);
        debug_assert_eq!(s.len(), Self::N_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N_BAR);

        for i in 0..Self::N_BAR {
            let i_n = i * Self::N;
            let i_bar = i * Self::N_BAR;
            for j in 0..Self::N_BAR {
                let mut sum = 0u16;
                for k in 0..Self::N {
                    sum = sum.wrapping_add(b[i_n + k].wrapping_mul(s[j * Self::N + k]));
                }
                out[i_bar + j] = sum & Self::Q_MASK;
            }
        }
    }

    /// Matrix subtraction
    fn add(&self, rhs: &[u16], out: &mut [u16]) {
        debug_assert_eq!(rhs.len(), Self::N_BAR_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N_BAR);
        for i in 0..Self::N_BAR_X_N_BAR {
            out[i] = out[i].wrapping_add(rhs[i]) & Self::Q_MASK;
        }
    }

    /// Matrix subtraction
    fn sub(&self, lhs: &[u16], out: &mut [u16]) {
        debug_assert_eq!(lhs.len(), Self::N_BAR_X_N_BAR);
        debug_assert_eq!(out.len(), Self::N_BAR_X_N_BAR);
        for i in 0..Self::N_BAR_X_N_BAR {
            out[i] = lhs[i].wrapping_sub(out[i]) & Self::Q_MASK;
        }
    }

    /// Matrix encoding into a bit sequence
    ///
    /// See Algorithm 1 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
    fn encode_message(&self, msg: &[u8], output: &mut [u16]) {
        debug_assert_eq!(msg.len(), Self::SHARED_SECRET_LENGTH);
        debug_assert_eq!(output.len(), Self::N_BAR_X_N_BAR);
        let n_words = Self::N_BAR_X_N_BAR / 8;
        let mask = (1u64 << Self::EXTRACTED_BITS) - 1;
        let mut pos = 0;

        for i in 0..n_words {
            let mut temp = 0;
            let ii = i * Self::EXTRACTED_BITS;
            for j in 0..Self::EXTRACTED_BITS {
                let t = msg[ii + j] as u64;
                temp |= t << (8 * j);
            }
            for _ in 0..8 {
                output[pos] = ((temp & mask) << Self::SHIFT) as u16;
                temp >>= Self::EXTRACTED_BITS;
                pos += 1;
            }
        }
    }

    /// Matrix decoding from a bit sequence
    ///
    /// See Algorithm 2 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
    fn decode_message(&self, input: &[u16], output: &mut [u8]) {
        debug_assert_eq!(input.len(), Self::N_BAR_X_N_BAR);
        debug_assert_eq!(output.len(), Self::SHARED_SECRET_LENGTH);

        let n_words = Self::N_BAR_X_N_BAR / 8;
        let mut index = 0;
        let add = 1u16 << (Self::SHIFT - 1);

        for i in 0..n_words {
            let mut temp = 0u64;
            for j in 0..8 {
                let mut t = (input[index] & Self::Q_MASK).wrapping_add(add);
                t >>= Self::SHIFT;
                temp |= ((t & Self::EXTRACTED_BITS_MASK) as u64) << (Self::EXTRACTED_BITS * j);
                index += 1;
            }
            let ii = i * Self::EXTRACTED_BITS;
            for j in 0..Self::EXTRACTED_BITS {
                output[ii + j] = (temp >> (8 * j)) as u8;
            }
        }
    }

    /// Pack the matrix input into the output byte sequence
    ///
    /// See Algorithm 3 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
    fn pack(&self, input: &[u16], output: &mut [u8]) {
        let mut i = 0;
        let mut j = 0;
        let mut w = 0u16;
        let mut bits = 0u8;
        let lsb = Self::LOG_Q as u8;

        let outlen = output.len();
        let inlen = input.len();

        while i < outlen && (j < inlen || (j == inlen && bits > 0)) {
            let mut b = 0u8;

            while b < 8 {
                let nbits = std::cmp::min(8 - b, bits);
                let mask = (1u16 << nbits).wrapping_sub(1);

                let w_shifted = w >> (bits - nbits);

                let t = (w_shifted & mask) as u32;

                let t_shifted = (t << (8 - b - nbits)) as u8;

                output[i] = output[i].wrapping_add(t_shifted);
                b = b.wrapping_add(nbits);
                bits = bits.wrapping_sub(nbits);

                let mask_shifted = !(mask << bits);

                w &= mask_shifted;

                if bits == 0 {
                    if j < inlen {
                        w = input[j];
                        bits = lsb;
                        j += 1;
                    } else {
                        break;
                    }
                }
            }
            if b == 8 {
                i += 1;
            }
        }
    }

    /// Unpack the input byte sequence into the output matrix
    ///
    /// See Algorithm 4 in the [spec](https://frodokem.org/files/FrodoKEM-specification-20210604.pdf).
    fn unpack(&self, input: &[u8], output: &mut [u16]) {
        let mut i = 0;
        let mut j = 0;
        let mut w = 0u8;
        let mut bits = 0u8;
        let lsb = Self::LOG_Q as u8;

        let outlen = output.len();
        let inlen = input.len();

        while i < outlen && (j < inlen || (j == inlen && bits > 0)) {
            let mut b = 0u8;

            while b < lsb {
                let nbits = std::cmp::min(lsb - b, bits);
                let mask = (1u16 << nbits).wrapping_sub(1);

                let w_shifted = w >> (bits.wrapping_sub(nbits));

                let t = w_shifted & (mask as u8);

                let t_shifted = ((t as u32) << (lsb - b - nbits)) as u16;

                output[i] = output[i].wrapping_add(t_shifted);
                b = b.wrapping_add(nbits);
                bits = bits.wrapping_sub(nbits);

                let mask_shifted = !(mask << bits);

                w &= mask_shifted as u8;

                if bits == 0 {
                    if j < inlen {
                        w = input[j];
                        j += 1;
                        bits = 8;
                    }
                } else {
                    break;
                }
            }
            if b == lsb {
                i += 1;
            }
        }
    }

    /// Constant time verify for a u16 array
    fn ct_verify(&self, a: &[u16], b: &[u16]) -> Choice {
        let mut choice = 0;

        for i in 0..a.len() {
            choice |= a[i] ^ b[i];
        }

        let mut choice = choice as i16;
        choice = ((choice | choice.wrapping_neg()) >> 15) + 1;
        Choice::from(choice as u8)
    }

    /// Constant time select for a u16 array
    fn ct_select(&self, choice: Choice, a: &[u8], b: &[u8], out: &mut [u8]) {
        for i in 0..a.len() {
            out[i] = u8::conditional_select(&b[i], &a[i], choice);
        }
    }
}
