pub use hkdf::InvalidLength;

use core::iter;
use hkdf::{Hkdf, hmac::digest::block_api::EagerHash};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

/// Maximum size of the concatenated prefixes when performing labeled operations.
const PREFIXES_MAX: usize = 256;

/// Maximum size of input key material or info after applying prefixes.
const LABELED_INPUT_MAX: usize = PREFIXES_MAX + 64;

/// HPKE version identifier from `RFC9180 §4`.
const HPKE_VERSION_ID: &[u8] = b"HPKE-v1";

/// HPKE suite ID from `RFC9180 §4`.
const HPKE_SUITE_ID: &[u8] = b"KEM\x00\x10";

/// Expander: wrapper for [RFC5869] HKDF-Expand operation which can be used for HPKE's
/// `LabeledExtract` and `LabeledExpand` as described in [RFC9180 §4].
///
/// [RFC5869]: https://datatracker.ietf.org/doc/html/rfc5869
/// [RFC9180 §4]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
#[derive(Debug)]
pub struct Expander<D: EagerHash> {
    /// Inner HKDF instance
    hkdf: Hkdf<D>,
}

impl<D: EagerHash> Expander<D> {
    /// Create a new expander with the given salt and input key material.
    #[must_use]
    pub fn new(salt: &[u8], input_key_material: &[u8]) -> Self {
        Self {
            hkdf: Hkdf::<D>::new(Some(salt), input_key_material),
        }
    }

    /// Create a new expander with a slice of prefixes concatenated to the IKM.
    ///
    /// # Errors
    /// Returns [`InvalidLength`] if the concatenated prefixes are too long.
    pub fn new_prefixed(
        salt: &[u8],
        prefixes: &[&[u8]],
        input_key_material: &[u8],
    ) -> Result<Self, InvalidLength> {
        let mut labeled_ikm_buf = [0u8; LABELED_INPUT_MAX];
        let labeled_ikm = concat_slices(
            prefixes
                .iter()
                .copied()
                .chain(iter::once(input_key_material)),
            &mut labeled_ikm_buf,
        )?;

        let ret = Self::new(salt, labeled_ikm);

        #[cfg(feature = "zeroize")]
        labeled_ikm_buf.zeroize();

        Ok(ret)
    }

    /// Create a new expander which uses the prefixes that implement HPKE `LabeledExtract` as
    /// described in [RFC9180 §4].
    ///
    /// # Errors
    /// Returns [`InvalidLength`] if the concatenated prefixes are too long.
    ///
    /// [RFC9180 §4]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
    pub fn new_labeled_hpke(
        salt: &[u8],
        label: &[u8],
        input_key_material: &[u8],
    ) -> Result<Self, InvalidLength> {
        Self::new_prefixed(
            salt,
            &[HPKE_VERSION_ID, HPKE_SUITE_ID, label],
            input_key_material,
        )
    }

    /// Perform the [RFC5869] `HKDF-Expand` operation, generating uniformly random output key
    /// material that fills `okm` in its entirety.
    ///
    /// If you don’t have any info to pass, use an empty slice.
    ///
    /// # Errors
    /// Returns [`InvalidLength`] if info is too long.
    ///
    /// [RFC5869]: https://datatracker.ietf.org/doc/html/rfc5869
    /// [RFC9180 §4]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), InvalidLength> {
        self.hkdf.expand(info, okm)
    }

    /// Performs the [RFC5869] `HKDF-Expand` operation with `info` assembled from a slice-of-slices.
    ///
    /// This is equivalent to calling `expand` with the `info` argument set equal to the
    /// concatenation of all the elements of `info_components`.
    ///
    /// # Errors
    /// Returns [`InvalidLength`] if info is too long.
    ///
    /// [RFC5869]: https://datatracker.ietf.org/doc/html/rfc5869
    pub fn expand_multi_info(
        &self,
        info_components: &[&[u8]],
        okm: &mut [u8],
    ) -> Result<(), InvalidLength> {
        self.hkdf.expand_multi_info(info_components, okm)
    }

    /// Create a new expander which uses the prefixes that implement HPKE `LabeledExpand` as
    /// described in [RFC9180 §4].
    ///
    /// # Errors
    /// Returns [`InvalidLength`] if label and/or info is too long.
    ///
    /// [RFC9180 §4]: https://datatracker.ietf.org/doc/html/rfc9180#section-4
    pub fn expand_labeled_hpke(
        &self,
        label: &[u8],
        info: &[u8],
        okm: &mut [u8],
    ) -> Result<(), InvalidLength> {
        let okm_len = u16::try_from(okm.len()).map_err(|_| InvalidLength)?;
        self.hkdf.expand_multi_info(
            &[
                &okm_len.to_be_bytes(),
                HPKE_VERSION_ID,
                HPKE_SUITE_ID,
                label,
                info,
            ],
            okm,
        )
    }
}

fn concat_slices<'a, I>(slices: I, out: &mut [u8]) -> Result<&[u8], InvalidLength>
where
    I: Iterator<Item = &'a [u8]>,
{
    let mut offset = 0usize;
    for segment in slices {
        let new_offset = offset.checked_add(segment.len()).ok_or(InvalidLength)?;
        out.get_mut(offset..new_offset)
            .ok_or(InvalidLength)?
            .copy_from_slice(segment);

        offset = new_offset;
    }

    Ok(&out[..offset])
}
