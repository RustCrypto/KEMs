//! `Debug` output tests.

use core::fmt::Debug;
use ml_kem::{Kem, MlKem512, MlKem768, MlKem1024, Seed, kem::Decapsulator};

fn debug_redaction_test<K>()
where
    K: Kem,
    K::DecapsulationKey: Debug + From<Seed>,
{
    let dk = K::DecapsulationKey::from(Seed::from([0x42; 64]));
    let expected = format!(
        "DecapsulationKey {{ ek: {:?}, .. }}",
        dk.encapsulation_key()
    );

    // Not `assert_eq!`, which would print the secret key if this fails
    assert!(
        format!("{dk:?}") == expected,
        "`Debug` output should only contain the encapsulation key"
    );
}

#[test]
fn debug_redaction() {
    debug_redaction_test::<MlKem512>();
    debug_redaction_test::<MlKem768>();
    debug_redaction_test::<MlKem1024>();
}
