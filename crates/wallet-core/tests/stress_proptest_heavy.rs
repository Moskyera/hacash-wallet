//! STRESS: Heavy property-based tests (512 cases each)

mod common;

use hacash_wallet_core::channel::derive_channel_id;
use hacash_wallet_core::hip23::validate_simple_l1_send;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn stress_prop_channel_deterministic(left in ".{1,24}", right in ".{1,24}", ver in 0u64..1000) {
        let a = derive_channel_id(&left, &right, ver);
        let b = derive_channel_id(&left, &right, ver);
        prop_assert_eq!(&a, &b);
    }

    #[test]
    fn stress_prop_small_send_ok(amt in 0.001f64..50.0) {
        let r = validate_simple_l1_send(
            "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
            amt,
            1000.0,
            0.001,
        );
        prop_assert!(r.is_ok());
    }
}
