//! AUDIT-GATE: Property-based tests (proptest). 64 cases each

mod common;

use hacash_wallet_core::channel::derive_channel_id;
use hacash_wallet_core::hip23::validate_simple_l1_send;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn prop_channel_id_deterministic(left in ".{1,20}", right in ".{1,20}", ver in 1u64..10) {
        let a = derive_channel_id(&left, &right, ver);
        let b = derive_channel_id(&left, &right, ver);
        prop_assert_eq!(&a, &b);
        prop_assert_eq!(a.len(), 32);
    }

    #[test]
    fn prop_channel_id_sensitive_to_party_order(left in ".{1,12}", right in ".{1,12}") {
        prop_assume!(left != right);
        prop_assert_ne!(derive_channel_id(&left, &right, 1), derive_channel_id(&right, &left, 1));
    }

    #[test]
    fn prop_garbage_address_rejected(suffix in "[^1A-Za-z0-9]{1,8}") {
        let addr = format!("0{suffix}");
        let r = validate_simple_l1_send(&addr, 1.0, 100.0, 0.001);
        prop_assert!(r.is_err());
    }

    #[test]
    fn prop_negative_amount_rejected(amt in -1000.0f64..0.0) {
        let r = validate_simple_l1_send("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS", amt, 100.0, 0.001);
        prop_assert!(r.is_err());
    }
}
