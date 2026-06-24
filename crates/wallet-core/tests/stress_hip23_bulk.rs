//! STRESS: HIP-23 validation throughput

mod common;

use common::stress_gate;
use hacash_wallet_core::hip23::{
    validate_all_patterns, validate_simple_l1_send, BalanceFloorInput, HeightScopeInput,
    Type3CheckInput, ISTANBUL_HEIGHT,
};

const ITERATIONS: usize = 10_000;

#[test]
fn stress_hip23_l1_validation_10k() {
    stress_gate("hip23_l1_10k", || {
        let addr = "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS";
        for i in 0..ITERATIONS {
            let amt = (i % 50) as f64 + 0.001;
            let r = validate_simple_l1_send(addr, amt, 1000.0, 0.001);
            assert!(r.is_ok(), "iteration {i}");
        }
    });
}

#[test]
fn stress_hip23_type3_combined_5k() {
    stress_gate("hip23_type3_5k", || {
        for i in 0..5000 {
            let checks = validate_all_patterns(
                &Type3CheckInput {
                    tx_type: 3,
                    chain_height: ISTANBUL_HEIGHT + (i as u64),
                    gas_max: (i % 100) as u64 + 1,
                    has_asset_tex: i % 3 == 0,
                    ast_depth: (i % 4) as u32,
                    guard_only: false,
                    action_count: (i % 5) as u32 + 1,
                },
                Some(&HeightScopeInput {
                    start: i as u64,
                    end: i as u64 + 100,
                    guard_before_debit: true,
                }),
                Some(&BalanceFloorInput {
                    floor_hacash_mei: 1.0 + (i % 10) as f64,
                    debit_before_floor: true,
                }),
            );
            assert_eq!(checks.len(), 3);
            assert!(checks.iter().all(|c| c.check.ok), "iteration {i}");
        }
    });
}