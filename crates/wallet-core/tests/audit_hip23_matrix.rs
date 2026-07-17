//! AUDIT-GATE: HIP-23 wallet checklist matrix (table-driven)

mod common;

use common::audit_gate;
use hacash_wallet_core::hip23::{
    BalanceFloorInput, HeightScopeInput, ISTANBUL_HEIGHT, Type3CheckInput, validate_all_patterns,
    validate_balance_floor_pattern, validate_height_scope_pattern, validate_simple_l1_send,
    validate_type3_universal,
};

#[test]
fn audit_hip23_matrix_l1_cases() {
    audit_gate("hip23_l1_matrix", || {
        let cases = [
            ("invalid addr", "bad", 1.0, 10.0, false),
            (
                "zero amount",
                "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                0.0,
                10.0,
                false,
            ),
            (
                "insufficient",
                "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                100.0,
                1.0,
                false,
            ),
            (
                "valid small",
                "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS",
                1.0,
                10.0,
                true,
            ),
        ];
        for (name, to, amt, bal, ok) in cases {
            let r = validate_simple_l1_send(to, amt, bal, 0.001);
            assert_eq!(r.is_ok(), ok, "case: {name}");
        }
    });
}

#[test]
fn audit_hip23_matrix_type3_universal() {
    audit_gate("hip23_type3_matrix", || {
        let bad_type2 = validate_type3_universal(&Type3CheckInput {
            tx_type: 2,
            chain_height: ISTANBUL_HEIGHT,
            gas_max: 100,
            has_asset_tex: false,
            ast_depth: 0,
            guard_only: false,
            action_count: 1,
        });
        assert!(!bad_type2.ok);

        let pre_istanbul = validate_type3_universal(&Type3CheckInput {
            tx_type: 3,
            chain_height: ISTANBUL_HEIGHT - 1,
            gas_max: 100,
            has_asset_tex: false,
            ast_depth: 0,
            guard_only: false,
            action_count: 1,
        });
        assert!(pre_istanbul.ok);
        assert!(!pre_istanbul.warnings.is_empty());

        let guard_only = validate_type3_universal(&Type3CheckInput {
            tx_type: 3,
            chain_height: ISTANBUL_HEIGHT,
            gas_max: 100,
            has_asset_tex: false,
            ast_depth: 0,
            guard_only: true,
            action_count: 1,
        });
        assert!(!guard_only.ok);
    });
}

#[test]
fn audit_hip23_matrix_p2_p3_combined() {
    audit_gate("hip23_p2_p3_matrix", || {
        let checks = validate_all_patterns(
            &Type3CheckInput {
                tx_type: 3,
                chain_height: ISTANBUL_HEIGHT,
                gas_max: 50,
                has_asset_tex: false,
                ast_depth: 0,
                guard_only: false,
                action_count: 2,
            },
            Some(&HeightScopeInput {
                start: 100,
                end: 200,
                guard_before_debit: true,
            }),
            Some(&BalanceFloorInput {
                floor_hacash_mei: 5.0,
                debit_before_floor: true,
            }),
        );
        assert_eq!(checks.len(), 3);
        assert!(checks.iter().all(|c| c.check.ok));

        let bad_p2 = validate_height_scope_pattern(&HeightScopeInput {
            start: 500,
            end: 100,
            guard_before_debit: true,
        });
        assert!(!bad_p2.ok);

        let bad_p3 = validate_balance_floor_pattern(&BalanceFloorInput {
            floor_hacash_mei: 0.0,
            debit_before_floor: true,
        });
        assert!(!bad_p3.ok);
    });
}
