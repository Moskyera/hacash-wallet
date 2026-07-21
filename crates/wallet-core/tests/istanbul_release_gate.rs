//! RELEASE-GATE: wallet compatibility with the activated Hacash protocol upgrade.
//!
//! These tests deliberately exercise the official protocol codecs used by the wallet.
//! They contain no network calls and must stay deterministic across desktop, Android and CI.

mod common;

use std::sync::Weak;

use basis::component::{Env, ExecFrom, MemMap};
use basis::interface::{
    ActExec, Action, Context, State, StateOperat, Transaction, TransactionRead,
};
use common::{tier0_gate, with_isolated_wallet_dir, with_protocol_setup};
use field::{AddrOrPtr, Address, Amount, AssetAmt, Field, Fold64, Serialize, ToJSON, Uint1};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::airgap::{AIRGAP_VERSION, AirgapSigned, AirgapUnsigned};
use hacash_wallet_core::send_options::{
    WALLET_TREASURY_ADDRESS, compute_service_fee_mei, format_service_fee_amount_wire,
};
use hacash_wallet_core::tx_binding::decode_transaction;
use hacash_wallet_core::{WalletError, WalletService};
use protocol::action::{
    AssetToTrs, AstIf, AstSelect, BalanceFloor, ChainAllow, HacFromTrs, HacToTrs, HeightScope,
    ReqSignList, TxBlob, TxMessage, action_create, precheck_tx_actions,
};
use protocol::context::ContextInst;
use protocol::state::{CoreState, EmptyLogs};
use protocol::tex::{
    CellCondChainIdEq, CellCondHeightAtMost, CellTrsZhuGet, CellTrsZhuPay, TexCellAct,
    do_settlement,
};
use protocol::transaction::{TransactionType2, TransactionType3, transaction_create};
use sys::{Account, ToHex};

const TEST_TIMESTAMP: u64 = 1_730_000_000;

fn account(seed: &str) -> Account {
    Account::create_by(seed).expect("deterministic test account")
}

fn address(account: &Account) -> Address {
    Address::from(*account.address())
}

fn hac_to(to: Address, amount: Amount) -> HacToTrs {
    let mut action = HacToTrs::new();
    action.to = AddrOrPtr::from_addr(to);
    action.hacash = amount;
    action
}

fn hac_from(from: Address, amount: Amount) -> HacFromTrs {
    let mut action = HacFromTrs::new();
    action.from = AddrOrPtr::from_addr(from);
    action.hacash = amount;
    action
}

fn ordinary_action() -> Box<dyn Action> {
    Box::new(hac_to(Address::create_privakey([0x42; 20]), Amount::mei(1)))
}

fn nested_ast(depth: usize) -> Box<dyn Action> {
    let mut action = ordinary_action();
    for _ in 0..depth {
        action = Box::new(AstSelect::create_list(vec![action]));
    }
    action
}

#[test]
fn release_gate_type2_known_shape_roundtrips_and_keeps_legacy_signature_semantics() {
    tier0_gate("istanbul_type2_backward_compatibility", || {
        with_protocol_setup(|| {
            let main = account("istanbul-type2-main");
            let unrelated = account("istanbul-type2-unrelated");
            let recipient = address(&account("istanbul-type2-recipient"));
            let mut tx = TransactionType2::new_by(address(&main), Amount::mei(1), TEST_TIMESTAMP);
            tx.push_action(Box::new(hac_to(recipient, Amount::mei(7))))
                .unwrap();

            tx.fill_sign(&main).unwrap();
            // Type 2 intentionally retains its historical at-least-required-signers behavior.
            // This distinguishes it from exact-set Type 3 without breaking old transactions.
            tx.fill_sign(&unrelated).unwrap();
            tx.verify_signature().unwrap();

            let wire = tx.serialize();
            let (decoded, consumed) = transaction_create(&wire).unwrap();
            assert_eq!(consumed, wire.len());
            assert_eq!(decoded.ty(), TransactionType2::TYPE);
            assert_eq!(decoded.main(), address(&main));
            assert_eq!(decoded.action_count(), 1);
            assert_eq!(decoded.actions()[0].kind(), HacToTrs::KIND);
            decoded.verify_signature().unwrap();

            let reviewed = decode_transaction(&wire.to_hex()).unwrap();
            assert_eq!(reviewed.tx_type, TransactionType2::TYPE);
            assert_eq!(reviewed.main_address, address(&main).to_readable());
            assert_eq!(reviewed.actions[0].kind, HacToTrs::KIND);
        });
    });
}

#[test]
fn release_gate_all_protocol_address_versions_roundtrip_without_network_rewriting() {
    tier0_gate("istanbul_address_version_matrix", || {
        let cases = [
            ("privakey", Address::create_privakey([0x10; 20]), 0, true),
            ("contract", Address::create_contract([0x11; 20]), 1, false),
            ("scriptmh", Address::create_scriptmh([0x12; 20]), 5, false),
            ("pqckey", Address::create_pqckey([0x13; 20]), 6, true),
            ("hybrid", Address::create_hybrid([0x14; 20]), 7, true),
        ];

        for (name, expected, version, can_sign) in cases {
            let readable = expected.to_readable();
            let parsed = Address::from_readable(&readable)
                .unwrap_or_else(|error| panic!("{name} address did not parse: {error}"));
            assert_eq!(parsed, expected, "{name} payload changed on roundtrip");
            assert_eq!(parsed.version(), version, "{name} version");
            assert_eq!(
                parsed.is_user_signing_address(),
                can_sign,
                "{name} signing class"
            );

            // Hacash addresses do not embed a mainnet/testnet bit. Network selection must
            // therefore never rewrite their Base58Check representation.
            for _network in ["mainnet", "testnet"] {
                assert_eq!(Address::from_readable(&readable).unwrap(), expected);
            }
        }

        for unsupported_version in [2_u8, 3, 4, 8, u8::MAX] {
            let mut raw = [0x55; Address::SIZE];
            raw[0] = unsupported_version;
            assert!(
                Address::from_bytes(&raw).is_err(),
                "unsupported address version {unsupported_version} must fail closed"
            );
        }
    });
}

#[test]
fn release_gate_each_guard_rejects_guard_only_and_allows_a_real_leaf() {
    tier0_gate("istanbul_guard_topology_matrix", || {
        let guards: Vec<(&str, Box<dyn Action>)> = vec![
            ("tx_message", Box::new(TxMessage::new())),
            ("tx_blob", Box::new(TxBlob::new())),
            ("chain_allow", Box::new(ChainAllow::new())),
            ("height_scope", Box::new(HeightScope::new())),
            ("balance_floor", Box::new(BalanceFloor::new())),
            (
                "req_sign_list",
                Box::new(
                    ReqSignList::create_by_addrs(vec![address(&account("guard-extra-signer"))])
                        .unwrap(),
                ),
            ),
        ];

        for (name, guard) in guards {
            let only_guard = vec![guard.clone()];
            let error = precheck_tx_actions(TransactionType3::TYPE, &only_guard)
                .expect_err("guard-only transaction must be rejected");
            assert!(error.contains("GUARD"), "{name}: {error}");

            let guard_and_leaf = vec![guard, ordinary_action()];
            precheck_tx_actions(TransactionType3::TYPE, &guard_and_leaf)
                .unwrap_or_else(|error| panic!("{name} plus ordinary action failed: {error}"));
        }

        let hidden_guard: Vec<Box<dyn Action>> =
            vec![Box::new(AstSelect::create_list(vec![Box::new(
                HeightScope::new(),
            )]))];
        let error = precheck_tx_actions(TransactionType3::TYPE, &hidden_guard).unwrap_err();
        assert!(error.contains("GUARD"), "{error}");

        let type1_guard: Vec<Box<dyn Action>> =
            vec![Box::new(HeightScope::new()), ordinary_action()];
        let error = precheck_tx_actions(1, &type1_guard).unwrap_err();
        assert!(error.contains("requires tx type >= 2"), "{error}");
    });
}

#[test]
fn release_gate_ast_depth_and_all_branch_signers_are_static() {
    tier0_gate("istanbul_ast_depth_and_signers", || {
        let depth_six = vec![nested_ast(6)];
        precheck_tx_actions(TransactionType3::TYPE, &depth_six)
            .expect("the documented depth-six AST must be accepted");

        let depth_seven = vec![nested_ast(7)];
        let error = precheck_tx_actions(TransactionType3::TYPE, &depth_seven)
            .expect_err("depth seven must be rejected");
        assert!(error.contains("depth") && error.contains("max"), "{error}");

        let type2_ast = vec![nested_ast(1)];
        let error = precheck_tx_actions(TransactionType2::TYPE, &type2_ast)
            .expect_err("AST must require Type 3");
        assert!(error.contains("requires tx type >= 3"), "{error}");

        let main = account("istanbul-ast-main");
        let cond = account("istanbul-ast-cond");
        let branch_if = account("istanbul-ast-if");
        let branch_else = account("istanbul-ast-else");
        let tree = AstIf::create_by(
            AstSelect::create_list(vec![Box::new(hac_from(address(&cond), Amount::mei(1)))]),
            AstSelect::create_list(vec![Box::new(hac_from(
                address(&branch_if),
                Amount::mei(1),
            ))]),
            AstSelect::create_list(vec![Box::new(hac_from(
                address(&branch_else),
                Amount::mei(1),
            ))]),
        );
        let mut tx = TransactionType3::new_by(address(&main), Amount::mei(1), TEST_TIMESTAMP);
        tx.push_action(Box::new(tree)).unwrap();
        let required = tx.req_sign().unwrap();
        for required_address in [
            address(&main),
            address(&cond),
            address(&branch_if),
            address(&branch_else),
        ] {
            assert!(
                required.contains(&required_address),
                "static signer set omitted {required_address}"
            );
        }
        assert_eq!(required.len(), 4);
    });
}

#[test]
fn release_gate_type3_gas_and_reqsignlist_use_an_exact_signer_set() {
    tier0_gate("istanbul_type3_exact_signers", || {
        with_protocol_setup(|| {
            let main = account("istanbul-type3-main");
            let extra = account("istanbul-type3-extra");
            let rogue = account("istanbul-type3-rogue");
            let recipient = address(&account("istanbul-type3-recipient"));
            let mut tx = TransactionType3::new_by(address(&main), Amount::mei(1), TEST_TIMESTAMP);
            tx.gas_max = Uint1::from(17);
            tx.push_action(Box::new(hac_to(recipient, Amount::mei(2))))
                .unwrap();
            tx.push_action(Box::new(
                ReqSignList::create_by_addrs(vec![address(&extra)]).unwrap(),
            ))
            .unwrap();

            precheck_tx_actions(tx.ty(), tx.actions()).unwrap();
            assert_eq!(tx.gas_max_byte(), Some(17));
            let required = tx.deterministic_signers().unwrap();
            assert_eq!(required.len(), 2);
            assert!(required.contains(&address(&main)));
            assert!(required.contains(&address(&extra)));
            assert_eq!(tx.missing_signers().unwrap(), required);
            assert!(tx.verify_signature().is_err());

            let hash_with_gas_17 = tx.hash();
            let mut changed_gas = tx.clone();
            changed_gas.gas_max = Uint1::from(18);
            assert_ne!(
                hash_with_gas_17,
                changed_gas.hash(),
                "gas_max must be signed"
            );

            tx.fill_sign(&main).unwrap();
            assert_eq!(tx.missing_signers().unwrap(), [address(&extra)].into());
            assert!(tx.verify_signature().is_err());
            tx.fill_sign(&extra).unwrap();
            tx.verify_signature().unwrap();
            assert!(
                tx.fill_sign(&rogue).is_err(),
                "undeclared Type 3 signer must be rejected"
            );

            let wire = tx.serialize();
            let (decoded, consumed) = transaction_create(&wire).unwrap();
            assert_eq!(consumed, wire.len());
            assert_eq!(decoded.ty(), TransactionType3::TYPE);
            assert_eq!(decoded.gas_max_byte(), Some(17));
            assert_eq!(decoded.req_sign().unwrap(), required);
            decoded.verify_signature().unwrap();

            let duplicate_actions: Vec<Box<dyn Action>> = vec![
                ordinary_action(),
                Box::new(ReqSignList::create_by_addrs(vec![address(&extra)]).unwrap()),
                Box::new(ReqSignList::create_by_addrs(vec![address(&rogue)]).unwrap()),
            ];
            let error = precheck_tx_actions(TransactionType3::TYPE, &duplicate_actions)
                .expect_err("ReqSignList must be top-level unique");
            assert!(error.contains("UNIQUE"), "{error}");

            let mut overlap =
                TransactionType3::new_by(address(&main), Amount::mei(1), TEST_TIMESTAMP);
            overlap.push_action(ordinary_action()).unwrap();
            overlap
                .push_action(Box::new(
                    ReqSignList::create_by_addrs(vec![address(&main)]).unwrap(),
                ))
                .unwrap();
            let error = overlap.deterministic_signers().unwrap_err();
            assert!(error.contains("overlaps intrinsic"), "{error}");

            let mut scripted =
                TransactionType3::new_by(address(&main), Amount::mei(1), TEST_TIMESTAMP);
            scripted.push_action(ordinary_action()).unwrap();
            scripted
                .push_action(Box::new(
                    ReqSignList::create_by_addrs(vec![Address::create_contract([0x77; 20])])
                        .unwrap(),
                ))
                .unwrap();
            let error = scripted.deterministic_signers().unwrap_err();
            assert!(error.contains("PRIVAKEY"), "{error}");
        });
    });
}

#[derive(Default, Clone)]
struct ReleaseGateState {
    parent: Weak<Box<dyn State>>,
    mem: MemMap,
}

impl State for ReleaseGateState {
    fn fork_sub(&self, parent: Weak<Box<dyn State>>) -> Box<dyn State> {
        Box::new(Self {
            parent,
            mem: MemMap::default(),
        })
    }

    fn merge_sub(&mut self, state: Box<dyn State>) {
        self.mem.extend(state.as_mem().clone());
    }

    fn detach(&mut self) {
        self.parent = Weak::new();
    }

    fn clone_state(&self) -> Box<dyn State> {
        Box::new(self.clone())
    }

    fn as_mem(&self) -> &MemMap {
        &self.mem
    }

    fn get(&self, key: Vec<u8>) -> Option<Vec<u8>> {
        if let Some(value) = self.mem.get(&key) {
            return value.clone();
        }
        self.parent.upgrade().and_then(|parent| parent.get(key))
    }

    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.mem.insert(key, Some(value));
    }

    fn del(&mut self, key: Vec<u8>) {
        self.mem.insert(key, None);
    }
}

fn tex_context(tx: &TransactionType3) -> ContextInst<'_> {
    let mut env = Env::default();
    env.chain.fast_sync = true;
    env.tx = protocol::transaction::create_tx_info(tx);
    ContextInst::new(
        env,
        Box::new(ReleaseGateState::default()),
        Box::new(EmptyLogs {}),
        tx,
    )
}

fn guarded_tex_bundle(account: &Account, pays: bool) -> TexCellAct {
    let mut bundle = TexCellAct::create_by(address(account));
    bundle
        .add_cell(Box::new(CellCondChainIdEq::new(0)))
        .unwrap();
    bundle
        .add_cell(Box::new(CellCondHeightAtMost::new(800_000)))
        .unwrap();
    let amount = Fold64::from(100).unwrap();
    if pays {
        bundle
            .add_cell(Box::new(CellTrsZhuPay::new(amount)))
            .unwrap();
    } else {
        bundle
            .add_cell(Box::new(CellTrsZhuGet::new(amount)))
            .unwrap();
    }
    bundle.do_sign(account).unwrap();
    bundle
}

#[test]
fn release_gate_tex_is_replayable_but_chain_expiry_bound_and_zero_sum() {
    tier0_gate("istanbul_tex_replay_guards_zero_sum", || {
        with_protocol_setup(|| {
            let payer = account("istanbul-tex-payer");
            let receiver = account("istanbul-tex-receiver");
            let pay_bundle = guarded_tex_bundle(&payer, true);
            let get_bundle = guarded_tex_bundle(&receiver, false);

            let bundle_json = pay_bundle.to_json();
            assert!(
                bundle_json.contains("\"cellid\":25"),
                "chain-id condition missing"
            );
            assert!(
                bundle_json.contains("\"cellid\":23"),
                "expiry condition missing"
            );

            let mut first = TransactionType3::new_by(
                address(&account("istanbul-tex-main-a")),
                Amount::mei(1),
                TEST_TIMESTAMP,
            );
            first.push_action(Box::new(pay_bundle.clone())).unwrap();
            let mut second = TransactionType3::new_by(
                address(&account("istanbul-tex-main-b")),
                Amount::mei(1),
                TEST_TIMESTAMP + 1,
            );
            second.push_action(Box::new(pay_bundle.clone())).unwrap();
            assert_eq!(
                first.actions()[0].serialize(),
                second.actions()[0].serialize()
            );
            assert_ne!(first.hash(), second.hash());

            let settlement_tx = TransactionType3::new_by(
                address(&account("istanbul-tex-settlement-main")),
                Amount::mei(1),
                TEST_TIMESTAMP,
            );
            let mut balanced = tex_context(&settlement_tx);
            {
                let mut state = CoreState::wrap(balanced.state());
                let mut payer_balance = state.balance(&address(&payer)).unwrap_or_default();
                payer_balance.hacash = Amount::zhu(100);
                state.balance_set(&address(&payer), &payer_balance);
            }
            balanced.exec_from_set(ExecFrom::Top);
            pay_bundle.execute(&mut balanced).unwrap();
            balanced.exec_from_set(ExecFrom::Top);
            get_bundle.execute(&mut balanced).unwrap();
            do_settlement(&mut balanced).expect("equal TEX pay/get legs must settle");

            let mut unbalanced = tex_context(&settlement_tx);
            {
                let mut state = CoreState::wrap(unbalanced.state());
                let mut payer_balance = state.balance(&address(&payer)).unwrap_or_default();
                payer_balance.hacash = Amount::zhu(100);
                state.balance_set(&address(&payer), &payer_balance);
            }
            unbalanced.exec_from_set(ExecFrom::Top);
            pay_bundle.execute(&mut unbalanced).unwrap();
            let error =
                do_settlement(&mut unbalanced).expect_err("non-zero TEX ledger must not settle");
            assert!(error.contains("coin settlement check failed"), "{error}");
        });
    });
}

#[test]
fn release_gate_native_asset_transfer_preserves_serial_amount_and_recipient() {
    tier0_gate("istanbul_native_asset_codec", || {
        with_protocol_setup(|| {
            let main = account("istanbul-asset-main");
            let recipient = address(&account("istanbul-asset-recipient"));
            let mut transfer = AssetToTrs::new();
            transfer.to = AddrOrPtr::from_addr(recipient);
            transfer.asset = AssetAmt::from(7_654, 987_654_321).unwrap();

            let mut tx = TransactionType2::new_by(address(&main), Amount::mei(1), TEST_TIMESTAMP);
            tx.push_action(Box::new(transfer)).unwrap();
            let wire = tx.serialize();
            let reviewed = decode_transaction(&wire.to_hex()).unwrap();
            assert_eq!(reviewed.tx_type, TransactionType2::TYPE);
            assert_eq!(reviewed.actions.len(), 1);
            assert_eq!(reviewed.actions[0].kind, AssetToTrs::KIND);
            assert_eq!(
                reviewed.actions[0].canonical_json["to"],
                recipient.to_readable()
            );
            assert_eq!(reviewed.actions[0].canonical_json["asset"]["serial"], 7_654);
            assert_eq!(
                reviewed.actions[0].canonical_json["asset"]["amount"],
                987_654_321_u64
            );
        });
    });
}

#[test]
fn release_gate_malformed_hvm_p2sh_and_unknown_actions_fail_closed() {
    tier0_gate("istanbul_vm_p2sh_decode_fail_closed", || {
        with_protocol_setup(|| {
            for (name, bytes) in [
                ("contract_main_call", vec![0x00, 44]),
                ("p2sh_script_prove", vec![0x00, 46]),
                ("unknown_action", vec![0xff, 0xff]),
            ] {
                assert!(
                    action_create(&bytes).is_err(),
                    "truncated or unknown {name} action must never decode"
                );
            }

            let main = account("istanbul-malformed-vm-main");
            let mut tx = TransactionType3::new_by(address(&main), Amount::mei(1), TEST_TIMESTAMP);
            tx.push_action(Box::new(TxBlob::new())).unwrap();
            let wire = tx.serialize();

            for replacement_kind in [44_u16, 46_u16] {
                let mut malformed = wire.clone();
                let original = TxBlob::KIND.to_be_bytes();
                let position = malformed
                    .windows(2)
                    .position(|window| window == original)
                    .expect("TxBlob kind in serialized transaction");
                malformed[position..position + 2].copy_from_slice(&replacement_kind.to_be_bytes());
                assert!(
                    decode_transaction(&malformed.to_hex()).is_err(),
                    "malformed action {replacement_kind} must fail at the wallet review boundary"
                );
            }
        });
    });
}

fn unsigned_airgap_fixture(from: Address) -> AirgapUnsigned {
    let to = address(&account("istanbul-airgap-recipient"));
    let amount_mei = 1.0;
    let amount_wire = "1".to_string();
    let service_fee_mei = compute_service_fee_mei(amount_mei);
    let service_fee_wire = format_service_fee_amount_wire(service_fee_mei);
    let fee = "1:244".to_string();

    let mut tx = TransactionType2::new_by(
        from,
        Amount::from(fee.as_str()).expect("fee amount"),
        TEST_TIMESTAMP,
    );
    tx.push_action(Box::new(hac_to(
        to,
        Amount::from(amount_wire.as_str()).expect("send amount"),
    )))
    .unwrap();
    tx.push_action(Box::new(hac_to(
        Address::from_readable(WALLET_TREASURY_ADDRESS).expect("treasury address"),
        Amount::from(service_fee_wire.as_str()).expect("service fee amount"),
    )))
    .unwrap();

    AirgapUnsigned {
        v: AIRGAP_VERSION,
        from: from.to_readable(),
        to: to.to_readable(),
        amount_mei,
        amount_wire,
        fee,
        service_fee_mei,
        service_fee_treasury: Some(WALLET_TREASURY_ADDRESS.to_string()),
        body_hex: tx.serialize().to_hex(),
        summary: "release-gate L1 air-gap fixture".to_string(),
        tx_type: TransactionType2::TYPE,
    }
}

#[test]
fn release_gate_airgap_signing_rejects_envelope_body_mismatches() {
    tier0_gate("istanbul_airgap_sign_binding", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let signing_account = WalletAccount::create_random().unwrap();
                let seed = signing_account.secret_hex();
                let unsigned = unsigned_airgap_fixture(
                    Address::from_readable(&signing_account.address()).unwrap(),
                );
                let mut wallet = WalletService::new(None, None).unwrap();
                let imported = wallet.import_wallet(&seed, "airgap-passphrase12").unwrap();
                assert_eq!(imported, unsigned.from);
                wallet
                    .sign_airgap_unsigned(&unsigned)
                    .expect("canonical fixture must sign");

                let mut mutations: Vec<(&str, AirgapUnsigned)> = Vec::new();
                let mut wrong_to = unsigned.clone();
                wrong_to.to = address(&account("istanbul-airgap-attacker")).to_readable();
                mutations.push(("recipient", wrong_to));
                let mut wrong_amount = unsigned.clone();
                wrong_amount.amount_wire = "2".to_string();
                mutations.push(("amount", wrong_amount));
                let mut wrong_fee = unsigned.clone();
                wrong_fee.fee = "2:244".to_string();
                mutations.push(("network fee", wrong_fee));
                let mut wrong_service_fee = unsigned.clone();
                wrong_service_fee.service_fee_mei += 0.001;
                mutations.push(("service fee", wrong_service_fee));
                let mut wrong_treasury = unsigned.clone();
                wrong_treasury.service_fee_treasury = Some(unsigned.to.clone());
                mutations.push(("treasury", wrong_treasury));
                let mut wrong_body = unsigned.clone();
                wrong_body.body_hex.push_str("00");
                mutations.push(("body trailing bytes", wrong_body));

                for (name, mutated) in mutations {
                    assert!(
                        wallet.sign_airgap_unsigned(&mutated).is_err(),
                        "offline signer accepted mismatched {name}"
                    );
                }
            });
        });
    });
}

#[test]
fn release_gate_airgap_broadcast_rejects_metadata_before_network_submission() {
    tier0_gate("istanbul_airgap_broadcast_binding", || {
        with_isolated_wallet_dir(|| {
            with_protocol_setup(|| {
                let runtime = tokio::runtime::Runtime::new().unwrap();
                let signing_account = WalletAccount::create_random().unwrap();
                let seed = signing_account.secret_hex();
                let unsigned = unsigned_airgap_fixture(
                    Address::from_readable(&signing_account.address()).unwrap(),
                );
                let mut wallet = WalletService::new(None, None).unwrap();
                wallet.import_wallet(&seed, "airgap-passphrase12").unwrap();
                let signed = wallet.sign_airgap_unsigned(&unsigned).unwrap().envelope;

                let mut wrong_type: AirgapSigned = signed.clone();
                wrong_type.tx_type = TransactionType3::TYPE;
                let error = runtime
                    .block_on(wallet.broadcast_airgap_signed(&wrong_type))
                    .unwrap_err();
                assert!(matches!(error, WalletError::Policy(_)));

                let mut wrong_to = signed;
                wrong_to.to = address(&account("istanbul-airgap-broadcast-attacker")).to_readable();
                let error = runtime
                    .block_on(wallet.broadcast_airgap_signed(&wrong_to))
                    .unwrap_err();
                assert!(matches!(error, WalletError::Policy(_)));
            });
        });
    });
}
