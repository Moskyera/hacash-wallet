#![cfg(feature = "agent-wallet-testnet-pilot")]

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use axum::{
    Json, Router,
    routing::{get, post},
};
use hpay_companion_protocol::{
    ApprovalNetworkBinding, DevicePermission, DeviceRole, SignedWitnessReceipt, WitnessReceipt,
};
use serde_json::{Value, json};
use tokio::sync::RwLock;

use super::fixtures::*;
use super::*;
use crate::node_binding::verified_agent_node;

const TX_HASH: &str = "1111111111111111111111111111111111111111111111111111111111111111";

struct MockPilotNode {
    url: String,
    capabilities: Arc<RwLock<Value>>,
    submit_count: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockPilotNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MockPilotNode {
    async fn set_capabilities(&self, capabilities: Value) {
        *self.capabilities.write().await = capabilities;
    }
}

fn official_capabilities() -> Value {
    let instance_id = hacash_wallet_core::network_instance_id(
        hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
        hacash_wallet_core::HPAY_LOCAL_PILOT_CHAIN_ID,
        false,
        TESTNET_ANCHOR,
        hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
        2,
    );
    json!({
        "ret": 0,
        "api_version": 1,
        "node": { "name": "hacash-fullnode", "version": "1.0.10", "build_time": "test" },
        "chain": { "id": 7, "height": 10, "next_height": 11, "mainnet": false },
        "network": {
            "kind": hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
            "node_profile_id": hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
            "block_1_available": true,
            "block_1_hash": TESTNET_ANCHOR,
            "instance_id": instance_id,
            "funding_confirmed": true,
            "transaction_ready": true,
            "current_height": 10,
            "transaction_format_version": 2
        },
        "istanbul": { "activation_height": 1, "evaluation_height": 11, "active": true },
        "transactions": { "registered": [2, 3], "enabled": [2, 3] },
        "actions": { "registered": [1], "enabled": [1] },
        "features": {
            "action_guard": false, "tx_blob": false, "ast": false, "tex": false,
            "native_assets": false, "hip20": false, "hip20_primitives": false,
            "hvm": false, "p2sh": false, "account_abstraction": false,
            "intent": false, "contract_state_leasing": false,
            "ir_decompilation": false, "req_sign_list": false,
            "type4_mainnet": false, "exact_unsigned_simulation": false
        },
        "api": {
            "balance_query": true,
            "transaction_submit": true,
            "transaction_query": true,
            "reconciliation_by_tx_hash": true
        },
        "limits": {
            "max_tx_size": 1024, "max_tx_actions": 8, "max_type3_signers": 2,
            "gas_max_byte": 1,
            "gas_max": protocol::context::decode_gas_budget(1),
            "ast_depth": 1
        }
    })
}

async fn spawn_pilot_node() -> MockPilotNode {
    let capabilities = Arc::new(RwLock::new(official_capabilities()));
    let submit_count = Arc::new(AtomicUsize::new(0));
    let capability_state = capabilities.clone();
    let submit_state = submit_count.clone();
    let app = Router::new()
        .route(
            "/query/block/intro",
            get(|| async {
                Json(json!({
                    "ret": 0,
                    "height": 1,
                    "hash": TESTNET_ANCHOR
                }))
            }),
        )
        .route(
            "/query/capabilities",
            get(move || {
                let capability_state = capability_state.clone();
                async move { Json(capability_state.read().await.clone()) }
            }),
        )
        .route(
            "/submit/transaction",
            post(move || {
                let submit_state = submit_state.clone();
                async move {
                    submit_state.fetch_add(1, Ordering::SeqCst);
                    Json(json!({ "ret": 0 }))
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockPilotNode {
        url,
        capabilities,
        submit_count,
        task,
    }
}

fn create_manager_for_node(
    node_url: &str,
    now: u64,
) -> (tempfile::TempDir, AgentWalletManager, AgentWalletId) {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.to_owned(),
                network_mode: "testnet".to_owned(),
                node_url: node_url.to_owned(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.to_owned()),
            },
            now,
        )
        .unwrap();
    manager
        .unlock(&created.wallet_id, PASSPHRASE, now + 1)
        .unwrap();
    manager
        .enable_agent_payments_locally(&created.wallet_id, now + 2)
        .unwrap();
    (root, manager, created.wallet_id)
}

fn register_witness_mobile(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) {
    let permissions = BTreeSet::from([DevicePermission::WitnessRollbackAnchor]);
    let record = mobile
        .public_record(wallet_id.as_str(), permissions, now)
        .unwrap();
    manager
        .register_verified_companion_device(wallet_id, record, now)
        .unwrap();
}

async fn prepare_signed_operation(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    node_url: &str,
    now: u64,
) -> OperationId {
    let node = verified_agent_node(node_url, "testnet", TESTNET_ANCHOR)
        .await
        .unwrap();
    let (mut approval, operation_id) =
        prepare_pending(manager, wallet_id, ApprovalMode::MobileManual, now);
    approval.approval_version = 3;
    approval.network_binding = Some(ApprovalNetworkBinding {
        network_id: node.network_kind().to_owned(),
        chain_id: node.chain_id(),
        genesis_identifier: TESTNET_ANCHOR.to_owned(),
        node_profile_id: node.node_profile_id().to_owned(),
        transaction_format_version: node.transaction_format_version(),
    });

    let (state_master, journal_key) = keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let operation = state.operations.get(operation_id.as_str()).unwrap().clone();
    let mut encoded = serde_json::to_value(operation).unwrap();
    encoded["approval_commitment"] = serde_json::to_value(approval).unwrap();
    encoded["status"] = json!("signed_awaiting_witness");
    encoded["signed_tx_hex"] = json!("00");
    encoded["tx_hash"] = json!(TX_HASH);
    state.operations.insert(
        operation_id.to_string(),
        serde_json::from_value(encoded).unwrap(),
    );
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::TransactionSigned,
            Some(operation_id.as_str().as_bytes()),
            None,
            now,
        )
        .unwrap();
    operation_id
}

async fn signed_receipt(
    proposal: &hpay_companion_protocol::SignedRollbackAnchor,
    mobile: &SoftwareDeviceIdentity,
    now: u64,
) -> SignedWitnessReceipt {
    let anchor_hash = proposal.anchor.canonical_sha256_hex().unwrap();
    let receipt = WitnessReceipt::for_anchor(&proposal.anchor, anchor_hash, now).unwrap();
    SignedWitnessReceipt::sign(receipt, mobile).await.unwrap()
}

async fn prepared_witness_flow(
    now: u64,
) -> (
    tempfile::TempDir,
    AgentWalletManager,
    AgentWalletId,
    SoftwareDeviceIdentity,
    OperationId,
    hpay_companion_protocol::SignedRollbackAnchor,
    SignedWitnessReceipt,
    MockPilotNode,
) {
    let node = spawn_pilot_node().await;
    let (root, mut manager, wallet_id) = create_manager_for_node(&node.url, now);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, now + 2);
    let operation_id = prepare_signed_operation(&mut manager, &wallet_id, &node.url, now + 3).await;
    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), now + 4)
        .await
        .unwrap();
    let receipt = signed_receipt(&proposal, &mobile, now + 5).await;
    (
        root,
        manager,
        wallet_id,
        mobile,
        operation_id,
        proposal,
        receipt,
        node,
    )
}

fn persist_test_state(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    state: &mut AgentWalletState,
    event: AgentJournalEventKind,
    now: u64,
) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    state.updated_at = now;
    manager
        .persist_event(state, &state_master, &journal_key, event, None, None, now)
        .unwrap();
}

fn write_unvalidated_current_state(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    state: &AgentWalletState,
) {
    let (state_master, _journal_key) = keys(manager, wallet_id);
    manager
        .storage
        .write_encrypted(
            wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            &state_master,
            state,
        )
        .unwrap();
}
#[tokio::test]
async fn malformed_authenticated_checkpoint_is_rejected_on_load() {
    let (_root, mut manager, wallet_id, _mobile, _operation_id, _proposal, _receipt, _node) =
        prepared_witness_flow(100).await;
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state.rollback_witness.as_mut().unwrap().last_anchor_hash = "malformed".to_owned();
    write_unvalidated_current_state(&manager, &wallet_id, &state);

    assert_eq!(
        manager.unlocked_status(&wallet_id, 111),
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[tokio::test]
async fn decreasing_authenticated_checkpoint_is_rejected_on_load() {
    let (_root, mut manager, wallet_id, _mobile, _operation_id, proposal, _receipt, _node) =
        prepared_witness_flow(200).await;
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let witness = state.rollback_witness.as_mut().unwrap();
    witness.last_anchor_sequence = proposal.anchor.anchor_sequence;
    witness.last_anchor_hash = proposal.anchor.canonical_sha256_hex().unwrap();
    write_unvalidated_current_state(&manager, &wallet_id, &state);

    assert_eq!(
        manager.unlocked_status(&wallet_id, 211),
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[tokio::test]
async fn exact_receipt_retry_after_witnessed_state_submits_once() {
    let (_root, mut manager, wallet_id, _mobile, operation_id, proposal, receipt, node) =
        prepared_witness_flow(300).await;
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let witness = state.rollback_witness.as_mut().unwrap();
    witness.last_anchor_sequence = proposal.anchor.anchor_sequence;
    witness.last_anchor_hash = proposal.anchor.canonical_sha256_hex().unwrap();
    witness.pending.as_mut().unwrap().receipt = Some(receipt.clone());
    state
        .operations
        .get_mut(operation_id.as_str())
        .unwrap()
        .mark_witnessed()
        .unwrap();
    persist_test_state(
        &mut manager,
        &wallet_id,
        &mut state,
        AgentJournalEventKind::RollbackWitnessAccepted,
        306,
    );

    let result = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 307)
        .await
        .unwrap();
    assert_eq!(
        result.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn lost_ack_after_broadcast_submitted_returns_status_without_second_submit() {
    let (_root, mut manager, wallet_id, _mobile, _operation_id, _proposal, receipt, node) =
        prepared_witness_flow(400).await;

    let first = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt.clone(), 406)
        .await
        .unwrap();
    let retry = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, 407)
        .await
        .unwrap();

    assert_eq!(first.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert_eq!(retry.status, OperationStatus::SubmittedAwaitingFinalWitness);
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn final_witness_releases_reservation_and_allows_a_second_operation() {
    let (_root, mut manager, wallet_id, mobile, _first_id, first_proposal, first_receipt, node) =
        prepared_witness_flow(500).await;
    let submitted = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, first_receipt, 506)
        .await
        .unwrap();
    assert_eq!(
        submitted.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    let post_submit = manager
        .pending_rollback_anchor(&wallet_id, &submitted.operation_id, mobile.device_id(), 507)
        .await
        .unwrap();
    assert_eq!(
        post_submit.anchor.operation_phase,
        hpay_companion_protocol::RollbackOperationPhase::Submitted
    );
    let post_receipt = signed_receipt(&post_submit, &mobile, 508).await;
    let reconciliation = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, post_receipt, 509)
        .await
        .unwrap();
    assert_eq!(
        reconciliation.status,
        OperationStatus::ReconciliationRequired
    );
    let reconciled = manager
        .confirm_broadcast(&wallet_id, &submitted.operation_id, TX_HASH, 510)
        .unwrap();
    assert_eq!(
        reconciled.status,
        OperationStatus::ReconciledAwaitingFinalWitness
    );
    let final_anchor = manager
        .pending_rollback_anchor(&wallet_id, &submitted.operation_id, mobile.device_id(), 511)
        .await
        .unwrap();
    assert_eq!(
        final_anchor.anchor.operation_phase,
        hpay_companion_protocol::RollbackOperationPhase::ReconciledFinal
    );
    let final_receipt = signed_receipt(&final_anchor, &mobile, 512).await;
    let committed = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, final_receipt, 513)
        .await
        .unwrap();
    assert_eq!(committed.status, OperationStatus::Committed);
    assert_eq!(committed.reserved_units, HacUnits::ZERO);

    let second_id = prepare_signed_operation(&mut manager, &wallet_id, &node.url, 514).await;
    let second_proposal = manager
        .pending_rollback_anchor(&wallet_id, &second_id, mobile.device_id(), 515)
        .await
        .unwrap();

    assert_eq!(
        second_proposal.anchor.anchor_sequence,
        first_proposal.anchor.anchor_sequence + 3
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn expired_pending_proposal_requires_recovery() {
    let (_root, mut manager, wallet_id, mobile, operation_id, proposal, _receipt, _node) =
        prepared_witness_flow(600).await;
    assert_eq!(
        manager
            .pending_rollback_anchor(
                &wallet_id,
                &operation_id,
                mobile.device_id(),
                proposal.anchor.expires_at,
            )
            .await,
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[tokio::test]
async fn node_profile_change_between_approval_and_anchor_is_rejected() {
    let node = spawn_pilot_node().await;
    let (_root, mut manager, wallet_id) = create_manager_for_node(&node.url, 700);
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &mobile, 702);
    let operation_id = prepare_signed_operation(&mut manager, &wallet_id, &node.url, 703).await;
    let mut changed = official_capabilities();
    changed["actions"]["registered"] = json!([1, 2]);
    changed["actions"]["enabled"] = json!([1, 2]);
    node.set_capabilities(changed).await;

    assert_eq!(
        manager
            .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), 704)
            .await,
        Err(AgentWalletError::ApprovalCommitmentMismatch)
    );
    assert_eq!(node.submit_count.load(Ordering::SeqCst), 0);
}

async fn complete_prepared_operation(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    operation_id: &OperationId,
    first_receipt: SignedWitnessReceipt,
    now: u64,
) {
    let submitted = manager
        .apply_mobile_witness_and_broadcast(wallet_id, first_receipt, now)
        .await
        .unwrap();
    let submitted_anchor = manager
        .pending_rollback_anchor(wallet_id, operation_id, mobile.device_id(), now + 1)
        .await
        .unwrap();
    let submitted_receipt = signed_receipt(&submitted_anchor, mobile, now + 2).await;
    let reconciliation = manager
        .apply_mobile_witness_and_broadcast(wallet_id, submitted_receipt, now + 3)
        .await
        .unwrap();
    assert_eq!(
        reconciliation.status,
        OperationStatus::ReconciliationRequired
    );
    manager
        .confirm_broadcast(
            wallet_id,
            operation_id,
            submitted.tx_hash.as_deref().unwrap(),
            now + 4,
        )
        .unwrap();
    let final_anchor = manager
        .pending_rollback_anchor(wallet_id, operation_id, mobile.device_id(), now + 5)
        .await
        .unwrap();
    let final_receipt = signed_receipt(&final_anchor, mobile, now + 6).await;
    assert_eq!(
        manager
            .apply_mobile_witness_and_broadcast(wallet_id, final_receipt, now + 7)
            .await
            .unwrap()
            .status,
        OperationStatus::Committed
    );
}

async fn pair_unregistered_rotation_candidate(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    rotation_id: &str,
    candidate: &SoftwareDeviceIdentity,
    now: u64,
) {
    use hpay_companion_protocol::{
        LanEndpoint, MobilePairingAttempt, RotationCandidateAcceptance,
        SignedRotationCandidateAcceptance,
    };

    let endpoint = LanEndpoint::parse("hpay-lan://192.168.1.9:42492").unwrap();
    let mut desktop_attempt = manager
        .start_rotation_candidate_pairing(wallet_id, rotation_id, vec![endpoint], now, 240)
        .unwrap();
    let mobile_attempt =
        MobilePairingAttempt::start(desktop_attempt.offer().clone(), candidate, now + 1)
            .await
            .unwrap();
    let request = mobile_attempt.request().clone();
    let (confirmation, ticket) = manager
        .accept_rotation_candidate_pairing_request(
            wallet_id,
            &mut desktop_attempt,
            request,
            now + 2,
        )
        .await
        .unwrap();
    let acceptance = RotationCandidateAcceptance::for_ticket(&ticket.ticket, now + 3).unwrap();
    let signed_acceptance = SignedRotationCandidateAcceptance::sign(acceptance, candidate)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (ack, mobile_result) = mobile_attempt
        .confirm(&confirmation, &code, candidate, now + 3)
        .await
        .unwrap();
    drop(mobile_result);
    manager
        .accept_companion_pairing_ack(wallet_id, &mut desktop_attempt, &ack, now + 4)
        .unwrap();
    manager
        .complete_rotation_candidate_pairing_code(
            wallet_id,
            &mut desktop_attempt,
            &code,
            signed_acceptance,
            now + 4,
        )
        .unwrap();
}

#[tokio::test]
async fn normal_rotation_requires_old_authorization_new_baseline_and_completion_anchor() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
        WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationPhase,
        WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(800).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        806,
    )
    .await;
    let new_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_normal_one".to_owned(),
            new_mobile.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            821,
        )
        .await
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 822)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::AwaitingOldWitnessAuthorization)
    );
    let authorization = SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(&wallet_id, authorization, 823)
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &new_mobile,
        824,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        829,
    )
    .unwrap();
    let baseline = SignedWitnessRotationBaselineReceipt::sign(baseline, &new_mobile)
        .await
        .unwrap();
    manager
        .accept_witness_rotation_baseline(&wallet_id, baseline, 829)
        .unwrap();
    let devices = manager.list_companion_devices(&wallet_id, 830).unwrap();
    assert!(
        devices
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked()
    );
    assert!(
        devices
            .iter()
            .all(|device| device.device_id != *new_mobile.device_id()),
        "candidate must not enter the active registry before final completion"
    );
    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &record.rotation_id, 831)
        .await
        .unwrap();
    let completion_receipt = signed_receipt(&completion, &new_mobile, 832).await;
    manager
        .complete_witness_rotation(&wallet_id, completion_receipt.clone(), 832)
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 833)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::Completed)
    );
    assert_eq!(
        manager
            .complete_witness_rotation(&wallet_id, completion_receipt, 833)
            .unwrap(),
        record
    );
    assert!(
        manager
            .start_companion_desktop_session(&wallet_id, old_mobile.device_id(), 834, 60,)
            .await
            .is_err(),
        "the revoked old witness phone must never authenticate after rotation"
    );
    let third_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let second_record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_normal_two".to_owned(),
            third_mobile.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            835,
        )
        .await
        .unwrap();
    assert_eq!(second_record.old_mobile_device_id, *new_mobile.device_id());
    assert_eq!(second_record.old_witness_epoch, record.new_witness_epoch);
}

#[tokio::test]
async fn restricted_candidate_survives_restart_and_can_be_safely_cancelled_before_baseline() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, WitnessRotationMode, WitnessRotationPhase,
        WitnessRotationReason,
    };

    let (root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(1_100).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        1_106,
    )
    .await;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_cancel_before_baseline".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_121,
        )
        .await
        .unwrap();
    let authorization = SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(&wallet_id, authorization, 1_122)
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        1_123,
    )
    .await;
    assert!(
        manager
            .is_restricted_rotation_candidate(&wallet_id, candidate.device_id(), 1_128)
            .unwrap()
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 1_128)
            .unwrap()
            .iter()
            .all(|device| device.device_id != *candidate.device_id())
    );

    drop(manager);
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 1_129).unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 1_130)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::CandidatePairedRestricted)
    );
    manager
        .cancel_witness_rotation(&wallet_id, &record.rotation_id, 1_131)
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 1_132)
            .await
            .unwrap()
            .witness_rotation_phase,
        None
    );
    let devices = manager.list_companion_devices(&wallet_id, 1_132).unwrap();
    assert!(
        !devices
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked()
    );
    assert!(
        devices
            .iter()
            .all(|device| device.device_id != *candidate.device_id()),
        "cancelled candidate must never enter the general registry"
    );
    let retry_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_after_cancel".to_owned(),
            retry_candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_133,
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn cancellation_is_blocked_after_baseline_authority_transition() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
        WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(1_200).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        1_206,
    )
    .await;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_cancel_blocked".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_221,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            1_222,
        )
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        1_223,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        1_228,
    )
    .unwrap();
    manager
        .accept_witness_rotation_baseline(
            &wallet_id,
            SignedWitnessRotationBaselineReceipt::sign(baseline, &candidate)
                .await
                .unwrap(),
            1_228,
        )
        .unwrap();
    assert_eq!(
        manager.cancel_witness_rotation(&wallet_id, &record.rotation_id, 1_229),
        Err(AgentWalletError::InvalidOperationState)
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 1_230)
            .unwrap()
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked(),
        "old authority remains revoked after the transition"
    );
    assert!(
        manager
            .is_restricted_rotation_candidate(&wallet_id, candidate.device_id(), 1_230)
            .unwrap(),
        "candidate remains restricted until the completion receipt"
    );
}

#[tokio::test]
async fn restart_after_durable_baseline_completes_old_device_revocation_once() {
    use hpay_companion_protocol::{
        SignedWitnessRotationAuthorization, SignedWitnessRotationBaselineReceipt,
        WitnessRotationBaselineReceipt, WitnessRotationMode, WitnessRotationPhase,
        WitnessRotationReason,
    };

    let (root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(1_240).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        1_246,
    )
    .await;
    let candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_restart_after_baseline".to_owned(),
            candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_261,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            1_262,
        )
        .unwrap();
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &candidate,
        1_263,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        1_268,
    )
    .unwrap();
    let signed_baseline = SignedWitnessRotationBaselineReceipt::sign(baseline, &candidate)
        .await
        .unwrap();

    // Simulate a process loss after the baseline checkpoint was durably
    // authenticated but before the old-device revocation checkpoint.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let mut state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    state.witness_rotation.as_mut().unwrap().new_mobile_baseline = Some(signed_baseline.clone());
    state.updated_at = 1_268;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::WitnessRotationBaselineAccepted,
            None,
            Some(candidate.device_id().as_str().as_bytes()),
            1_268,
        )
        .unwrap();
    drop(manager);

    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    manager.unlock(&wallet_id, PASSPHRASE, 1_269).unwrap();
    manager
        .accept_witness_rotation_baseline(&wallet_id, signed_baseline.clone(), 1_270)
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 1_271)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::AwaitingCompletionAnchor)
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 1_271)
            .unwrap()
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked()
    );
    assert!(
        manager
            .is_restricted_rotation_candidate(&wallet_id, candidate.device_id(), 1_271)
            .unwrap()
    );
    assert_eq!(
        manager
            .accept_witness_rotation_baseline(&wallet_id, signed_baseline, 1_272)
            .unwrap(),
        record,
        "replaying the same durable baseline must be idempotent"
    );
}

#[tokio::test]
async fn rotation_ticket_is_single_use_and_blocks_concurrent_candidate_scan() {
    use hpay_companion_protocol::{
        LanEndpoint, MobilePairingAttempt, RotationCandidateAcceptance,
        SignedRotationCandidateAcceptance, SignedWitnessRotationAuthorization, WitnessRotationMode,
        WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(1_300).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        1_306,
    )
    .await;
    let first_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let second_candidate = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_single_use".to_owned(),
            first_candidate.device_id(),
            WitnessRotationMode::Normal,
            WitnessRotationReason::ReplacePhone,
            1_321,
        )
        .await
        .unwrap();
    manager
        .authorize_witness_rotation(
            &wallet_id,
            SignedWitnessRotationAuthorization::sign(record.clone(), &old_mobile)
                .await
                .unwrap(),
            1_322,
        )
        .unwrap();

    let endpoint = LanEndpoint::parse("hpay-lan://192.168.1.9:42492").unwrap();
    let mut desktop_attempt = manager
        .start_rotation_candidate_pairing(
            &wallet_id,
            &record.rotation_id,
            vec![endpoint.clone()],
            1_323,
            240,
        )
        .unwrap();
    let mobile_attempt =
        MobilePairingAttempt::start(desktop_attempt.offer().clone(), &first_candidate, 1_324)
            .await
            .unwrap();
    let (confirmation, ticket) = manager
        .accept_rotation_candidate_pairing_request(
            &wallet_id,
            &mut desktop_attempt,
            mobile_attempt.request().clone(),
            1_325,
        )
        .await
        .unwrap();
    assert!(
        manager
            .start_rotation_candidate_pairing(
                &wallet_id,
                &record.rotation_id,
                vec![endpoint],
                1_326,
                240,
            )
            .is_err(),
        "a second candidate cannot race an already-issued ticket"
    );
    let acceptance = RotationCandidateAcceptance::for_ticket(&ticket.ticket, 1_326).unwrap();
    let signed_acceptance = SignedRotationCandidateAcceptance::sign(acceptance, &first_candidate)
        .await
        .unwrap();
    let code = confirmation.verification_code.clone();
    let (ack, result) = mobile_attempt
        .confirm(&confirmation, &code, &first_candidate, 1_326)
        .await
        .unwrap();
    let candidate_record = result.mobile_device_record.clone();
    drop(result);
    manager
        .accept_companion_pairing_ack(&wallet_id, &mut desktop_attempt, &ack, 1_327)
        .unwrap();
    manager
        .complete_rotation_candidate_pairing_code(
            &wallet_id,
            &mut desktop_attempt,
            &code,
            signed_acceptance.clone(),
            1_327,
        )
        .unwrap();
    assert_eq!(
        manager.accept_rotation_candidate(
            &wallet_id,
            &record.rotation_id,
            candidate_record,
            signed_acceptance,
            1_328,
        ),
        Err(AgentWalletError::InvalidOperationState),
        "the consumed ticket cannot be replayed"
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 1_329)
            .unwrap()
            .iter()
            .all(|device| device.device_id != *second_candidate.device_id())
    );
}

#[tokio::test]
async fn lost_phone_rotation_is_blocked_by_unresolved_financial_state() {
    use hpay_companion_protocol::{WitnessRotationMode, WitnessRotationReason};

    let (_root, mut manager, wallet_id, _old_mobile, _operation_id, _proposal, _receipt, _node) =
        prepared_witness_flow(900).await;
    let new_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    register_witness_mobile(&mut manager, &wallet_id, &new_mobile, 906);
    assert_eq!(
        manager
            .prepare_witness_rotation(
                &wallet_id,
                "rotation_blocked".to_owned(),
                new_mobile.device_id(),
                WitnessRotationMode::LostPhoneRecovery,
                WitnessRotationReason::LostPhone,
                907,
            )
            .await,
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[tokio::test]
async fn lost_phone_rotation_requires_clean_state_live_node_and_new_baseline() {
    use hpay_companion_protocol::{
        SignedWitnessRotationBaselineReceipt, WitnessRotationBaselineReceipt, WitnessRotationMode,
        WitnessRotationPhase, WitnessRotationReason,
    };

    let (_root, mut manager, wallet_id, old_mobile, operation_id, _proposal, first_receipt, _node) =
        prepared_witness_flow(940).await;
    complete_prepared_operation(
        &mut manager,
        &wallet_id,
        &old_mobile,
        &operation_id,
        first_receipt,
        946,
    )
    .await;
    let new_mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = manager
        .prepare_witness_rotation(
            &wallet_id,
            "rotation_lost_phone_one".to_owned(),
            new_mobile.device_id(),
            WitnessRotationMode::LostPhoneRecovery,
            WitnessRotationReason::LostPhone,
            961,
        )
        .await
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 962)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::AwaitingCandidatePairing)
    );
    pair_unregistered_rotation_candidate(
        &mut manager,
        &wallet_id,
        &record.rotation_id,
        &new_mobile,
        963,
    )
    .await;
    let baseline = WitnessRotationBaselineReceipt::for_rotation(
        &record,
        record.canonical_sha256_hex().unwrap(),
        968,
    )
    .unwrap();
    manager
        .accept_witness_rotation_baseline(
            &wallet_id,
            SignedWitnessRotationBaselineReceipt::sign(baseline, &new_mobile)
                .await
                .unwrap(),
            968,
        )
        .unwrap();
    let completion = manager
        .pending_witness_rotation_completion_anchor(&wallet_id, &record.rotation_id, 969)
        .await
        .unwrap();
    manager
        .complete_witness_rotation(
            &wallet_id,
            signed_receipt(&completion, &new_mobile, 970).await,
            970,
        )
        .unwrap();
    assert_eq!(
        manager
            .overview(&wallet_id, 971)
            .await
            .unwrap()
            .witness_rotation_phase,
        Some(WitnessRotationPhase::Completed)
    );
    assert!(
        manager
            .list_companion_devices(&wallet_id, 971)
            .unwrap()
            .iter()
            .find(|device| device.device_id == *old_mobile.device_id())
            .unwrap()
            .is_revoked()
    );
}
