use super::payment::{
    ensure_agent_request_rate, ensure_operation_capacity, random_challenge_nonce,
};
use super::state::{prune_aged_terminal_pre_signing_operations, state_commitment};
use super::*;
use crate::journal::{AgentJournal, AgentJournalEvent};
const PASSPHRASE: &str = "agent wallet passphrase 123";

fn create_request() -> CreateAgentWallet {
    CreateAgentWallet {
        passphrase: PASSPHRASE.into(),
        network_mode: "testnet".into(),
        node_url: "http://127.0.0.1:18081".into(),
        block_one_fingerprint: Some(
            "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff".into(),
        ),
    }
}

fn insert_indexed_operation(
    state: &mut AgentWalletState,
    agent_id: &AgentId,
    idempotency_key: &str,
    status: OperationStatus,
    created_at: u64,
    expires_at: u64,
) -> (OperationId, String) {
    let mut operation = AgentOperation::new(
        OperationId::new(),
        agent_id.clone(),
        state.wallet_id.clone(),
        AgentPaymentRequest {
            idempotency_key: idempotency_key.to_owned(),
            asset: "HAC".to_owned(),
            amount_units: HacUnits::new(10_000),
            recipient: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS".to_owned(),
            reason: "compaction invariant".to_owned(),
            expires_at,
        },
        created_at,
    )
    .unwrap();
    match status {
        OperationStatus::Cancelled => {
            operation.cancel_pre_signing("test_cancelled").unwrap();
        }
        OperationStatus::Failed => {
            operation.fail_unsigned("test_failed").unwrap();
        }
        OperationStatus::PaymentIntentCreated => {}
        other => {
            let mut encoded = serde_json::to_value(&operation).unwrap();
            encoded["status"] = serde_json::to_value(other).unwrap();
            if matches!(other, OperationStatus::Rejected) {
                encoded["final_result"] = serde_json::json!("test_rejected");
            }
            operation = serde_json::from_value(encoded).unwrap();
        }
    }
    let view = operation.view();
    let operation_id = view.operation_id.clone();
    let scoped_key = scoped_idempotency_key(agent_id, idempotency_key);
    state.idempotency.insert(
        scoped_key.clone(),
        IdempotencyRecord {
            request_commitment: view.request_commitment,
            operation_id: operation_id.clone(),
        },
    );
    state
        .operations
        .insert(operation_id.as_str().to_owned(), operation);
    (operation_id, scoped_key)
}

fn wallet_state(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
) -> (AgentWalletState, [u8; 32], [u8; 32]) {
    let session = manager.session(wallet_id).unwrap();
    let state_master = *session.state_master;
    let journal_key = *session.journal_key;
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    (state, state_master, journal_key)
}
#[test]
fn create_rejects_missing_testnet_anchor_before_publishing_a_wallet() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let mut request = create_request();
    request.block_one_fingerprint = None;
    assert_eq!(
        manager.create_wallet(request, 100),
        Err(AgentWalletError::InvalidNodeAnchor)
    );
    assert!(manager.list_wallets().unwrap().is_empty());
}

#[test]
fn mainnet_create_fails_before_registry_or_filesystem_mutation() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let registry_before = std::fs::read(manager.storage.registry_path()).unwrap();
    let mut entries_before: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries_before.sort();
    let request = CreateAgentWallet {
        passphrase: PASSPHRASE.into(),
        network_mode: "mainnet".into(),
        node_url: "http://nodeapi.hacash.org".into(),
        block_one_fingerprint: None,
    };
    assert_eq!(
        manager.create_wallet(request, 100),
        Err(AgentWalletError::InvalidPaymentRequest)
    );
    assert!(manager.list_wallets().unwrap().is_empty());
    assert_eq!(
        std::fs::read(manager.storage.registry_path()).unwrap(),
        registry_before
    );
    let mut entries_after: Vec<_> = std::fs::read_dir(root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    entries_after.sort();
    assert_eq!(entries_after, entries_before);
}

#[test]
fn authenticated_legacy_state_without_anchor_fails_closed() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let session = manager.session(&created.wallet_id).unwrap();
    let state_master = *session.state_master;
    let journal_key = *session.journal_key;
    let state = manager
        .load_verified_state(&created.wallet_id, &state_master, &journal_key)
        .unwrap();
    let mut legacy = serde_json::to_value(state).unwrap();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("block_one_fingerprint");
    manager
        .storage
        .write_encrypted(
            &created.wallet_id,
            STATE_NAME,
            STATE_SCHEMA_VERSION,
            &state_master,
            &legacy,
        )
        .unwrap();
    assert_eq!(
        manager.unlocked_status(&created.wallet_id, 102),
        Err(AgentWalletError::RecoveryRequired)
    );
}

#[tokio::test]
async fn overview_does_not_report_verified_when_balance_data_fails() {
    use axum::{Json, Router, routing::get};
    use serde_json::json;

    const ANCHOR: &str = "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";

    let app = Router::new()
        .route(
            "/query/block/intro",
            get(|| async {
                Json(json!({
                    "ret": 0,
                    "height": 1,
                    "hash": ANCHOR
                }))
            }),
        )
        .route(
            "/query/balance",
            get(|| async { Json(json!({ "ret": 1, "err": "balance unavailable" })) }),
        );
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    let app = app.route(
        "/query/capabilities",
        get(|| async {
            let instance_id = hacash_wallet_core::network_instance_id(
                hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
                hacash_wallet_core::HPAY_LOCAL_PILOT_CHAIN_ID,
                false,
                ANCHOR,
                hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
                2,
            );
            Json(json!({
                "ret": 0,
                "api_version": 1,
                "node": { "name": "hacash-fullnode", "version": "1.0.10", "build_time": "test" },
                "chain": { "id": 7, "height": 1, "next_height": 2, "mainnet": false },
                "network": {
                    "kind": hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
                    "node_profile_id": hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
                    "block_1_available": true,
                    "block_1_hash": ANCHOR,
                    "instance_id": instance_id,
                    "funding_confirmed": false,
                    "transaction_ready": false,
                    "current_height": 1,
                    "transaction_format_version": 2
                },
                "istanbul": { "activation_height": 1, "evaluation_height": 2, "active": true },
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
            }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let node_url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let mut request = create_request();
    request.node_url = node_url;
    let created = manager.create_wallet(request, 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let overview = manager.overview(&created.wallet_id, 102).await.unwrap();
    assert_eq!(overview.node_status, AgentNodeStatus::BalanceError);
    assert!(overview.confirmed_balance_units.is_none());
    assert!(overview.node_error.is_some());
    assert!(overview.stale);
    task.abort();
}

#[test]
fn wallet_is_created_only_by_explicit_call_and_has_unique_keys_and_paths() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    assert!(manager.list_wallets().unwrap().is_empty());
    let first = manager.create_wallet(create_request(), 100).unwrap();
    let second = manager.create_wallet(create_request(), 101).unwrap();
    assert_ne!(first.wallet_id, second.wallet_id);
    assert_ne!(first.address, second.address);
    assert_ne!(
        manager
            .storage
            .paths(&first.wallet_id)
            .unwrap()
            .vault_path(),
        manager
            .storage
            .paths(&second.wallet_id)
            .unwrap()
            .vault_path()
    );
    assert!(!manager.unlocked.contains_key(first.wallet_id.as_str()));
}

#[test]
fn unlocking_one_agent_wallet_does_not_unlock_another() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let first = manager.create_wallet(create_request(), 100).unwrap();
    let second = manager.create_wallet(create_request(), 101).unwrap();
    manager.unlock(&first.wallet_id, PASSPHRASE, 102).unwrap();
    assert!(manager.unlocked_status(&first.wallet_id, 103).is_ok());
    assert!(matches!(
        manager.unlocked_status(&second.wallet_id, 103),
        Err(AgentWalletError::AgentWalletLocked)
    ));
    assert!(matches!(
        manager.unlocked_status(&first.wallet_id, 1_002),
        Err(AgentWalletError::AgentWalletLocked)
    ));
    assert!(!manager.unlocked.contains_key(first.wallet_id.as_str()));
}

#[test]
fn emergency_stop_is_fail_closed_and_preserves_other_wallet() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let first = manager.create_wallet(create_request(), 100).unwrap();
    let second = manager.create_wallet(create_request(), 101).unwrap();
    manager.unlock(&first.wallet_id, PASSPHRASE, 102).unwrap();
    manager.unlock(&second.wallet_id, PASSPHRASE, 103).unwrap();
    manager
        .enable_agent_payments_locally(&first.wallet_id, 104)
        .unwrap();
    manager
        .disable_all_agent_payments(&first.wallet_id, 105)
        .unwrap();
    assert!(
        manager
            .unlocked_status(&first.wallet_id, 107)
            .unwrap()
            .payments_suspended
    );
    assert!(
        manager
            .unlocked_status(&second.wallet_id, 107)
            .unwrap()
            .payments_suspended
    );
    manager
        .enable_agent_payments_locally(&second.wallet_id, 106)
        .unwrap();
    assert!(
        !manager
            .unlocked_status(&second.wallet_id, 107)
            .unwrap()
            .payments_suspended
    );
    assert!(
        manager
            .unlocked_status(&first.wallet_id, 107)
            .unwrap()
            .payments_suspended
    );
}

#[test]
fn marker_only_crash_is_reconciled_before_signer_is_published() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    manager
        .enable_agent_payments_locally(&created.wallet_id, 102)
        .unwrap();
    let controller = manager.emergency_controller(&created.wallet_id).unwrap();
    assert!(!controller.status(false).stopped);

    // Simulate the supervisor durably stopping immediately before the
    // process dies, without ever acquiring the manager lock to update the
    // encrypted state.
    controller.request_stop().unwrap();
    drop(controller);
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    let status = restarted
        .unlock(&created.wallet_id, PASSPHRASE, 103)
        .unwrap();
    assert!(status.payments_suspended);
    assert!(
        restarted
            .emergency_controller(&created.wallet_id)
            .unwrap()
            .status(false)
            .stopped
    );
    let session = restarted.session(&created.wallet_id).unwrap();
    let state = restarted
        .load_verified_state(
            &created.wallet_id,
            &session.state_master,
            &session.journal_key,
        )
        .unwrap();
    assert!(state.payments_suspended);
}

#[test]
fn interrupted_journal_transition_recovers_from_the_durable_pending_slot() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let session = manager.session(&created.wallet_id).unwrap();
    let current = manager
        .load_verified_state(
            &created.wallet_id,
            &session.state_master,
            &session.journal_key,
        )
        .unwrap();
    let mut pending = current.clone();
    pending.emergency_epoch += 1;
    pending.payments_suspended = true;
    pending.updated_at = 102;
    manager
        .storage
        .write_encrypted(
            &created.wallet_id,
            PENDING_STATE_NAME,
            STATE_SCHEMA_VERSION,
            &session.state_master,
            &pending,
        )
        .unwrap();

    // A crash before the journal append leaves current authoritative.
    let before_append = manager
        .load_verified_state(
            &created.wallet_id,
            &session.state_master,
            &session.journal_key,
        )
        .unwrap();
    assert_eq!(before_append.emergency_epoch, current.emergency_epoch);

    let mut journal = AgentJournal::open(
        journal_path(&manager.storage.paths(&created.wallet_id).unwrap()),
        WalletScope::for_agent_wallet(&created.wallet_id),
        &session.journal_key,
    )
    .unwrap();
    let recovery = journal.verify().unwrap();
    journal
        .append(AgentJournalEvent {
            kind: AgentJournalEventKind::EmergencyStopEnabled,
            operation_commitment: None,
            actor_commitment: None,
            metadata_commitment: None,
            previous_state_commitment: recovery.head.state_commitment.unwrap(),
            new_state_commitment: state_commitment(&pending).unwrap(),
            occurred_at_unix_ms: 102_000,
        })
        .unwrap();

    // A crash after journal append but before current replacement promotes
    // only the exact pending state bound by the authenticated record.
    let recovered = manager
        .load_verified_state(
            &created.wallet_id,
            &session.state_master,
            &session.journal_key,
        )
        .unwrap();
    assert_eq!(recovered.emergency_epoch, pending.emergency_epoch);
    assert_eq!(
        state_commitment(&recovered).unwrap(),
        state_commitment(&pending).unwrap()
    );
}

#[test]
fn compaction_prunes_only_expired_terminal_pre_signing_outcomes() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let (mut state, _, _) = wallet_state(&manager, &created.wallet_id);
    let agent_id = AgentId::new();
    let mut prunable = Vec::new();
    for (index, status) in [
        OperationStatus::Cancelled,
        OperationStatus::Failed,
        OperationStatus::Rejected,
    ]
    .into_iter()
    .enumerate()
    {
        prunable.push(insert_indexed_operation(
            &mut state,
            &agent_id,
            &format!("prunable-{index}"),
            status,
            100,
            101,
        ));
    }
    let mut protected = Vec::new();
    for (index, status) in [
        OperationStatus::Approved,
        OperationStatus::Signed,
        OperationStatus::BroadcastSubmitted,
        OperationStatus::BroadcastUncertain,
        OperationStatus::Committed,
        OperationStatus::RecoveryRequired,
    ]
    .into_iter()
    .enumerate()
    {
        protected.push(insert_indexed_operation(
            &mut state,
            &agent_id,
            &format!("protected-{index}"),
            status,
            100,
            101,
        ));
    }

    assert_eq!(
        prune_aged_terminal_pre_signing_operations(&mut state, 160),
        0
    );
    assert_eq!(
        prune_aged_terminal_pre_signing_operations(&mut state, 161),
        3
    );
    for (operation_id, scoped_key) in prunable {
        assert!(!state.operations.contains_key(operation_id.as_str()));
        assert!(!state.idempotency.contains_key(&scoped_key));
    }
    for (operation_id, scoped_key) in protected {
        assert!(state.operations.contains_key(operation_id.as_str()));
        assert!(state.idempotency.contains_key(&scoped_key));
    }
    assert_eq!(
        prune_terminal_pre_signing_for_agent(&mut state, &agent_id),
        0
    );
}

#[test]
fn near_expiry_compaction_cannot_bypass_the_rolling_rate_limit() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let (mut state, _, _) = wallet_state(&manager, &created.wallet_id);
    let agent_id = AgentId::new();
    for index in 0..MAX_REQUESTS_PER_AGENT_PER_MINUTE {
        insert_indexed_operation(
            &mut state,
            &agent_id,
            &format!("near-expiry-{index}"),
            OperationStatus::Cancelled,
            100,
            101,
        );
    }

    assert_eq!(
        prune_aged_terminal_pre_signing_operations(&mut state, 102),
        0
    );
    assert_eq!(
        ensure_agent_request_rate(&state, &agent_id, 102),
        Err(AgentWalletError::RateLimited)
    );
    assert_eq!(
        prune_aged_terminal_pre_signing_operations(&mut state, 161),
        30
    );
    assert!(ensure_agent_request_rate(&state, &agent_id, 161).is_ok());
    assert!(ensure_operation_capacity(&state).is_ok());
}

#[test]
fn expired_terminal_rows_recover_the_full_operation_capacity() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let (mut state, _, _) = wallet_state(&manager, &created.wallet_id);
    let agent_id = AgentId::new();
    for index in 0..MAX_OPERATIONS_PER_WALLET {
        insert_indexed_operation(
            &mut state,
            &agent_id,
            &format!("capacity-{index}"),
            OperationStatus::Cancelled,
            100,
            200,
        );
    }
    assert_eq!(
        ensure_operation_capacity(&state),
        Err(AgentWalletError::RateLimited)
    );
    assert_eq!(
        prune_aged_terminal_pre_signing_operations(&mut state, 261),
        MAX_OPERATIONS_PER_WALLET
    );
    assert!(state.operations.is_empty());
    assert!(state.idempotency.is_empty());
    assert!(ensure_operation_capacity(&state).is_ok());
}
#[test]
fn durable_compaction_and_idempotency_removal_survive_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let (mut state, state_master, journal_key) = wallet_state(&manager, &created.wallet_id);
    let (operation_id, scoped_key) = insert_indexed_operation(
        &mut state,
        &AgentId::new(),
        "durable-compaction",
        OperationStatus::Cancelled,
        100,
        101,
    );
    state.updated_at = 150;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            150,
        )
        .unwrap();
    let before_sequence = state.journal_sequence;
    assert_eq!(
        manager
            .compact_aged_terminal_pre_signing_operations(
                &mut state,
                &state_master,
                &journal_key,
                161,
            )
            .unwrap(),
        1
    );
    assert_eq!(state.journal_sequence, before_sequence + 1);
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted
        .unlock(&created.wallet_id, PASSPHRASE, 162)
        .unwrap();
    let (recovered, _, _) = wallet_state(&restarted, &created.wallet_id);
    assert!(!recovered.operations.contains_key(operation_id.as_str()));
    assert!(!recovered.idempotency.contains_key(&scoped_key));
}

#[test]
fn compaction_persistence_failure_preserves_operation_and_idempotency() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let (mut state, state_master, journal_key) = wallet_state(&manager, &created.wallet_id);
    let (operation_id, scoped_key) = insert_indexed_operation(
        &mut state,
        &AgentId::new(),
        "failed-compaction",
        OperationStatus::Cancelled,
        100,
        101,
    );
    state.updated_at = 150;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            150,
        )
        .unwrap();
    let before_sequence = state.journal_sequence;
    let pending_path = manager
        .storage
        .paths(&created.wallet_id)
        .unwrap()
        .encrypted_state_path(PENDING_STATE_NAME)
        .unwrap();
    if pending_path.exists() {
        std::fs::remove_file(&pending_path).unwrap();
    }
    std::fs::create_dir(&pending_path).unwrap();
    assert!(
        manager
            .compact_aged_terminal_pre_signing_operations(
                &mut state,
                &state_master,
                &journal_key,
                161,
            )
            .is_err()
    );
    std::fs::remove_dir(&pending_path).unwrap();

    let recovered = manager
        .load_verified_state(&created.wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(recovered.journal_sequence, before_sequence);
    assert!(recovered.operations.contains_key(operation_id.as_str()));
    assert!(recovered.idempotency.contains_key(&scoped_key));
}
#[test]
fn interrupted_compaction_recovers_exact_pending_state_after_restart() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let (mut current, state_master, journal_key) = wallet_state(&manager, &created.wallet_id);
    let (operation_id, scoped_key) = insert_indexed_operation(
        &mut current,
        &AgentId::new(),
        "crash-compaction",
        OperationStatus::Cancelled,
        100,
        101,
    );
    current.updated_at = 150;
    manager
        .persist_event(
            &mut current,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            150,
        )
        .unwrap();

    let mut pending = current.clone();
    assert_eq!(
        prune_aged_terminal_pre_signing_operations(&mut pending, 161),
        1
    );
    pending.updated_at = 161;
    manager
        .storage
        .write_encrypted(
            &created.wallet_id,
            PENDING_STATE_NAME,
            STATE_SCHEMA_VERSION,
            &state_master,
            &pending,
        )
        .unwrap();
    let mut journal = AgentJournal::open(
        journal_path(&manager.storage.paths(&created.wallet_id).unwrap()),
        WalletScope::for_agent_wallet(&created.wallet_id),
        &journal_key,
    )
    .unwrap();
    let recovery = journal.verify().unwrap();
    journal
        .append(AgentJournalEvent {
            kind: AgentJournalEventKind::OperationsCompacted,
            operation_commitment: None,
            actor_commitment: None,
            metadata_commitment: None,
            previous_state_commitment: recovery.head.state_commitment.unwrap(),
            new_state_commitment: state_commitment(&pending).unwrap(),
            occurred_at_unix_ms: 161_000,
        })
        .unwrap();
    drop(manager);

    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted
        .unlock(&created.wallet_id, PASSPHRASE, 162)
        .unwrap();
    let (recovered, _, _) = wallet_state(&restarted, &created.wallet_id);
    assert!(!recovered.operations.contains_key(operation_id.as_str()));
    assert!(!recovered.idempotency.contains_key(&scoped_key));
}
#[test]
fn daily_policy_counts_total_debit_of_pending_reservations() {
    let wallet_id = AgentWalletId::new();
    let agent_id = AgentId::new();
    let mut policy = AgentPolicy {
        max_per_payment_units: HacUnits::new(10_000_000),
        max_daily_units: HacUnits::new(10_000_000),
        max_pending_operations: 3,
        ..AgentPolicy::default()
    };
    policy
        .permissions
        .insert(AgentPermission::CreatePaymentIntent);
    policy
        .allowed_recipients
        .insert("1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS".into());
    let agent = AgentRecord {
        agent_id: agent_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
        name: "test-agent".into(),
        version: "1".into(),
        identity_public_key_sec1: "02".repeat(33),
        identity_fingerprint: "ABCD-ABCD-ABCD-ABCD-ABCD".into(),
        identity_key_sha256: "ab".repeat(32),
        server_identity: hpay_agent_connector::ServerIdentityKey::generate()
            .pinned_identity("desktop_11111111111111111111111111111111".into())
            .unwrap(),
        status: AgentStatus::Active,
        authorization_epoch: 1,
        policy,
        paired_at: 1_000,
    };
    let mut existing = AgentOperation::new(
        OperationId::new(),
        agent_id.clone(),
        wallet_id.clone(),
        AgentPaymentRequest {
            idempotency_key: "existing".into(),
            asset: "HAC".into(),
            amount_units: HacUnits::new(6_000_000),
            recipient: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS".into(),
            reason: "existing".into(),
            expires_at: 2_000,
        },
        1_000,
    )
    .unwrap();
    existing.reserve(HacUnits::MIN_NETWORK_FEE).unwrap();
    let state = AgentWalletState {
        schema_version: STATE_SCHEMA_VERSION,
        wallet_id: wallet_id.clone(),
        address: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS".into(),
        network_mode: "testnet".into(),
        node_url: "http://127.0.0.1:18081".into(),
        block_one_fingerprint: "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff"
            .into(),
        primary_signing_device_id: "desktop_11111111111111111111111111111111".into(),
        signer_epoch: 1,
        policy_epoch: 1,
        emergency_epoch: 1,
        payments_suspended: false,
        external_rollback_anchor_ready: false,
        agents: BTreeMap::new(),
        pairing_completion_outbox: BTreeMap::new(),
        companion_security: None,
        rollback_witness: None,
        witness_rotation: None,
        witness_rotation_history: Vec::new(),
        operations: BTreeMap::from([(existing.operation_id().as_str().to_owned(), existing)]),
        idempotency: BTreeMap::new(),
        authentication_challenges: BTreeMap::new(),
        authenticated_sessions: BTreeMap::new(),
        journal_sequence: 0,
        journal_head_hash: ZERO_HASH_HEX.into(),
        updated_at: 1_000,
    };
    let new_request = AgentPaymentRequest {
        idempotency_key: "new".into(),
        asset: "HAC".into(),
        amount_units: HacUnits::new(4_000_000),
        recipient: "1AVRuFXNFi3rdMrPH4hdqSgFrEBnWisWaS".into(),
        reason: "new".into(),
        expires_at: 2_000,
    };
    let new_total = HacUnits::new(4_001_000);
    assert_eq!(
        validate_policy_for_request(&state, &agent, &new_request, new_total, 1_001),
        Err(AgentWalletError::DailyLimitExceeded)
    );
}

#[test]
fn empty_completion_outbox_preserves_the_exact_legacy_state_commitment() {
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager.create_wallet(create_request(), 100).unwrap();
    manager.unlock(&created.wallet_id, PASSPHRASE, 101).unwrap();
    let session = manager.session(&created.wallet_id).unwrap();
    let state = manager
        .load_verified_state(
            &created.wallet_id,
            &session.state_master,
            &session.journal_key,
        )
        .unwrap();
    assert!(state.pairing_completion_outbox.is_empty());
    assert!(state.companion_security.is_none());
    let expected = state_commitment(&state).unwrap();
    let legacy_bytes = serde_json::to_vec(&state).unwrap();
    assert!(
        !String::from_utf8_lossy(&legacy_bytes).contains("pairing_completion_outbox"),
        "an empty new field must be omitted from legacy state bytes"
    );
    assert!(
        !String::from_utf8_lossy(&legacy_bytes).contains("companion_security"),
        "unused companion state must not change legacy authenticated bytes"
    );
    let legacy_roundtrip: AgentWalletState = serde_json::from_slice(&legacy_bytes).unwrap();
    assert_eq!(state_commitment(&legacy_roundtrip).unwrap(), expected);
}

#[test]
fn approval_challenge_nonce_is_exactly_sixteen_lowercase_hex_bytes() {
    for _ in 0..32 {
        let nonce = random_challenge_nonce();
        assert_eq!(nonce.len(), 32);
        assert!(
            nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }
}

#[test]
fn personal_like_files_outside_agent_root_are_never_touched() {
    let parent = tempfile::tempdir().unwrap();
    let personal_vault = parent.path().join("vault.json");
    let personal_settings = parent.path().join("settings.json");
    std::fs::write(&personal_vault, b"personal-vault-sentinel").unwrap();
    std::fs::write(&personal_settings, b"personal-settings-sentinel").unwrap();
    let root = parent.path().join("agent-wallets");
    let mut manager = AgentWalletManager::open(&root).unwrap();
    manager.create_wallet(create_request(), 100).unwrap();
    assert_eq!(
        std::fs::read(&personal_vault).unwrap(),
        b"personal-vault-sentinel"
    );
    assert_eq!(
        std::fs::read(&personal_settings).unwrap(),
        b"personal-settings-sentinel"
    );
}
