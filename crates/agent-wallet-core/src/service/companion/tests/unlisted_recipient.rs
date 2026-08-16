//! A recipient the owner has never vetted may be PROPOSED, never auto-paid.
//!
//! Every test here drives the real durable manager over real encrypted state.
//! The default-off proof deliberately re-reads state that was written before
//! the flag existed, because a fresh `AgentPolicy::default()` fixture would
//! prove nothing about wallets that already exist on disk.

use axum::{
    Json, Router,
    routing::{get, post},
};
use hpay_agent_connector::PairingSubmissionCommitment;
use hpay_companion_protocol::CompanionPayload;
use serde_json::json;

use super::fixtures::*;
use super::*;
use crate::service::{AgentAuthorization, validate_policy_for_request};

/// A recipient that is valid for testnet and is on no list in any test here.
const UNLISTED_RECIPIENT: &str = "1MzNY1oA3kfgYi75zquj3SRUPYztzXHzK9";

struct MockNode {
    url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for MockNode {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// A node that verifies and answers a balance query, and then refuses to build
/// a transaction. That is exactly far enough: `create_payment_intent` reaches
/// the node only after `validate_policy_for_request` has admitted the payment,
/// so the error identity distinguishes "refused by policy" from "admitted by
/// policy" without this test needing to construct real consensus bytes.
async fn spawn_node() -> MockNode {
    let app = Router::new()
        .route(
            "/query/block/intro",
            get(|| async { Json(json!({ "ret": 0, "height": 1, "hash": TESTNET_ANCHOR })) }),
        )
        .route(
            // One entry with no address is the older-node shape the client
            // accepts for a single-address query, so this funds whichever
            // wallet the test creates.
            "/query/balance",
            get(|| async { Json(json!({ "ret": 0, "list": [{ "hacash": "1000" }] })) }),
        )
        .route(
            "/create/transaction",
            post(|| async { Json(json!({ "ret": 1, "err": "tx build refused by test node" })) }),
        );
    #[cfg(feature = "agent-wallet-testnet-pilot")]
    let app = app.route(
        "/query/capabilities",
        get(|| async {
            let instance_id = hacash_wallet_core::network_instance_id(
                hacash_wallet_core::HPAY_LOCAL_PILOT_NETWORK_KIND,
                hacash_wallet_core::HPAY_LOCAL_PILOT_CHAIN_ID,
                false,
                TESTNET_ANCHOR,
                hacash_wallet_core::HPAY_LOCAL_PILOT_PROFILE_ID,
                2,
            );
            Json(json!({
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
                "actions": { "registered": [1, 2, 3, 14, 1041], "enabled": [1, 2, 3, 14, 1041] },
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
                    "transaction_submit_bound": true,
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
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    MockNode { url, task }
}

fn manager_for_node(
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
                mainnet_pilot_acknowledgement: None,
            },
            now,
        )
        .unwrap();
    manager
        .unlock(&created.wallet_id, PASSPHRASE, now + 1)
        .unwrap();
    (root, manager, created.wallet_id)
}

/// Pairs one agent through the production pairing writer. The policy this
/// leaves on disk contains no `allow_unlisted_recipient_with_approval` key at
/// all, which is precisely the shape every wallet paired before this feature
/// existed has.
fn pair_agent(manager: &mut AgentWalletManager, wallet_id: &AgentWalletId, now: u64) -> AgentId {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let identity = AgentIdentityKey::generate();
    let server_identity = ServerIdentityKey::generate()
        .pinned_identity(state.primary_signing_device_id.clone())
        .unwrap();
    let agent_id = AgentId::new();
    let permissions = BTreeSet::from([AgentPermission::CreatePaymentIntent]);
    let paired = PairedAgent {
        agent_id: agent_id.clone(),
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(wallet_id),
        name: "Unlisted recipient agent".to_owned(),
        version: "1.0.0".to_owned(),
        identity_public_key_sec1_hex: identity.public_key_sec1_hex(),
        identity_fingerprint: identity.fingerprint(),
        capabilities: permissions.clone(),
        status: PairedAgentStatus::Active,
        paired_at_unix: now,
        authorization_epoch: 1,
        server_identity,
    };
    let policy = AgentPolicy {
        permissions,
        max_per_payment_units: HacUnits::new(1_000_000),
        max_daily_units: HacUnits::new(10_000_000),
        max_pending_operations: 4,
        allowed_recipients: BTreeSet::new(),
        blocked_recipients: BTreeSet::new(),
        allow_unlisted_recipient_with_approval: false,
        approval_mode: ApprovalMode::DesktopManual,
        policy_epoch: state.policy_epoch,
    };
    manager
        .commit_paired_agent(
            paired,
            policy,
            &format!("pair_{}", "34".repeat(32)),
            PairingSubmissionCommitment::parse("cd".repeat(32)).unwrap(),
            now + 100,
            now,
        )
        .unwrap();
    agent_id
}

fn stored_policy(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    agent_id: &AgentId,
) -> AgentPolicy {
    let (state_master, journal_key) = keys(manager, wallet_id);
    manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
        .agents
        .get(agent_id.as_str())
        .unwrap()
        .policy
        .clone()
}

/// Rebuilt after every setup step, because enabling payments and editing a
/// policy both bump the epochs this authorization is checked against.
fn authorization(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    agent_id: &AgentId,
) -> AgentAuthorization {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let agent = state.agents.get(agent_id.as_str()).unwrap();
    AgentAuthorization {
        wallet_id: wallet_id.clone(),
        wallet_scope: agent.wallet_scope.clone(),
        agent_id: agent_id.clone(),
        authorization_epoch: agent.authorization_epoch,
        identity_key_sha256: agent.identity_key_sha256.clone(),
        capability: AgentPermission::CreatePaymentIntent,
    }
}

fn unlisted_request(idempotency_key: &str, expires_at: u64) -> AgentPaymentRequest {
    AgentPaymentRequest {
        idempotency_key: idempotency_key.to_owned(),
        asset: "HAC".to_owned(),
        amount_units: HacUnits::new(50_000),
        recipient: UNLISTED_RECIPIENT.to_owned(),
        reason: "pay the developer the agent just found".to_owned(),
        expires_at,
    }
}

fn set_allow_unlisted(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    agent_id: &AgentId,
    allow: bool,
    now: u64,
) {
    let mut policy = stored_policy(manager, wallet_id, agent_id);
    policy.allow_unlisted_recipient_with_approval = allow;
    manager
        .update_agent_policy_admin(wallet_id, agent_id, policy, now)
        .unwrap();
}

/// Default off, proven over state that was written to disk without the field.
///
/// This also pins the serialization: the flag must be omitted when false, or
/// every already-stored wallet would recompute a different state commitment
/// than the one in its authenticated journal head and fail to load at all.
#[tokio::test]
async fn stored_policy_written_without_the_flag_still_refuses_an_unlisted_recipient() {
    let node = spawn_node().await;
    let (root, mut manager, wallet_id) = manager_for_node(&node.url, 100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let agent_id = pair_agent(&mut manager, &wallet_id, 103);

    let policy = stored_policy(&manager, &wallet_id, &agent_id);
    let policy_bytes = serde_json::to_vec(&policy).unwrap();
    assert!(
        !String::from_utf8_lossy(&policy_bytes).contains("allow_unlisted_recipient_with_approval"),
        "a default-off flag must not appear in stored policy bytes"
    );
    assert!(!policy.allow_unlisted_recipient_with_approval);

    // Close and reopen the vault so the assertion below is made against state
    // read back from disk, not against anything still held in memory.
    drop(manager);
    let mut restarted = AgentWalletManager::open(root.path()).unwrap();
    restarted.unlock(&wallet_id, PASSPHRASE, 104).unwrap();
    assert!(
        !stored_policy(&restarted, &wallet_id, &agent_id).allow_unlisted_recipient_with_approval
    );

    let authorization = authorization(&restarted, &wallet_id, &agent_id);
    assert_eq!(
        restarted
            .create_payment_intent(&authorization, unlisted_request("default-off", 500), 105)
            .await,
        Err(AgentWalletError::RecipientNotAllowed)
    );

    let (state_master, journal_key) = keys(&restarted, &wallet_id);
    let state = restarted
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(
        state.operations.is_empty(),
        "a refused payment must leave no operation behind"
    );
}

/// A policy JSON that predates the field decodes, and decodes to false.
#[test]
fn legacy_policy_json_without_the_field_decodes_to_off() {
    let legacy = r#"{
        "permissions": ["create_payment_intent"],
        "max_per_payment_units": "1000000",
        "max_daily_units": "10000000",
        "max_pending_operations": 4,
        "allowed_recipients": [],
        "blocked_recipients": [],
        "approval_mode": "desktop_manual",
        "policy_epoch": 2
    }"#;
    let policy: AgentPolicy = serde_json::from_str(legacy).unwrap();
    assert!(!policy.allow_unlisted_recipient_with_approval);
    assert_eq!(
        serde_json::to_string(&policy).unwrap(),
        serde_json::to_string(&serde_json::from_str::<AgentPolicy>(legacy).unwrap()).unwrap()
    );
    assert!(
        !serde_json::to_string(&policy)
            .unwrap()
            .contains("allow_unlisted_recipient_with_approval")
    );
}

/// Turned on, the same request is admitted past the recipient gate. It reaches
/// the node stage, which is downstream of every policy decision, and it is
/// still on its way to the approval ceremony rather than to a signature.
#[tokio::test]
async fn the_owner_flag_admits_an_unlisted_recipient_only_as_a_proposal() {
    let node = spawn_node().await;
    let (_root, mut manager, wallet_id) = manager_for_node(&node.url, 100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let agent_id = pair_agent(&mut manager, &wallet_id, 103);

    let refused = manager
        .create_payment_intent(
            &authorization(&manager, &wallet_id, &agent_id),
            unlisted_request("before-flag", 500),
            104,
        )
        .await;
    assert_eq!(refused, Err(AgentWalletError::RecipientNotAllowed));

    set_allow_unlisted(&mut manager, &wallet_id, &agent_id, true, 105);
    assert!(stored_policy(&manager, &wallet_id, &agent_id).allow_unlisted_recipient_with_approval);

    // Admitted by policy, and only by policy: the intent now runs on to the
    // node, which is the first step after every limit has been applied.
    let admitted = manager
        .create_payment_intent(
            &authorization(&manager, &wallet_id, &agent_id),
            unlisted_request("after-flag", 500),
            106,
        )
        .await;
    assert_eq!(admitted, Err(AgentWalletError::NodeRejected));

    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let operation = state
        .operations
        .values()
        .find(|operation| operation.view().recipient == UNLISTED_RECIPIENT)
        .expect("the admitted proposal must be journalled")
        .view();
    assert_eq!(operation.status, OperationStatus::Failed);
    assert_eq!(
        operation.final_result.as_deref(),
        Some("transaction_build_failed")
    );
    // Nothing signed, nothing broadcast, no transaction hash.
    assert!(operation.tx_hash.is_none());
}

/// The proposal stops at the approval ceremony, and the ceremony is bound to
/// the exact recipient, amount, network fee and total debit. This is the same
/// `ApprovalCommitment` machinery an allowlisted payment uses; there is no
/// second approval path for unlisted recipients.
#[tokio::test]
async fn an_unlisted_proposal_waits_in_the_approval_ceremony_bound_to_the_exact_payment() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let agent_id = pair_agent(&mut manager, &wallet_id, 103);
    set_allow_unlisted(&mut manager, &wallet_id, &agent_id, true, 104);
    let (approval, operation_id) =
        pending_unlisted_approval(&mut manager, &wallet_id, &agent_id, 105);

    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let view = state
        .operations
        .get(operation_id.as_str())
        .unwrap()
        .view()
        .clone();
    assert_eq!(view.status, OperationStatus::ApprovalRequested);
    assert!(view.tx_hash.is_none());

    // What the owner is shown, taken from the durable operation, is the exact
    // payment and nothing the agent can restate.
    let shown = manager
        .pending_approval(&wallet_id, &operation_id, 106)
        .unwrap();
    assert_eq!(shown, approval);
    assert_eq!(shown.recipient, UNLISTED_RECIPIENT);
    assert_eq!(shown.amount_units, view.amount_units.get());
    assert_eq!(shown.fee_units, HacUnits::MIN_NETWORK_FEE.get());
    assert_eq!(shown.wallet_fee_units, 0);
    assert_eq!(shown.total_debit_units, view.total_debit_units.get());
    assert_eq!(
        shown.total_debit_units,
        view.amount_units
            .checked_add(HacUnits::MIN_NETWORK_FEE)
            .unwrap()
            .get()
    );

    // Any restatement of the recipient breaks the binding, so an approval can
    // never be redirected to a different address.
    let mut redirected = approval.clone();
    redirected.recipient = RECIPIENT.to_owned();
    let mut probe = state.operations.get(operation_id.as_str()).unwrap().clone();
    assert!(
        probe
            .record_approval(
                redirected,
                ApprovalMode::DesktopManual,
                state.policy_epoch,
                107,
            )
            .is_err()
    );
    assert_eq!(probe.status(), OperationStatus::ApprovalRequested);
}

/// The blocklist is absolute. Neither the flag nor a real approval commitment
/// bound to the exact payment can admit a blocked recipient.
#[tokio::test]
async fn a_blocked_recipient_is_refused_with_the_flag_on() {
    let node = spawn_node().await;
    let (_root, mut manager, wallet_id) = manager_for_node(&node.url, 100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let agent_id = pair_agent(&mut manager, &wallet_id, 103);

    let mut policy = stored_policy(&manager, &wallet_id, &agent_id);
    policy.allow_unlisted_recipient_with_approval = true;
    policy
        .blocked_recipients
        .insert(UNLISTED_RECIPIENT.to_owned());
    manager
        .update_agent_policy_admin(&wallet_id, &agent_id, policy, 104)
        .unwrap();

    assert_eq!(
        manager
            .create_payment_intent(
                &authorization(&manager, &wallet_id, &agent_id),
                unlisted_request("blocked", 500),
                105,
            )
            .await,
        Err(AgentWalletError::RecipientNotAllowed)
    );

    // And a blocked address that is somehow also allowlisted stays blocked.
    // `validate_policy` refuses to persist that overlap, so it is asserted
    // here directly against the single enforcement site.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let mut agent = state.agents.get(agent_id.as_str()).unwrap().clone();
    agent
        .policy
        .allowed_recipients
        .insert(UNLISTED_RECIPIENT.to_owned());
    let request = unlisted_request("blocked-and-allowed", 500);
    let total = request
        .amount_units
        .checked_add(HacUnits::MIN_NETWORK_FEE)
        .unwrap();
    assert_eq!(
        validate_policy_for_request(&state, &agent, &request, total, 105),
        Err(AgentWalletError::RecipientNotAllowed)
    );
}

/// One payment is one payment. Proposing, journalling and approving a payment
/// to an unlisted recipient never writes that recipient into the allowlist.
#[tokio::test]
async fn paying_an_unlisted_recipient_never_adds_it_to_the_allowlist() {
    let node = spawn_node().await;
    let (_root, mut manager, wallet_id) = manager_for_node(&node.url, 100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let agent_id = pair_agent(&mut manager, &wallet_id, 103);
    set_allow_unlisted(&mut manager, &wallet_id, &agent_id, true, 104);
    let epoch_before = stored_policy(&manager, &wallet_id, &agent_id).policy_epoch;

    // Proposal.
    let _ = manager
        .create_payment_intent(
            &authorization(&manager, &wallet_id, &agent_id),
            unlisted_request("no-allowlisting", 500),
            105,
        )
        .await;
    assert!(
        stored_policy(&manager, &wallet_id, &agent_id)
            .allowed_recipients
            .is_empty(),
        "proposing a payment must not grant the recipient standing permission"
    );

    // Approval ceremony, run to whatever this build allows, over an operation
    // whose commitment is bound to the exact unlisted recipient.
    let (approval, operation_id) =
        pending_unlisted_approval(&mut manager, &wallet_id, &agent_id, 106);
    assert_eq!(approval.recipient, UNLISTED_RECIPIENT);
    let _ = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, 107)
        .await;

    let policy = stored_policy(&manager, &wallet_id, &agent_id);
    assert!(
        policy.allowed_recipients.is_empty(),
        "an approved payment must not grant the recipient standing permission"
    );
    assert!(policy.blocked_recipients.is_empty());
    assert_eq!(policy.policy_epoch, epoch_before);
    assert!(policy.allow_unlisted_recipient_with_approval);

    // The next payment to the same recipient is a fresh proposal that needs
    // its own approval; it is not admitted by the allowlist.
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(!state.operations.is_empty());
    assert!(state.operations.contains_key(operation_id.as_str()));
}

/// The recipient gate is one clause among five in one function. Relaxing it
/// must not relax the other four for the payments it admits.
#[tokio::test]
async fn every_existing_limit_still_applies_to_an_unlisted_recipient() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let agent_id = pair_agent(&mut manager, &wallet_id, 103);
    set_allow_unlisted(&mut manager, &wallet_id, &agent_id, true, 104);

    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let agent = state.agents.get(agent_id.as_str()).unwrap().clone();
    let request = unlisted_request("limits", 500);
    let total = request
        .amount_units
        .checked_add(HacUnits::MIN_NETWORK_FEE)
        .unwrap();
    assert!(validate_policy_for_request(&state, &agent, &request, total, 105).is_ok());

    let mut capped = agent.clone();
    capped.policy.max_per_payment_units = total.checked_sub(HacUnits::new(1)).unwrap();
    assert_eq!(
        validate_policy_for_request(&state, &capped, &request, total, 105),
        Err(AgentWalletError::PaymentLimitExceeded)
    );

    let mut no_pending = agent.clone();
    no_pending.policy.max_pending_operations = 0;
    assert_eq!(
        validate_policy_for_request(&state, &no_pending, &request, total, 105),
        Err(AgentWalletError::TooManyPendingOperations)
    );

    let mut daily = agent.clone();
    daily.policy.max_daily_units = total.checked_sub(HacUnits::new(1)).unwrap();
    assert_eq!(
        validate_policy_for_request(&state, &daily, &request, total, 105),
        Err(AgentWalletError::DailyLimitExceeded)
    );

    // The rolling window counts reservations, not just committed spend, so an
    // in-flight proposal to an unlisted recipient consumes the same budget.
    let (approval, _) = pending_unlisted_approval(&mut manager, &wallet_id, &agent_id, 106);
    assert_eq!(approval.recipient, UNLISTED_RECIPIENT);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let mut window = state.agents.get(agent_id.as_str()).unwrap().clone();
    window.policy.max_daily_units = total.checked_add(HacUnits::new(1)).unwrap();
    assert_eq!(
        validate_policy_for_request(&state, &window, &request, total, 107),
        Err(AgentWalletError::DailyLimitExceeded)
    );
}

/// Emergency stop fails closed for a proposal to an unlisted recipient, at the
/// same point and with the same error as for an allowlisted one.
#[tokio::test]
async fn emergency_stop_refuses_an_unlisted_recipient_payment() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let agent_id = pair_agent(&mut manager, &wallet_id, 103);
    set_allow_unlisted(&mut manager, &wallet_id, &agent_id, true, 104);
    let authorization = authorization(&manager, &wallet_id, &agent_id);

    manager
        .emergency_controller(&wallet_id)
        .unwrap()
        .request_stop()
        .unwrap();

    assert_eq!(
        manager
            .create_payment_intent(&authorization, unlisted_request("stopped", 500), 105)
            .await,
        Err(AgentWalletError::AgentPaymentsSuspended)
    );
    let (state_master, journal_key) = keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    assert!(state.operations.is_empty());
}

/// No agent, phone or remote protocol can set the flag.
///
/// The flag is never encoded into any wire message, so there is nothing for a
/// remote peer to send back, and the only mobile-originated administrative
/// command the desktop accepts at all is the emergency stop.
#[tokio::test]
async fn no_agent_phone_or_remote_protocol_can_set_the_flag() {
    let (_root, mut manager, wallet_id) = create_manager(100);
    manager
        .enable_agent_payments_locally(&wallet_id, 102)
        .unwrap();
    let agent_id = pair_agent(&mut manager, &wallet_id, 103);
    set_allow_unlisted(&mut manager, &wallet_id, &agent_id, true, 104);

    // The companion snapshot is the entire read surface the phone has, and it
    // carries no representation of the flag in either direction.
    let payload = manager
        .companion_status_snapshot(&wallet_id, 105)
        .await
        .unwrap();
    let encoded = serde_json::to_string(&payload).unwrap();
    assert!(!encoded.contains("allow_unlisted_recipient_with_approval"));
    assert!(!encoded.contains("allow_unlisted"));
    let CompanionPayload::StatusSnapshot { policies, .. } = &payload else {
        panic!("expected status snapshot");
    };
    let summary = serde_json::to_string(&policies).unwrap();
    assert!(!summary.contains("allow_unlisted"));

    // The agent-facing policy summary that crosses the connector wire likewise
    // carries only capabilities, never this flag.
    let policy = stored_policy(&manager, &wallet_id, &agent_id);
    assert!(policy.allow_unlisted_recipient_with_approval);
    let permissions = serde_json::to_string(&policy.permissions).unwrap();
    assert!(!permissions.contains("allow_unlisted"));

    // A mobile-signed administrative command cannot carry a policy at all, and
    // any kind other than the emergency stop is refused outright.
    // Registered with more device permission than the product grants, so the
    // signature and permission checks pass and the refusal below is the
    // command-kind gate itself rather than a missing permission.
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mut permissions = mobile_permissions();
    permissions.insert(DevicePermission::RevokeAgent);
    let device = manager
        .register_verified_companion_device(
            &wallet_id,
            mobile
                .public_record(wallet_id.as_str(), permissions, 106)
                .unwrap(),
            106,
        )
        .unwrap();
    let mut command = admin_command(
        &manager,
        &wallet_id,
        &mobile,
        device.authorization_epoch,
        1,
        107,
    );
    // Exhaustive on purpose. If a mobile command that could carry a policy is
    // ever added, this stops compiling instead of silently opening a path.
    match &command.command_type {
        AdminCommandKind::SuspendAgentPayments
        | AdminCommandKind::RevokeAgent { .. }
        | AdminCommandKind::RevokeMobileDevice { .. } => {}
    }
    command.command_type = AdminCommandKind::RevokeAgent {
        agent_id: agent_id.to_string(),
    };
    let signed = SignedAdminCommand::sign(command, &mobile).await.unwrap();
    assert_eq!(
        manager
            .apply_mobile_admin_command(&wallet_id, signed, 108)
            .err(),
        Some(AgentWalletError::AgentPermissionDenied)
    );
    assert!(
        stored_policy(&manager, &wallet_id, &agent_id).allow_unlisted_recipient_with_approval,
        "a refused mobile command must not have changed the policy"
    );
}

/// Builds a durable `ApprovalRequested` operation for the unlisted recipient,
/// bound by a commitment over the exact recipient, amount, fee and total.
/// Mirrors `fixtures::prepare_pending`, but reuses the agent this module
/// paired so the operation belongs to a policy with the flag on.
fn pending_unlisted_approval(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    agent_id: &AgentId,
    now: u64,
) -> (ApprovalCommitment, OperationId) {
    let (state_master, journal_key) = keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let operation_id = OperationId::new();
    let mut operation = AgentOperation::new(
        operation_id.clone(),
        agent_id.clone(),
        wallet_id.clone(),
        unlisted_request(&format!("ceremony-{}", operation_id.as_str()), now + 300),
        now,
    )
    .unwrap();
    operation.reserve(HacUnits::MIN_NETWORK_FEE).unwrap();
    operation
        .persist_unsigned_transaction("00".to_owned())
        .unwrap();
    let view = operation.view();
    let approval = ApprovalCommitment {
        // Version 2 with no network binding, exactly as `prepare_pending`
        // builds it. These tests never resume a payment, which is the only
        // step that requires the pilot's version 3 binding.
        approval_version: 2,
        approval_id: format!("approval_{}", operation_id.as_str()),
        operation_id: operation_id.to_string(),
        agent_wallet_id: wallet_id.to_string(),
        agent_id: agent_id.to_string(),
        desktop_device_id: DeviceId::parse(state.primary_signing_device_id.clone()).unwrap(),
        transaction_commitment: view.transaction_commitment.unwrap(),
        amount_units: view.amount_units.get(),
        fee_units: HacUnits::MIN_NETWORK_FEE.get(),
        wallet_fee_units: 0,
        total_debit_units: view.total_debit_units.get(),
        recipient: view.recipient,
        policy_epoch: state.policy_epoch,
        challenge_nonce: operation_id
            .as_str()
            .strip_prefix("op_")
            .unwrap()
            .to_owned(),
        issued_at: now,
        expires_at: now + 300,
        network_binding: None,
    };
    operation
        .request_approval(approval.clone(), state.policy_epoch, now)
        .unwrap();
    state
        .operations
        .insert(operation_id.as_str().to_owned(), operation);
    state.updated_at = now;
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::ApprovalRequested,
            Some(operation_id.as_str().as_bytes()),
            Some(agent_id.as_str().as_bytes()),
            now,
        )
        .unwrap();
    (approval, operation_id)
}
