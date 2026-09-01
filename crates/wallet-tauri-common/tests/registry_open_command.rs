//! THE CONTROL A PERSON PRESSES TO OPEN A CHANNEL, AND THE GATE UNDER IT.
//!
//! # What was missing
//!
//! No Agent Wallet in this app could hold a provider channel. Adoption only
//! accepts a bundle whose serial-1 refund bill carries the wallet's own left
//! signature, that signature can only be made at channel open, and nothing an
//! owner could press made one. The exit works end to end on a real chain and
//! could not help a single person, because there was never anything to exit.
//!
//! The subject here is therefore deliberately **not** the core.
//! `AgentWalletManager::open_hvm_registry_channel` is proven in
//! `agent-wallet-core`. What is proven here is
//! [`wallet_tauri_common::agent_commands::open_hvm_registry_channel`], the
//! function the Tauri command's body *is* - a Tauri command cannot be entered
//! without a real `Webview`, so a command whose whole body lives behind that
//! attribute can only ever be proven by a test that reimplements it, which is
//! the same "the only caller is a test" failure one layer up.
//!
//! # What is real here
//!
//! A real `AgentWalletManager` on disk, a real wallet created and unlocked
//! through it, a real `HubState` behind the real axum router on a real socket,
//! and the real HTTP round trip to `/v2/hvm-registry/channel/open-countersign`.
//! The wallet's key never leaves its vault: this test cannot reach it and does
//! not try. Every signature in the exchange comes from the shipped signing
//! boundary.
//!
//! # What moved out of this file, and where it went
//!
//! Two behavioural tests here drove the press against a real Hub with no
//! fullnode anywhere, because the command needed none. It needs one now: a
//! reviewer took a full deposit through the gap where the wallet believed a
//! pasted channel description instead of reading its own chain, so the press
//! reads the chain before it signs. Standing up an HTTP fullnode double for
//! that would be a second, weaker copy of a proof that already exists against
//! a real block executor, so the whole press - open, deposit, adoption with the
//! provider killed, and the exit - is proven end to end in
//! `agent_wallet_core::service::hvm_registry::exit_on_chain_tests::a_wallet_opens_pays_and_walks_out_with_the_provider_deleted`,
//! and the manager-level refusals in
//! `agent-wallet-core/tests/registry_open_and_fund.rs`.
//!
//! What stays here is what only this layer can decide: the comparison between
//! the deposit the owner typed and the deposit the pasted channel would lock
//! up, which happens before any chain or provider is touched, and the count of
//! the doors onto the funding gate.
//!
//! Nothing is broadcast. Nothing reaches a chain. No money moves anywhere.

#![cfg(feature = "on-chain-exit-proof")]

use std::path::PathBuf;
use std::sync::Arc;

use agent_wallet_core::{AgentWalletId, AgentWalletManager, CreateAgentWallet};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::HvmLocalPilotNetwork;
use l2_fast_pay_hub::hvm_registry::{HPAY_REGISTRY_SETTLEMENT_PROFILE, HvmRegistryBindingV2};
use l2_fast_pay_hub::hvm_registry_pilot::build_hvm_registry_pilot_deployment;
use sys::Account;
use wallet_tauri_common::agent_commands::open_hvm_registry_channel;

const PASSPHRASE: &str = "agent wallet passphrase 123";
const DEPOSIT_ZHU: u64 = 5_000_000;
const CHALLENGE_BLOCKS: u64 = 6;
const CHANNEL_ID: &str = "6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a6a";
const SETUP_FEE_ZHU: u64 = 500_000;
const TESTNET_ANCHOR: &str = "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// A real Hub, on a real socket, with the real router.
async fn spawn_hub(
    hub: &Account,
    directory: &tempfile::TempDir,
) -> (String, Arc<HubState>, tokio::task::JoinHandle<()>) {
    let state_path: PathBuf = directory.path().join("hub-state.json");
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "registry open command proof",
            hub.readable().to_owned(),
            "http://127.0.0.1:1".to_owned(),
            None,
            state_path,
            hex::encode(hub.secret_key().serialize()),
            &"92".repeat(32),
            &"93".repeat(32),
            "local-pilot",
            0,
            0,
        )
        .expect("hub state"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let router = l2_fast_pay_hub::server::build_router(state.clone());
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .await;
    });
    (format!("http://{address}"), state, handle)
}

/// The channel a provider publishes and a wallet re-states as its own.
///
/// Built from a real deployment transaction, so the contract address, the
/// deployment hash and the bytecode digest are the ones the reviewed profile
/// demands rather than plausible-looking strings.
fn binding_for(
    hub: &Account,
    left_address: &str,
    deposit_zhu: u64,
) -> (HvmRegistryBindingV2, HvmLocalPilotNetwork) {
    let network = HvmLocalPilotNetwork::canonical();
    let deployment =
        build_hvm_registry_pilot_deployment(hub, &network, SETUP_FEE_ZHU, 100, u8::MAX).unwrap();
    let binding = HvmRegistryBindingV2 {
        schema: "hpay-hvm-registry-binding/2".into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: network.chain_id,
        network_instance_id: network.network_instance_id.clone(),
        contract_address: deployment.contract_address.clone(),
        deployment_tx_hash: deployment.transaction.transaction_hash.clone(),
        deployment_height: 100,
        bytecode_sha3: deployment.bytecode_sha3.clone(),
        channel_id: CHANNEL_ID.into(),
        reuse_version: 0,
        left_address: left_address.to_owned(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: deposit_zhu,
        right_hub_deposit_zhu: 0,
        challenge_blocks: CHALLENGE_BLOCKS,
    };
    binding.validate().expect("a reviewed-profile channel");
    (binding, network)
}

/// A real wallet, created and unlocked through the shipped manager.
fn wallet(root: &tempfile::TempDir) -> (AgentWalletManager, AgentWalletId, String) {
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.into(),
                network_mode: "testnet".into(),
                node_url: "http://127.0.0.1:18081".into(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.into()),
                mainnet_pilot_acknowledgement: None,
            },
            now_unix(),
        )
        .unwrap();
    let wallet_id: AgentWalletId = created.wallet_id.clone();
    manager.unlock(&wallet_id, PASSPHRASE, now_unix()).unwrap();
    (manager, wallet_id, created.address)
}

/// A pasted channel that would lock up more than the owner typed is refused
/// here, before the provider is asked and before anything is signed.
///
/// The owner's typed deposit and the deposit inside the provider's channel
/// description are two independent statements of the same fact, and this
/// command is the only place they can be compared: from here on, every hop
/// reads the amount out of the binding. A mismatch is refused rather than
/// reconciled, because one number is what the owner decided to risk and the
/// other is what would actually leave their balance.
#[tokio::test(flavor = "multi_thread")]
async fn a_channel_that_locks_up_more_than_the_owner_typed_is_refused_before_the_ask() {
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let hub = Account::create_by("registry-open-command-hub-2").unwrap();
    let hub_directory = tempfile::tempdir().unwrap();
    let (hub_url, hub_state, hub_server) = spawn_hub(&hub, &hub_directory).await;

    let root = tempfile::tempdir().unwrap();
    let (mut manager, wallet_id, address) = wallet(&root);
    let (binding, _network) = binding_for(&hub, &address, DEPOSIT_ZHU * 10);

    let refusal = open_hvm_registry_channel(
        &mut manager,
        &wallet_id,
        &hub_url,
        serde_json::to_value(&binding).unwrap(),
        DEPOSIT_ZHU,
        now_unix(),
    )
    .await
    .expect_err("a channel that does not lock up what the owner typed is refused");
    assert!(
        refusal.contains(
            "No channel was opened, nothing was sent to the network and no money has moved"
        ),
        "the refusal has to close down the fear before it explains anything: {refusal}"
    );

    // Nothing was signed and nothing was stored, so the wallet is exactly where
    // it started and the owner may simply try again.
    assert!(
        manager
            .hvm_registry_channel_open(&wallet_id, now_unix())
            .unwrap()
            .is_none(),
        "a refused open must leave no durable trace at all"
    );

    hub_server.abort();
    drop(hub_state);
}

/// EVERY ROUTE TO FUNDING, ENUMERATED, EACH SHOWN TO HIT THE SAME GATE.
///
/// A check on one of two doors is this project's recurring defect and reviewers
/// have caught it four times now - the fourth being the one that mattered most,
/// because it was not a registry-aware door at all. There are exactly three
/// places in this workspace that can produce bytes which put money into a
/// registry contract, and one gate that produces the permission to reach the
/// only one of them a shipped wallet can call:
///
/// 1. `l2_fast_pay_hub::hvm_registry_pilot::build_hvm_registry_pilot_exact_funding`,
///    the operator's builder, behind `local-pilot-tools`;
/// 2. `l2_fast_pay_hub::hvm_registry_watchtower::build_signed_hvm_registry_funding_transaction`,
///    the wallet's builder;
/// 3. the ordinary agent payment path, which builds an Action 1 transfer to any
///    recipient - the door nobody had counted, and the one a reviewer used to
///    fund a real channel on chain with no countersignature in existence.
///
/// Doors 1 and 2 take the countersigned bundle rather than a contract, a Hub
/// and an amount, and validate it on their first line. Door 3 is now closed to
/// contract addresses outright, at both of its own two doors. And the
/// permission that reaches door 2 cannot be produced without a live reading of
/// the wallet's own fullnode.
///
/// This reads shipped source with comments and test modules removed, because a
/// tripwire that can be satisfied by describing the thing it demands is a
/// tripwire that will be.
#[test]
fn every_door_to_funding_validates_the_refund_and_the_chain() {
    fn shipped(source: &str) -> String {
        source
            .split("#[cfg(test)]")
            .next()
            .unwrap_or_default()
            .lines()
            .filter(|line| {
                let line = line.trim_start();
                !line.starts_with("//") && !line.starts_with("///") && !line.starts_with("//!")
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
    fn first_statement<'a>(body: &'a str, after: &str) -> &'a str {
        body.split(after)
            .nth(1)
            .unwrap_or_default()
            .split('{')
            .nth(1)
            .unwrap_or_default()
            .trim_start()
    }

    // ---- door one: the operator's builder ----
    let pilot = shipped(include_str!(
        "../../l2-fast-pay-hub/src/hvm_registry_pilot.rs"
    ));
    let door_one = pilot
        .split("pub fn build_hvm_registry_pilot_exact_funding")
        .nth(1)
        .expect("the operator funding builder is still named this");
    assert!(
        door_one.starts_with("(\n    left: &Account,\n    bundle: &HvmRegistryRecoveryBundleV2,"),
        "door one must take the bundle rather than a contract, a Hub and an amount"
    );
    assert!(
        first_statement(&pilot, "pub fn build_hvm_registry_pilot_exact_funding")
            .starts_with("bundle.validate_crypto()?;"),
        "door one must validate the countersigned refund before anything else"
    );

    // ---- door two: the wallet's builder ----
    let watchtower = shipped(include_str!(
        "../../l2-fast-pay-hub/src/hvm_registry_watchtower.rs"
    ));
    let door_two = watchtower
        .split("pub fn build_signed_hvm_registry_funding_transaction")
        .nth(1)
        .expect("the wallet funding builder is still named this");
    assert!(
        door_two.starts_with(
            "(\n    signer: &Account,\n    bundle: &crate::hvm_registry::HvmRegistryRecoveryBundleV2,"
        ),
        "door two must take the bundle rather than a contract and an amount"
    );
    assert!(
        first_statement(
            &watchtower,
            "pub fn build_signed_hvm_registry_funding_transaction"
        )
        .starts_with("bundle.validate_crypto()?;"),
        "door two must validate the countersigned refund before anything else"
    );

    // ---- door three: the ordinary agent payment path ----
    //
    // This is the one that was never counted. The chain's own `PayableHAC`
    // accepts any correctly-sized transfer from the left address, and this
    // product's agent payment path built exactly those bytes for any recipient.
    let address = shipped(include_str!("../../wallet-core/src/address.rs"));
    assert!(
        address.contains("pub fn require_agent_payment_recipient("),
        "the agent payment path must have its own, narrower notion of recipient"
    );
    assert!(
        address.contains(
            "if parsed.kind == AddressKind::Contract || parsed.version == Address::CONTRACT"
        ),
        "and that notion must exclude contract addresses"
    );
    for (label, source) in [
        (
            "the agent payment intent",
            shipped(include_str!(
                "../../agent-wallet-core/src/service/payment.rs"
            )),
        ),
        (
            "the agent signing boundary",
            shipped(include_str!("../../agent-wallet-core/src/signer.rs")),
        ),
    ] {
        assert!(
            source.contains("require_agent_payment_recipient("),
            "{label} must go through the narrower recipient rule"
        );
        assert!(
            !source.contains("require_address_for_network(&request.recipient")
                && !source.contains("require_address_for_network(approved.recipient()"),
            "{label} must not still be using the wider rule for a payment recipient"
        );
    }

    // ---- the gate that produces permission for door two ----
    let core = shipped(include_str!("../../wallet-core/src/hvm_registry_open.rs"));
    let constructor = core
        .split("pub fn authorize_registry_funding")
        .nth(1)
        .expect("the only constructor is still named this");
    assert!(
        constructor.starts_with("(\n    bundle: &HvmRegistryRecoveryBundleV2,"),
        "the gate must take the bundle first"
    );
    assert!(
        constructor.contains("chain: &HvmRegistryOpenChainEvidenceV1<'_>,"),
        "THE FIX A REVIEWER'S THEFT PAID FOR: permission may not be produced without a live \
         reading of the wallet's own fullnode"
    );
    assert!(
        first_statement(&core, "pub fn authorize_registry_funding")
            .starts_with("bundle.validate_crypto()"),
        "the gate must validate the countersigned refund before anything else"
    );
    assert!(
        constructor.contains("chain.require_agrees_with(binding)?;"),
        "and it must then require the chain to agree with the binding"
    );
    assert!(
        core.contains("self.snapshot\n            .validate_prefunding_binding("),
        "the chain check must be the pre-funding snapshot validator, not a looser one"
    );

    // The permission is genuinely unforgeable: an opaque value with no
    // `Deserialize` cannot be parsed off a disk, defaulted, or built by a
    // struct literal from outside its module.
    let construction_sites = core
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            line.contains("HvmRegistryFundingAuthorizationV1 {")
                && !line.starts_with("pub struct")
                && !line.starts_with("impl")
        })
        .count();
    assert_eq!(
        construction_sites, 1,
        "the authorization must have exactly one construction site, inside the gate"
    );
    assert!(
        constructor.contains("Ok(HvmRegistryFundingAuthorizationV1 {"),
        "that one construction site must be the gate itself"
    );
    assert!(
        !core.contains("Deserialize)]\npub struct HvmRegistryFundingAuthorizationV1"),
        "the funding authorization must never become deserialisable"
    );

    // ---- and the one signing boundary that spends it ----
    let signer = shipped(include_str!("../../agent-wallet-core/src/signer.rs"));
    assert_eq!(
        signer.matches("fn sign_exact_registry_funding").count(),
        1,
        "there must be exactly one signing boundary that funds a registry channel"
    );
    assert!(
        signer.contains(
            "authorization:\n        &'a hacash_wallet_core::hvm_registry_open::HvmRegistryFundingAuthorizationV1,"
        ),
        "and it must take the unforgeable permission rather than an address and an amount"
    );

    // ---- the manager, and the command an owner presses ----
    let agent = shipped(include_str!(
        "../../agent-wallet-core/src/service/hvm_registry_open.rs"
    ));
    assert!(
        agent.contains("authorize_registry_funding(&bundle, &state.address, &reading.evidence())"),
        "the manager's permission must be re-derived from the stored bundle and a live chain \
         reading every time"
    );
    assert_eq!(
        agent.matches("fn fund_hvm_registry_channel").count(),
        1,
        "there must be exactly one way for a wallet to put money into a channel"
    );

    let command = shipped(include_str!("../src/agent_commands.rs"));
    assert!(
        command.contains(".hvm_registry_funding_authorization(wallet_id, &chain, now)"),
        "the pressable command must go through the one gate, with the wallet's own chain"
    );
    assert!(
        !command.contains("build_hvm_registry_pilot_exact_funding")
            && !command.contains("build_signed_hvm_registry_funding_transaction"),
        "the command must never build funding bytes itself"
    );
}
