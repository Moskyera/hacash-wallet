//! KILL IT MID-EXIT, AT EVERY STEP — ON CHAIN.
//!
//! `dead_hub_user_exit_on_chain.rs` proves the exit runs to completion against
//! a real block executor when nothing interrupts it.
//! `durable_exit_survives_app_close.rs` proves the durable record refuses a
//! second signature — but against a hand-built snapshot, with no chain
//! underneath it.
//!
//! This file is the crossing of the two, which is the only place the question
//! "does the user still get paid if the laptop lid closes mid-exit" can
//! actually be answered. For each of `challenge`, `respond`, `finalize` and
//! the Action 14 `claim`, the wallet is killed
//!
//!   1. after signing, before the bytes reach the node;
//!   2. after the bytes reach the node, before any block carries them;
//!   3. after the block carries them, before the record is updated;
//!
//! and then reopened from disk and driven to the end. Every kill is a real
//! `drop(ClientL2Safety)`: the exclusive lock is released and every byte of
//! in-memory state is gone. The chain is NOT killed, which is the point — a
//! mempool and a block history outlive a laptop.
//!
//! Nothing here edits production code. The driver loop below is the test's
//! own, because the shipped app has no such loop
//! (`crates/wallet-tauri-common/src/agent_commands.rs` still answers
//! `USER_EXIT_DRIVER_MISSING`); it is written to use only shipped functions,
//! in the order the shipped doc comments prescribe, and to have no authority
//! of its own: it may not sign unless `HvmRegistryExitResumeV1::may_sign()`
//! says so, and it may not invent a timestamp for a step that already has one.
//!
//! Nothing is broadcast. `testkit::sim::memchain` is an in-process chain on
//! chain id 7.

#![cfg(feature = "on-chain-exit-proof")]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use field::{Address, Hash, Serialize as _, Sign};
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::error::WalletError;
use hacash_wallet_core::hvm_registry_exit::{
    HvmRegistryExitKitV1, HvmRegistryExitPlanV1, HvmRegistryExitStep, build_exit_kit,
    build_user_exit_transaction, plan_user_exit_step,
};
use hacash_wallet_core::hvm_registry_exit_driver::{
    HvmRegistryExitChainV1, HvmRegistryExitProgressV1, HvmRegistryExitSightingV1,
    HvmRegistryExitSignerV1, HvmRegistryExitTermsV1, advance_registry_exit,
};
use hacash_wallet_core::hvm_registry_exit_record::{
    HvmRegistryExitIntentV1, HvmRegistryExitPhase, HvmRegistryExitResumeV1,
    PersistedHvmRegistryExitStepV1,
};
use hacash_wallet_core::l2_safety::ClientL2Safety;
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::{HvmLocalPilotNetwork, HvmPilotSignedTransaction};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_BILL_SCHEMA, HVM_REGISTRY_CHANNEL_KEY_COUNT,
    HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBillV2,
    HvmRegistryBindingV2, HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2,
    HvmRegistryLiveSnapshotV2, HvmRegistryRecoveryBundleV2, HvmRegistryRefundCountersignRequestV2,
};
use l2_fast_pay_hub::hvm_registry_pilot::{
    HvmRegistryPilotChannelParameters, build_hvm_registry_pilot_channel_init,
    build_hvm_registry_pilot_deployment, build_hvm_registry_pilot_exact_funding,
    build_hvm_registry_pilot_refund_countersign_request,
};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    HvmRegistryCallerRole, build_signed_hvm_registry_call_transaction,
    registry_challenge_call_source,
};
use l2_fast_pay_hub::node::HvmStorageEntry;
use sys::Account;
use testkit::sim::memchain::{MemChain, TxOutput};
use vm::ContractAddress;
use vm::value::Value;

const DEPOSIT_ZHU: u64 = 5_000_000_000;
const SPENT_ZHU: u64 = 500_000_000;
const OWED_ZHU: u64 = DEPOSIT_ZHU - SPENT_ZHU;
const CHALLENGE_BLOCKS: u64 = 6;
const FEE_ZHU: u64 = 500_000;
const GAS_MAX: u8 = u8::MAX;
const CHANNEL_ID: &str = "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e";

// ---------------------------------------------------------------------------
// Chain plumbing, lifted unchanged from `dead_hub_user_exit_on_chain.rs`.
// ---------------------------------------------------------------------------

fn addr(account: &Account) -> Address {
    Address::from(*account.address())
}

fn channel_key(prefix: &str, left: &Address) -> Value {
    let mut key = prefix.as_bytes().to_vec();
    key.extend_from_slice(left.as_bytes());
    Value::bytes(key)
}

fn parameters() -> HvmRegistryPilotChannelParameters {
    HvmRegistryPilotChannelParameters {
        channel_id: CHANNEL_ID.into(),
        reuse_version: 0,
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: CHALLENGE_BLOCKS,
    }
}

fn submit_wallet_bytes(
    chain: &mut MemChain,
    signed: &HvmPilotSignedTransaction,
    output: TxOutput,
) -> Hash {
    let raw = hex::decode(&signed.signed_transaction_hex).expect("wallet transaction is hex");
    let hash = chain
        .submit_signed_transaction_raw(&raw, output)
        .expect("chain accepted the wallet transaction");
    assert_eq!(
        hex::encode(hash.as_bytes()),
        signed.transaction_hash,
        "the chain must agree with the wallet about the transaction hash"
    );
    hash
}

fn confirm_wallet_bytes(
    chain: &mut MemChain,
    miner: Address,
    signed: &HvmPilotSignedTransaction,
    output: TxOutput,
) {
    let hash = submit_wallet_bytes(chain, signed, output);
    chain
        .confirm_formal_block(miner)
        .expect("block executed")
        .expect_success(&hash);
}

fn lease(chain: &MemChain, contract: &ContractAddress, key: &Value) -> (u64, u64, bool, bool) {
    let height = chain.height();
    vm::VMStateRead::wrap(chain.state())
        .debug_storage_get(
            &vm::rt::GasExtra::new(height),
            &vm::rt::SpaceCap::new(height),
            height,
            &contract.to_addr(),
            key,
        )
        .expect("storage read")
        .map(|debug| {
            (
                debug.live_blocks,
                debug.recover_blocks,
                debug.active,
                debug.recoverable,
            )
        })
        .expect("a live channel's storage key must exist")
}

fn entry_of<T>(
    chain: &MemChain,
    contract: &ContractAddress,
    key: &Value,
    value: T,
) -> HvmStorageEntry<T> {
    let (live_blocks, recover_blocks, active, recoverable) = lease(chain, contract, key);
    HvmStorageEntry {
        value,
        live_blocks,
        recover_blocks,
        active,
        recoverable,
    }
}

fn as_u64(value: Value) -> u64 {
    match value {
        Value::U64(inner) => inner,
        Value::U8(inner) => u64::from(inner),
        Value::U16(inner) => u64::from(inner),
        Value::U32(inner) => u64::from(inner),
        other => panic!("expected an integer storage value, got {other:?}"),
    }
}

/// The fullnode's `/query/hpay/channel-registry` answer, reproduced by reading
/// all eighteen storage keys and their remaining rent out of chain state.
fn read_snapshot(
    chain: &MemChain,
    contract: &ContractAddress,
    binding: &HvmRegistryBindingV2,
) -> HvmRegistryLiveSnapshotV2 {
    let left = Address::from_readable(&binding.left_address).expect("left address");
    let global = |name: &str| Value::bytes(name.as_bytes().to_vec());
    let channel = |prefix: &str| channel_key(prefix, &left);

    let registry = HvmRegistryGlobalStorageV2 {
        g_network: entry_of(
            chain,
            contract,
            &global("g_network"),
            binding.network_instance_id.clone(),
        ),
        g_hub: entry_of(
            chain,
            contract,
            &global("g_hub"),
            binding.right_hub_address.clone(),
        ),
        g_locked: entry_of(
            chain,
            contract,
            &global("g_locked"),
            as_u64(chain.storage(contract, &global("g_locked"))),
        ),
        g_left_claimable: entry_of(
            chain,
            contract,
            &global("g_left_claimable"),
            as_u64(chain.storage(contract, &global("g_left_claimable"))),
        ),
        g_hub_claimable: entry_of(
            chain,
            contract,
            &global("g_hub_claimable"),
            as_u64(chain.storage(contract, &global("g_hub_claimable"))),
        ),
        g_open_count: entry_of(
            chain,
            contract,
            &global("g_open_count"),
            as_u64(chain.storage(contract, &global("g_open_count"))),
        ),
    };

    let left_claimed = matches!(
        chain.storage(contract, &channel("c_left_claimed_")),
        Value::Bool(true)
    );
    let channel_storage = HvmRegistryChannelStorageV2 {
        status: entry_of(
            chain,
            contract,
            &channel("c_status_"),
            as_u64(chain.storage(contract, &channel("c_status_"))) as u8,
        ),
        channel_id: entry_of(
            chain,
            contract,
            &channel("c_id_"),
            binding.channel_id.clone(),
        ),
        reuse: entry_of(
            chain,
            contract,
            &channel("c_reuse_"),
            as_u64(chain.storage(contract, &channel("c_reuse_"))) as u32,
        ),
        deposit: entry_of(
            chain,
            contract,
            &channel("c_deposit_"),
            as_u64(chain.storage(contract, &channel("c_deposit_"))),
        ),
        paid: entry_of(
            chain,
            contract,
            &channel("c_paid_"),
            as_u64(chain.storage(contract, &channel("c_paid_"))),
        ),
        total: entry_of(
            chain,
            contract,
            &channel("c_total_"),
            as_u64(chain.storage(contract, &channel("c_total_"))),
        ),
        serial: entry_of(
            chain,
            contract,
            &channel("c_serial_"),
            as_u64(chain.storage(contract, &channel("c_serial_"))),
        ),
        left_balance: entry_of(
            chain,
            contract,
            &channel("c_left_balance_"),
            as_u64(chain.storage(contract, &channel("c_left_balance_"))),
        ),
        hub_balance: entry_of(
            chain,
            contract,
            &channel("c_hub_balance_"),
            as_u64(chain.storage(contract, &channel("c_hub_balance_"))),
        ),
        challenge_blocks: entry_of(
            chain,
            contract,
            &channel("c_challenge_"),
            as_u64(chain.storage(contract, &channel("c_challenge_"))),
        ),
        deadline: entry_of(
            chain,
            contract,
            &channel("c_deadline_"),
            as_u64(chain.storage(contract, &channel("c_deadline_"))),
        ),
        left_claimed: entry_of(chain, contract, &channel("c_left_claimed_"), left_claimed),
    };

    let observed_height = chain.height();
    let mut snapshot = HvmRegistryLiveSnapshotV2 {
        ret: 0,
        schema: HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        chain_id: binding.chain_id,
        network_instance_id: binding.network_instance_id.clone(),
        observed_height,
        evaluation_height: observed_height + 1,
        contract_address: binding.contract_address.clone(),
        deployment_tx_hash: binding.deployment_tx_hash.clone(),
        deployment_height: binding.deployment_height,
        deployment_action_verified: true,
        bytecode_sha3: binding.bytecode_sha3.clone(),
        hub_address: binding.right_hub_address.clone(),
        left_address: binding.left_address.clone(),
        registry_key_count: HVM_REGISTRY_STORAGE_KEY_COUNT,
        channel_key_count: HVM_REGISTRY_CHANNEL_KEY_COUNT,
        all_keys_active: true,
        minimum_live_blocks: 0,
        minimum_recover_blocks: 0,
        registry,
        channel: channel_storage,
    };
    let leases: Vec<(u64, u64, bool, bool)> = [
        "g_network",
        "g_hub",
        "g_locked",
        "g_left_claimable",
        "g_hub_claimable",
        "g_open_count",
    ]
    .into_iter()
    .map(|name| lease(chain, contract, &global(name)))
    .chain(
        [
            "c_status_",
            "c_id_",
            "c_reuse_",
            "c_deposit_",
            "c_paid_",
            "c_total_",
            "c_serial_",
            "c_left_balance_",
            "c_hub_balance_",
            "c_challenge_",
            "c_deadline_",
            "c_left_claimed_",
        ]
        .into_iter()
        .map(|prefix| lease(chain, contract, &channel(prefix))),
    )
    .collect();
    assert_eq!(leases.len(), 18);
    snapshot.all_keys_active = leases.iter().all(|entry| entry.2);
    snapshot.minimum_live_blocks = leases.iter().map(|entry| entry.0).min().unwrap_or_default();
    snapshot.minimum_recover_blocks = leases.iter().map(|entry| entry.1).min().unwrap_or_default();
    snapshot
}

fn countersigned_bill(
    binding: &HvmRegistryBindingV2,
    left: &Account,
    hub: &Account,
    serial: u64,
    left_balance_zhu: u64,
) -> HvmRegistryBillV2 {
    let mut bill = HvmRegistryBillV2 {
        schema: HVM_REGISTRY_BILL_SCHEMA.into(),
        binding_commitment: binding.commitment().expect("binding commitment"),
        serial,
        left_balance_zhu,
        hub_balance_zhu: binding.left_deposit_zhu - left_balance_zhu,
        left_signature_hex: String::new(),
        hub_signature_hex: String::new(),
    };
    let hash = bill.signing_hash(binding).expect("bill signing hash");
    bill.left_signature_hex = hex::encode(Sign::create_by(left, &hash).serialize());
    bill.hub_signature_hex = hex::encode(Sign::create_by(hub, &hash).serialize());
    bill.validate_fully_signed(binding)
        .expect("both parties signed this bill");
    bill
}

async fn spawn_hub(
    hub: &Account,
    directory: &tempfile::TempDir,
) -> (String, Arc<HubState>, tokio::task::JoinHandle<()>) {
    let state_path: PathBuf = directory.path().join("hub-state.json");
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "kill mid exit proof",
            addr(hub).to_readable(),
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

async fn ask_hub(
    hub_url: &str,
    ask: &HvmRegistryRefundCountersignRequestV2,
) -> Result<l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryRefundCountersignResponseV2, String> {
    let response = reqwest::Client::new()
        .post(format!(
            "{hub_url}/v2/hvm-registry/channel/open-countersign"
        ))
        .json(ask)
        .send()
        .await
        .map_err(|error| error.to_string())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    response.json().await.map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// The rig: one funded, paid channel with a dead Hub, plus the wallet's own
// durable store, plus a journal of every signature that was ever produced.
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KillPoint {
    /// Death inside the signer: the key was used and the bytes were lost with
    /// the process. This is the phase `SignatureMayExist` exists to name, and
    /// the only resume path that is allowed to use the key again.
    InsideTheSignerBytesLost,
    /// The same death, except the bytes were not lost — they reached the node
    /// before the process died, and the wallet has no idea. The worst of the
    /// five: a wallet that treats this as "nothing happened" signs a second
    /// transaction for a step already on the wire.
    InsideTheSignerBytesLeaked,
    /// The key has been used and the bytes exist. Nothing has been told to
    /// them yet.
    AfterSigningBeforeSubmit,
    /// The node has the bytes. No block carries them.
    AfterSubmitBeforeReceipt,
    /// A block carries them. The wallet's record does not know.
    AfterReceiptBeforeRecord,
}

impl KillPoint {
    fn label(self) -> &'static str {
        match self {
            Self::InsideTheSignerBytesLost => "inside the signer, bytes lost",
            Self::InsideTheSignerBytesLeaked => "inside the signer, bytes already on the node",
            Self::AfterSigningBeforeSubmit => "after signing, before submitting",
            Self::AfterSubmitBeforeReceipt => "after submitting, before the receipt",
            Self::AfterReceiptBeforeRecord => "after the receipt, before the record",
        }
    }
}

/// When the app is closed during a run of the shipped driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShippedClose {
    /// Closed cleanly after this many units of progress, which is what a lid
    /// closing looks like: somewhere between two steps, with whatever is
    /// durable being all that survives.
    AfterPasses(u32),
    /// Closed in the one gap that is not a clean boundary — the exact bytes
    /// are durable and no node has them.
    BeforeTheWire,
}

#[derive(Debug, PartialEq, Eq)]
enum SessionEnd {
    /// The wallet was killed at the requested point.
    Killed,
    /// The channel is FINAL and the user's share is claimed.
    ExitComplete,
    /// The wallet is running and cannot make progress. This is "the user is
    /// trapped".
    Stalled(String),
}

struct Rig {
    chain: MemChain,
    contract: ContractAddress,
    binding: HvmRegistryBindingV2,
    kit: HvmRegistryExitKitV1,
    wallet: WalletAccount,
    miner: Address,
    root: tempfile::TempDir,
    /// Height -> block hash, the way a node answers "which block".
    block_hashes: HashMap<u64, String>,
    /// Transaction hashes the node holds but no block carries yet.
    mempool: Vec<String>,
    /// Every signature this wallet has ever produced, across every session.
    signings: Vec<(HvmRegistryExitStep, String, u64)>,
    /// Every set of bytes ever handed to the node.
    submissions: Vec<(HvmRegistryExitStep, String)>,
    /// The same two journals, for the runs driven by the *shipped*
    /// [`advance_registry_exit`] rather than by this file's own loop.
    shipped_signings: Vec<(HvmRegistryExitStep, String, u64)>,
    shipped_submissions: Vec<String>,
    sessions: u32,
    clock: u64,
}

/// The shipped driver's view of this rig's chain.
///
/// Four methods, all answerable by a fullnode with the Hub deleted, which is
/// the whole point of the trait. `RefCell` because
/// [`advance_registry_exit`] holds the store mutably and the chain by shared
/// reference at the same time, exactly as a real caller would hold an open
/// store and an HTTP client.
struct RigChain<'a> {
    rig: std::cell::RefCell<&'a mut Rig>,
    /// When set, the next hand-off to the node fails instead of happening.
    /// This is the app being closed between the durable signature and the
    /// wire — the one gap where bytes exist and nobody has them.
    close_before_the_wire: std::cell::Cell<bool>,
}

impl HvmRegistryExitChainV1 for RigChain<'_> {
    async fn registry_snapshot(&self) -> Result<HvmRegistryLiveSnapshotV2, WalletError> {
        let rig = self.rig.borrow();
        Ok(read_snapshot(&rig.chain, &rig.contract, &rig.binding))
    }

    async fn chain_tip(&self) -> Result<(u64, u64), WalletError> {
        Ok((self.rig.borrow().chain.height(), 0))
    }

    async fn transaction_sighting(
        &self,
        hash: &str,
    ) -> Result<HvmRegistryExitSightingV1, WalletError> {
        let rig = self.rig.borrow();
        if let Some((block_height, block_hash)) = rig.node_lookup(hash) {
            return Ok(HvmRegistryExitSightingV1::Mined {
                block_height,
                block_hash,
            });
        }
        if rig.mempool.iter().any(|pending| pending == hash) {
            return Ok(HvmRegistryExitSightingV1::Pending);
        }
        Ok(HvmRegistryExitSightingV1::Unknown)
    }

    async fn submit_exit_transaction(
        &self,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> Result<(), WalletError> {
        if self.close_before_the_wire.replace(false) {
            return Err(WalletError::L2(
                "the wallet was closed before these bytes reached the network".into(),
            ));
        }
        let mut rig = self.rig.borrow_mut();
        if rig.node_lookup(transaction_hash).is_some()
            || rig
                .mempool
                .iter()
                .any(|pending| pending == transaction_hash)
        {
            return Ok(());
        }
        let raw = hex::decode(signed_transaction_hex).expect("exit transaction is hex");
        let hash = rig
            .chain
            .submit_signed_transaction_raw(&raw, TxOutput::None)
            .map_err(|error| WalletError::L2(format!("{error:?}")))?;
        assert_eq!(
            hex::encode(hash.as_bytes()),
            transaction_hash,
            "the chain must agree with the wallet about the transaction hash"
        );
        rig.mempool.push(transaction_hash.to_owned());
        rig.shipped_submissions.push(transaction_hash.to_owned());
        Ok(())
    }
}

/// The shipped driver holds no key. This is the test's stand-in for whatever
/// owns the secret above `wallet-core`, and it has no authority of its own: it
/// signs at the durable record's own terms and refuses to invent any.
struct RigSigner {
    account: Account,
    journal: std::cell::RefCell<Vec<(HvmRegistryExitStep, String, u64)>>,
}

impl HvmRegistryExitSignerV1 for RigSigner {
    fn sign_exit_step(
        &self,
        kit: &HvmRegistryExitKitV1,
        plan: &HvmRegistryExitPlanV1,
        record: &PersistedHvmRegistryExitStepV1,
    ) -> Result<
        l2_fast_pay_hub::hvm_registry_watchtower::SignedHvmRegistryCallTransactionV2,
        WalletError,
    > {
        let signed = build_user_exit_transaction(
            &self.account,
            kit,
            plan,
            record.network_fee_zhu,
            record.transaction_timestamp,
            record.gas_max,
        )?;
        self.journal.borrow_mut().push((
            record.step,
            signed.transaction_hash.clone(),
            record.transaction_timestamp,
        ));
        Ok(signed)
    }
}

impl Rig {
    fn open_store(&self) -> ClientL2Safety {
        ClientL2Safety::open_scoped_with_key_provider_for_network(
            &self.wallet,
            self.root.path(),
            "personal:kill-mid-exit",
            "testnet",
            &self.binding.right_hub_address,
            &self.binding.commitment().unwrap(),
        )
        .expect("the wallet's own L2 store opens")
    }

    fn snapshot(&self) -> HvmRegistryLiveSnapshotV2 {
        read_snapshot(&self.chain, &self.contract, &self.binding)
    }

    /// What a node answers when asked about a transaction hash.
    fn node_lookup(&self, transaction_hash: &str) -> Option<(u64, String)> {
        self.chain
            .receipts()
            .iter()
            .find(|receipt| hex::encode(receipt.tx_hash.as_bytes()) == transaction_hash)
            .map(|receipt| {
                (
                    receipt.height,
                    self.block_hashes
                        .get(&receipt.height)
                        .cloned()
                        .expect("every mined height has a block hash"),
                )
            })
    }

    fn mine(&mut self) -> (u64, String) {
        let confirmed = self
            .chain
            .confirm_formal_block(self.miner)
            .expect("block executed");
        let block_hash = hex::encode(confirmed.block_hash.as_bytes());
        self.block_hashes
            .insert(confirmed.height, block_hash.clone());
        self.mempool.clear();
        (confirmed.height, block_hash)
    }

    fn mine_empty_to(&mut self, height: u64) {
        assert!(
            self.mempool.is_empty(),
            "empty blocks cannot be mined while the node holds unmined bytes"
        );
        let first = self.chain.height() + 1;
        self.chain
            .confirm_empty_formal_blocks_to_height(self.miner, height)
            .expect("age the chain");
        // Empty blocks carry no user transaction, so their hashes are never
        // looked up; record them anyway so the map is never a lie.
        for h in first..=height {
            self.block_hashes.entry(h).or_insert_with(|| "0".repeat(64));
        }
        self.block_hashes.insert(
            self.chain.height(),
            hex::encode(self.chain.last_block_hash().as_bytes()),
        );
    }

    fn settled(&self) -> bool {
        let left = Address::from_readable(&self.binding.left_address).unwrap();
        self.chain
            .storage(&self.contract, &channel_key("c_status_", &left))
            == Value::U8(4)
            && self
                .chain
                .storage(&self.contract, &channel_key("c_left_claimed_", &left))
                == Value::Bool(true)
    }

    /// One run of the wallet process, driven by the **shipped**
    /// [`advance_registry_exit`] rather than by this file's own loop.
    ///
    /// Everything that decides anything here lives in `wallet-core`: the plan,
    /// the durable record, the phase rules, the resume decision and the order
    /// of the writes. What is left in the test is a chain, a key and the
    /// choice of when to close the app.
    async fn shipped_session(&mut self, close: Option<ShippedClose>) -> SessionEnd {
        self.sessions += 1;
        let kit = self.kit.clone();
        let terms = HvmRegistryExitTermsV1 {
            network_fee_zhu: FEE_ZHU,
            gas_max: GAS_MAX,
        };
        let signer = RigSigner {
            account: self.wallet.inner().clone(),
            journal: std::cell::RefCell::new(Vec::new()),
        };
        let mut store = self.open_store();

        let mut passes: u32 = 0;
        let outcome = loop {
            if close == Some(ShippedClose::AfterPasses(passes)) {
                break SessionEnd::Killed;
            }
            if passes >= 32 {
                break SessionEnd::Stalled("the shipped driver ran out of passes".into());
            }
            passes += 1;
            let progress = {
                let oracle = RigChain {
                    rig: std::cell::RefCell::new(&mut *self),
                    close_before_the_wire: std::cell::Cell::new(
                        close == Some(ShippedClose::BeforeTheWire) && passes == 1,
                    ),
                };
                advance_registry_exit(&mut store, &kit, &oracle, &signer, terms).await
            };
            match progress {
                Ok(HvmRegistryExitProgressV1::Complete { claimed_zhu }) => {
                    println!("    the shipped driver reports the exit complete: {claimed_zhu} zhu");
                    break SessionEnd::ExitComplete;
                }
                Ok(HvmRegistryExitProgressV1::Stepped {
                    step,
                    transaction_hash,
                    phase,
                }) => {
                    println!("    {step:?} -> {phase:?} ({})", &transaction_hash[..16]);
                    if !self.mempool.is_empty() {
                        self.mine();
                    }
                }
                Ok(HvmRegistryExitProgressV1::Waiting {
                    reason,
                    status,
                    deadline,
                    ..
                }) => {
                    if !self.mempool.is_empty() {
                        self.mine();
                        continue;
                    }
                    if self.settled() {
                        break SessionEnd::ExitComplete;
                    }
                    if status == 3 && deadline > self.chain.height() {
                        // A laptop cannot mine blocks; this is the objection
                        // window passing, which is the thing the exit spends
                        // most of its life waiting for.
                        self.mine_empty_to(deadline);
                        continue;
                    }
                    break SessionEnd::Stalled(reason);
                }
                Err(error) => {
                    if close == Some(ShippedClose::BeforeTheWire) {
                        println!("    the app closed with signed bytes nobody had: {error}");
                        break SessionEnd::Killed;
                    }
                    break SessionEnd::Stalled(error.to_string());
                }
            }
        };
        self.shipped_signings.extend(signer.journal.into_inner());
        // The app closing. The exclusive lock goes, and so does every byte of
        // state this process was holding.
        drop(store);
        outcome
    }

    /// One run of the wallet process.
    ///
    /// The whole body is the driver a shipped app would need. It has no
    /// authority the shipped functions do not give it: it never signs without
    /// a resume that permits signing, and it never chooses a timestamp for a
    /// step that already carries one.
    fn session(&mut self, kill: Option<(HvmRegistryExitStep, KillPoint)>) -> SessionEnd {
        self.sessions += 1;
        // A fresh process holds a fresh clock. If any resume path ever signed
        // on "now" instead of on the record's own timestamp, the transaction
        // hash would move and the journal check at the end would catch it.
        self.clock = 1_700_000_000 + u64::from(self.sessions) * 4_000;
        let binding_commitment = self.binding.commitment().unwrap();
        let mut store = self.open_store();

        for _round in 0..32 {
            let snapshot = self.snapshot();
            let tip = self.chain.height();
            let plan = match plan_user_exit_step(&self.kit, &snapshot, tip, 0) {
                Ok(plan) => plan,
                Err(error) => return SessionEnd::Stalled(format!("the planner refused: {error}")),
            };
            let step = match &plan {
                HvmRegistryExitPlanV1::Wait { reason } => {
                    if self.settled() {
                        return SessionEnd::ExitComplete;
                    }
                    let deadline = snapshot.channel.deadline.value;
                    if snapshot.channel.status.value == 3 && deadline > tip {
                        self.mine_empty_to(deadline);
                        continue;
                    }
                    return SessionEnd::Stalled(format!(
                        "the wallet is waiting for something that is not coming: {reason}"
                    ));
                }
                HvmRegistryExitPlanV1::Call { step, .. } => *step,
                HvmRegistryExitPlanV1::Claim { .. } => HvmRegistryExitStep::Claim,
            };

            // ---- 1. What does the durable record say about this step?
            let resumed = match store.resume_exit_step(&self.kit, &binding_commitment, step) {
                Ok(Some(resumed)) => resumed,
                Ok(None) => {
                    let intent = match HvmRegistryExitIntentV1::from_plan(
                        &self.kit, &plan, &snapshot, FEE_ZHU, self.clock, GAS_MAX,
                    ) {
                        Ok(intent) => intent,
                        Err(error) => {
                            return SessionEnd::Stalled(format!(
                                "no intent could be built: {error}"
                            ));
                        }
                    };
                    match store.begin_or_resume_exit_step(&self.kit, &intent) {
                        Ok(resumed) => resumed,
                        Err(error) => {
                            return SessionEnd::Stalled(format!(
                                "the store refused to open {step:?}: {error}"
                            ));
                        }
                    }
                }
                Err(error) => {
                    return SessionEnd::Stalled(format!(
                        "the durable record for {step:?} did not re-derive: {error}"
                    ));
                }
            };

            // ---- 2. Sign, or don't.
            let (signed_hex, transaction_hash) = match resumed {
                HvmRegistryExitResumeV1::Done { record } => {
                    return SessionEnd::Stalled(format!(
                        "the chain asks for {step:?} and the record calls it {:?}; the wallet \
                         has nothing left to try",
                        record.phase
                    ));
                }
                HvmRegistryExitResumeV1::SignFresh { record }
                | HvmRegistryExitResumeV1::ResignExact { record } => {
                    if record.phase == HvmRegistryExitPhase::IntentPersisted {
                        // The possibility of a signature is durable before the
                        // key is used.
                        store
                            .mark_exit_step_signature_may_exist(
                                &self.kit,
                                &binding_commitment,
                                step,
                            )
                            .expect("the signer is announced first");
                    }
                    let signed = build_user_exit_transaction(
                        self.wallet.inner(),
                        &self.kit,
                        &plan,
                        record.network_fee_zhu,
                        record.transaction_timestamp,
                        record.gas_max,
                    )
                    .expect("the user's own key signs their own exit step");
                    self.signings.push((
                        step,
                        signed.transaction_hash.clone(),
                        record.transaction_timestamp,
                    ));
                    // Death inside the signer: the key has been used and the
                    // store does not hold the bytes.
                    if kill == Some((step, KillPoint::InsideTheSignerBytesLost)) {
                        drop(store);
                        return SessionEnd::Killed;
                    }
                    if kill == Some((step, KillPoint::InsideTheSignerBytesLeaked)) {
                        let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
                        let hash = self
                            .chain
                            .submit_signed_transaction_raw(&raw, TxOutput::None)
                            .expect("the node took the bytes the wallet is about to forget");
                        assert_eq!(hex::encode(hash.as_bytes()), signed.transaction_hash);
                        self.mempool.push(signed.transaction_hash.clone());
                        self.submissions
                            .push((step, signed.transaction_hash.clone()));
                        drop(store);
                        return SessionEnd::Killed;
                    }
                    store
                        .persist_exit_step_signature(
                            &self.kit,
                            &binding_commitment,
                            step,
                            &signed.signed_transaction_hex,
                            &signed.transaction_hash,
                        )
                        .expect("the exact bytes are durable");
                    if kill == Some((step, KillPoint::AfterSigningBeforeSubmit)) {
                        drop(store);
                        return SessionEnd::Killed;
                    }
                    (signed.signed_transaction_hex, signed.transaction_hash)
                }
                HvmRegistryExitResumeV1::AwaitChain {
                    transaction_hash,
                    signed_transaction_hex,
                    ..
                } => {
                    if let Some((height, block_hash)) = self.node_lookup(&transaction_hash) {
                        store
                            .mark_exit_step_confirmed(
                                &self.kit,
                                &binding_commitment,
                                step,
                                &transaction_hash,
                                height,
                                &block_hash,
                            )
                            .expect("our own mined transaction confirms the step");
                        continue;
                    }
                    (signed_transaction_hex, transaction_hash)
                }
            };

            // ---- 3. Hand the bytes to the node, durably first.
            let phase = store
                .exit_step_record(&binding_commitment, step)
                .map(|record| record.phase);
            if phase == Some(HvmRegistryExitPhase::Signed) {
                store
                    .mark_exit_step_submitted(&self.kit, &binding_commitment, step)
                    .expect("submission is durable before the wire");
            }
            if self.node_lookup(&transaction_hash).is_none()
                && !self.mempool.contains(&transaction_hash)
            {
                let raw = hex::decode(&signed_hex).expect("exit transaction is hex");
                let hash = self
                    .chain
                    .submit_signed_transaction_raw(&raw, TxOutput::None)
                    .expect("chain accepted the user's exit transaction");
                assert_eq!(
                    hex::encode(hash.as_bytes()),
                    transaction_hash,
                    "the chain must agree with the wallet about the transaction hash"
                );
                self.mempool.push(transaction_hash.clone());
                self.submissions.push((step, transaction_hash.clone()));
            }
            if kill == Some((step, KillPoint::AfterSubmitBeforeReceipt)) {
                drop(store);
                return SessionEnd::Killed;
            }

            // ---- 4. A block carries them.
            let (height, block_hash) = self.mine();
            assert!(
                self.node_lookup(&transaction_hash).is_some(),
                "{step:?} was submitted and the next block does not carry it"
            );
            if kill == Some((step, KillPoint::AfterReceiptBeforeRecord)) {
                drop(store);
                return SessionEnd::Killed;
            }

            // ---- 5. And only now is the record allowed to catch up.
            store
                .mark_exit_step_confirmed(
                    &self.kit,
                    &binding_commitment,
                    step,
                    &transaction_hash,
                    height,
                    &block_hash,
                )
                .expect("our own mined transaction confirms the step");
        }
        SessionEnd::Stalled("the driver ran out of rounds without settling".into())
    }
}

/// A funded, paid registry channel whose Hub has been killed and proven dead.
///
/// `head_serial` is 2 for the ordinary exit. The `respond` scenarios need a
/// stale challenge already standing on chain, which needs a head bill one
/// serial above the bill in that challenge.
async fn dead_hub_rig(seed: &str, head_serial: u64) -> (Rig, Account) {
    let network = HvmLocalPilotNetwork::canonical();
    let mut chain = MemChain::new();
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    chain.set_chain_id(network.chain_id);
    chain.set_height(protocol::upgrade::ONLINE_OPEN_HEIGHT);

    let hub = Account::create_by(&format!("kill-mid-exit-hub-{seed}")).unwrap();
    let wallet = WalletAccount::create(&format!("kill-mid-exit-left-{seed}")).unwrap();
    let left = wallet.inner().clone();
    let miner = addr(&Account::create_by(&format!("kill-mid-exit-miner-{seed}")).unwrap());
    for account in [&hub, &left] {
        chain.mint_hac(&addr(account), 30_000_000_000_000);
    }

    let deployment = build_hvm_registry_pilot_deployment(&hub, &network, FEE_ZHU, 100, GAS_MAX)
        .expect("wallet built the registry deployment");
    let contract = ContractAddress::from_addr(
        Address::from_readable(&deployment.contract_address).expect("contract address"),
    )
    .expect("contract address is a contract");
    confirm_wallet_bytes(
        &mut chain,
        miner,
        &deployment.transaction,
        TxOutput::ContractAddress(contract.clone()),
    );
    let deployment_height = chain.height();

    let init = build_hvm_registry_pilot_channel_init(
        &left,
        &hub,
        &deployment.contract_address,
        &network,
        &parameters(),
        FEE_ZHU,
        101,
        GAS_MAX,
    )
    .expect("wallet built the channel init");
    confirm_wallet_bytes(&mut chain, miner, &init, TxOutput::None);

    let directory = tempfile::tempdir().unwrap();
    let (hub_url, hub_state, hub_server) = spawn_hub(&hub, &directory).await;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let ask = build_hvm_registry_pilot_refund_countersign_request(
        &left,
        hub.readable(),
        &deployment,
        deployment_height,
        &parameters(),
        now,
        now + 300,
    )
    .expect("wallet built the refund countersign ask");
    let answer = ask_hub(&hub_url, &ask).await.expect("Hub countersigned");
    let bundle: HvmRegistryRecoveryBundleV2 = ask
        .attach_hub_countersignature(&answer.hub_refund_signature_hex)
        .expect("the Hub signature verifies against the wallet's own binding");
    let binding = bundle.binding.clone();

    let funding =
        build_hvm_registry_pilot_exact_funding(&left, &bundle, &network, FEE_ZHU, 102, GAS_MAX)
            .expect("funding requires a countersigned refund, and there is one");
    confirm_wallet_bytes(&mut chain, miner, &funding, TxOutput::None);
    assert_eq!(
        chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(DEPOSIT_ZHU),
        "the deposit is inside the contract"
    );

    // The user spends through the channel while the Hub is alive.
    let head = countersigned_bill(&binding, &left, &hub, head_serial, OWED_ZHU);
    assert_eq!(head.hub_balance_zhu, SPENT_ZHU);

    hub_server.abort();
    drop(hub_state);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let corpse = ask_hub(&hub_url, &ask).await;
    assert!(
        corpse.is_err(),
        "this proof is worthless unless the Hub is actually dead: {corpse:?}"
    );

    let kit = build_exit_kit(binding.clone(), head).expect("the user's own exit kit");
    let rig = Rig {
        chain,
        contract,
        binding,
        kit,
        wallet,
        miner,
        root: tempfile::tempdir().expect("wallet storage root"),
        block_hashes: HashMap::new(),
        mempool: Vec::new(),
        signings: Vec::new(),
        submissions: Vec::new(),
        shipped_signings: Vec::new(),
        shipped_submissions: Vec::new(),
        sessions: 0,
        clock: 0,
    };
    (rig, hub)
}

/// The hostile Hub's last act: a `challenge` carrying a bill one serial behind
/// the user's, signed with the Hub's own settlement key.
///
/// This is what puts the channel in CHALLENGING with a serial below the
/// wallet's, which is the only state in which the user's driver plans
/// `Respond`.
fn hub_posts_a_stale_challenge(rig: &mut Rig, hub: &Account, stale_serial: u64) {
    let stale = countersigned_bill(
        &rig.binding,
        rig.wallet.inner(),
        hub,
        stale_serial,
        OWED_ZHU,
    );
    let call_source =
        registry_challenge_call_source(&rig.binding, &stale).expect("the Hub's own challenge");
    let signed = build_signed_hvm_registry_call_transaction(
        hub,
        &rig.binding,
        HvmRegistryCallerRole::Hub,
        call_source,
        FEE_ZHU,
        1_690_000_000,
        GAS_MAX,
    )
    .expect("the Hub can sign its own challenge");
    let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
    let hash = rig
        .chain
        .submit_signed_transaction_raw(&raw, TxOutput::None)
        .expect("chain accepted the Hub's stale challenge");
    rig.mine();
    assert!(
        rig.node_lookup(&hex::encode(hash.as_bytes())).is_some(),
        "the Hub's stale challenge must be mined"
    );
    let snapshot = rig.snapshot();
    assert_eq!(
        snapshot.channel.status.value, 3,
        "the channel is CHALLENGING"
    );
    assert_eq!(snapshot.channel.serial.value, stale_serial);
}

/// Drive one scenario end to end and return the sentence describing it.
fn drive(rig: &mut Rig, kill: (HvmRegistryExitStep, KillPoint)) -> String {
    let left = Address::from_readable(&rig.binding.left_address).unwrap();
    let before = rig.chain.balance(&left).to_zhu_u64().unwrap();

    let first = rig.session(Some(kill));
    assert_eq!(
        first,
        SessionEnd::Killed,
        "the scenario is worthless unless the wallet actually died at {:?}/{}",
        kill.0,
        kill.1.label()
    );
    println!(
        "    KILLED at {:?} {}: the wallet process is gone, the chain is not",
        kill.0,
        kill.1.label()
    );

    // Reopen and drive to the end. Any number of further sessions is allowed;
    // none of them may sign a step a second time.
    let mut ended = SessionEnd::Killed;
    for _ in 0..8 {
        ended = rig.session(None);
        if ended != SessionEnd::Killed {
            break;
        }
    }
    match &ended {
        SessionEnd::ExitComplete => {}
        other => panic!("the reopened wallet did not finish the exit: {other:?}"),
    }

    // ---- What the chain says.
    let after = rig.chain.balance(&left).to_zhu_u64().unwrap();
    assert_eq!(
        rig.chain
            .storage(&rig.contract, &channel_key("c_status_", &left)),
        Value::U8(4),
        "the channel must be FINAL"
    );
    assert_eq!(
        rig.chain
            .storage(&rig.contract, &channel_key("c_left_claimed_", &left)),
        Value::Bool(true),
        "the user's share must be claimed"
    );
    assert_eq!(
        rig.chain.balance(&rig.contract.to_addr()).to_zhu_u64(),
        Ok(SPENT_ZHU),
        "only the Hub's earned share may be left inside the contract"
    );
    let cost = (before + OWED_ZHU)
        .checked_sub(after)
        .expect("the payout must have reached the user's own address");
    assert!(after > before, "the user must end richer than they started");
    assert!(cost < OWED_ZHU, "the exit must cost less than it recovers");

    // ---- The invariant that the record exists for: one signature per step,
    // at one timestamp, forever.
    for step in [
        HvmRegistryExitStep::Challenge,
        HvmRegistryExitStep::Respond,
        HvmRegistryExitStep::Finalize,
        HvmRegistryExitStep::Claim,
        HvmRegistryExitStep::RenewChannelLease,
        HvmRegistryExitStep::RenewRegistryLease,
    ] {
        let signed: Vec<_> = rig
            .signings
            .iter()
            .filter(|(taken, _, _)| *taken == step)
            .collect();
        if signed.is_empty() {
            continue;
        }
        let (_, first_hash, first_timestamp) = signed[0];
        for (_, hash, timestamp) in &signed {
            assert_eq!(
                hash, first_hash,
                "{step:?} was signed as two different transactions"
            );
            assert_eq!(
                timestamp, first_timestamp,
                "{step:?} was signed twice at two different timestamps"
            );
        }
        let submitted: Vec<_> = rig
            .submissions
            .iter()
            .filter(|(taken, _)| *taken == step)
            .map(|(_, hash)| hash.clone())
            .collect();
        let mut distinct = submitted.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            1,
            "{step:?} put {} different transactions on the wire",
            distinct.len()
        );
        println!(
            "    {step:?}: signed {} time(s), all as {} at timestamp {}; {} submission(s), one \
             transaction",
            signed.len(),
            &first_hash[..16],
            first_timestamp,
            submitted.len(),
        );
    }

    format!(
        "paid {OWED_ZHU} zhu, cost {cost} zhu, {} wallet session(s)",
        rig.sessions
    )
}

// ---------------------------------------------------------------------------
// THE TWELVE KILLS
// ---------------------------------------------------------------------------

#[tokio::test]
async fn the_wallet_is_killed_at_every_point_of_every_exit_step_and_the_user_is_still_paid() {
    let mut results: Vec<(String, String)> = Vec::new();
    for (index, step) in [
        HvmRegistryExitStep::Challenge,
        HvmRegistryExitStep::Respond,
        HvmRegistryExitStep::Finalize,
        HvmRegistryExitStep::Claim,
    ]
    .into_iter()
    .enumerate()
    {
        for (inner, point) in [
            KillPoint::InsideTheSignerBytesLost,
            KillPoint::InsideTheSignerBytesLeaked,
            KillPoint::AfterSigningBeforeSubmit,
            KillPoint::AfterSubmitBeforeReceipt,
            KillPoint::AfterReceiptBeforeRecord,
        ]
        .into_iter()
        .enumerate()
        {
            let seed = format!("{index}-{inner}");
            println!("\n=== KILL {step:?} {} ===", point.label());
            let (mut rig, hub) = if step == HvmRegistryExitStep::Respond {
                let (mut rig, hub) = dead_hub_rig(&seed, 3).await;
                hub_posts_a_stale_challenge(&mut rig, &hub, 2);
                (rig, hub)
            } else {
                dead_hub_rig(&seed, 2).await
            };
            let _ = hub;
            let outcome = drive(&mut rig, (step, point));
            println!("    RESULT: {outcome}");
            results.push((format!("{step:?} / {}", point.label()), outcome));
        }
    }

    println!("\n=== TWELVE KILLS, TWELVE PAYMENTS ===");
    for (scenario, outcome) in &results {
        println!("  {scenario}: {outcome}");
    }
    assert_eq!(results.len(), 20);
}

/// The `Respond` kills above hand-build a same-amount serial bump, and this is
/// why: with a *genuinely* stale bill the shipped planner never reaches
/// `Respond` at all, and what it reaches instead is a dead end.
///
/// The setup is the ordinary hostile move on any payment channel — the Hub
/// posts an old state. On this one-directional rail an old state pays the user
/// MORE, so `registry_respond_defends_left_payout`
/// (`crates/l2-fast-pay-hub/src/hvm_registry_watchtower.rs:326`) correctly
/// tells the user's driver not to argue with it, and `plan_user_exit_step`
/// answers `Wait`.
///
/// Then the objection window closes, and
/// `decide_registry_watchtower_action` line 229 — `3 if chain_serial <
/// latest.serial => RecoveryRequired` — turns that same standing challenge
/// into a hard `Err` from the planner. `finalize` and the Action 14 claim are
/// both permissionless and both would pay this user the larger number the Hub
/// itself put on chain, and the shipped planner will not emit either one,
/// forever.
///
/// The last third of this test presses those two buttons by hand to establish
/// what kind of stuck this is: the coin is reachable on chain, and it is the
/// wallet's own planner that will not reach for it.
///
/// # This is the *old* behaviour, kept as the before-and-after
///
/// `decide_user_exit_action` now reads a disagreeing chain from the left
/// party's chair instead of deferring to the Hub's, so the sequence below no
/// longer dead-ends: past the deadline the planner emits `finalize`, and then
/// the Action 14 claim, and the user is paid the *larger* number the Hub itself
/// put on chain. The assertions have been turned around to say so, and the
/// hand-pressed third of the test is gone because the driver now presses them
/// itself.
#[tokio::test]
async fn a_genuinely_stale_challenge_is_finished_by_the_driver_in_the_users_favour() {
    let (mut rig, hub) = dead_hub_rig("stale", 3).await;
    // The Hub challenges with serial 2, from back when the user was owed more.
    let generous = OWED_ZHU + 250_000_000;
    let stale = countersigned_bill(&rig.binding, rig.wallet.inner(), &hub, 2, generous);
    let call_source = registry_challenge_call_source(&rig.binding, &stale).unwrap();
    let signed = build_signed_hvm_registry_call_transaction(
        &hub,
        &rig.binding,
        HvmRegistryCallerRole::Hub,
        call_source,
        FEE_ZHU,
        1_690_000_000,
        GAS_MAX,
    )
    .unwrap();
    let raw = hex::decode(&signed.signed_transaction_hex).unwrap();
    rig.chain
        .submit_signed_transaction_raw(&raw, TxOutput::None)
        .unwrap();
    rig.mine();

    let snapshot = rig.snapshot();
    assert_eq!(snapshot.channel.status.value, 3);
    assert_eq!(snapshot.channel.left_balance.value, generous);

    // ---- Inside the window: the driver correctly declines to respond.
    let plan = plan_user_exit_step(&rig.kit, &snapshot, rig.chain.height(), 0).unwrap();
    assert!(
        matches!(plan, HvmRegistryExitPlanV1::Wait { .. }),
        "the driver must not answer a challenge that pays its own user more, got {plan:?}"
    );
    println!("inside the window the driver waits, which is right: arguing would cost it money");

    // ---- The window closes. This is where the planner used to return a hard
    // `Err(RecoveryRequired)` and stop the exit forever.
    let left = Address::from_readable(&rig.binding.left_address).unwrap();
    let before = rig.chain.balance(&left).to_zhu_u64().unwrap();
    let deadline = snapshot.channel.deadline.value;
    rig.mine_empty_to(deadline);
    let snapshot = rig.snapshot();
    let plan = plan_user_exit_step(&rig.kit, &snapshot, rig.chain.height(), 0)
        .expect("past the deadline a standing challenge is finished, not refused");
    assert!(
        matches!(
            plan,
            HvmRegistryExitPlanV1::Call {
                step: HvmRegistryExitStep::Finalize,
                ..
            }
        ),
        "past the deadline the planner must finalize whatever is standing, got {plan:?}"
    );
    println!("past the deadline the planner finalizes what is standing instead of refusing");

    // ---- And a whole wallet session drives it to the end, unaided.
    let mut ended = SessionEnd::Killed;
    for _ in 0..8 {
        ended = rig.session(None);
        if ended != SessionEnd::Killed {
            break;
        }
    }
    assert_eq!(
        ended,
        SessionEnd::ExitComplete,
        "the driver must finish an exit whose challenge somebody else opened"
    );

    let after = rig.chain.balance(&left).to_zhu_u64().unwrap();
    assert!(after > before, "the exit must pay the user");
    assert_eq!(
        rig.chain.balance(&rig.contract.to_addr()).to_zhu_u64(),
        Ok(DEPOSIT_ZHU - generous),
        "the user is paid the Hub's own larger number"
    );
    assert_eq!(
        rig.chain
            .storage(&rig.contract, &channel_key("c_left_claimed_", &left)),
        Value::Bool(true)
    );
    println!(
        "SO: the hostile Hub's own stale challenge paid this user {generous} zhu, {} zhu MORE \
         than their own head bill claimed, and the shipped driver reached for it by itself.",
        generous - OWED_ZHU
    );
    // The shortfall reporter is the other direction and must stay quiet here:
    // the chain is paying more, not less.
    assert_eq!(
        hacash_wallet_core::hvm_registry_exit::exit_payout_shortfall_zhu(&rig.kit, &snapshot),
        None
    );
}

// ---------------------------------------------------------------------------
// ONE CHANNEL, NINE KILLS
// ---------------------------------------------------------------------------

/// Twelve separate scenarios each survive one kill. That is not the same
/// question as whether one exit survives being killed over and over, which is
/// what an unreliable laptop actually does.
///
/// Here a single funded channel is killed at all three points of `challenge`,
/// then all three points of `finalize`, then all three points of the Action 14
/// `claim` — nine process deaths inside one exit — and the user still has to
/// end up paid exactly once.
#[tokio::test]
async fn one_exit_survives_being_killed_nine_times() {
    let (mut rig, _hub) = dead_hub_rig("nine", 2).await;
    let left = Address::from_readable(&rig.binding.left_address).unwrap();
    let before = rig.chain.balance(&left).to_zhu_u64().unwrap();

    let kills = [
        (
            HvmRegistryExitStep::Challenge,
            KillPoint::AfterSigningBeforeSubmit,
        ),
        (
            HvmRegistryExitStep::Challenge,
            KillPoint::AfterSubmitBeforeReceipt,
        ),
        (
            HvmRegistryExitStep::Challenge,
            KillPoint::AfterReceiptBeforeRecord,
        ),
        (
            HvmRegistryExitStep::Finalize,
            KillPoint::AfterSigningBeforeSubmit,
        ),
        (
            HvmRegistryExitStep::Finalize,
            KillPoint::AfterSubmitBeforeReceipt,
        ),
        (
            HvmRegistryExitStep::Finalize,
            KillPoint::AfterReceiptBeforeRecord,
        ),
        (
            HvmRegistryExitStep::Claim,
            KillPoint::AfterSigningBeforeSubmit,
        ),
        (
            HvmRegistryExitStep::Claim,
            KillPoint::AfterSubmitBeforeReceipt,
        ),
        (
            HvmRegistryExitStep::Claim,
            KillPoint::AfterReceiptBeforeRecord,
        ),
    ];
    for kill in kills {
        let ended = rig.session(Some(kill));
        assert_eq!(
            ended,
            SessionEnd::Killed,
            "expected to die at {:?} {}",
            kill.0,
            kill.1.label()
        );
        println!("  died at {:?} {}", kill.0, kill.1.label());
    }
    let mut ended = SessionEnd::Killed;
    for _ in 0..8 {
        ended = rig.session(None);
        if ended != SessionEnd::Killed {
            break;
        }
    }
    assert_eq!(
        ended,
        SessionEnd::ExitComplete,
        "nine deaths and the exit never finished"
    );

    let after = rig.chain.balance(&left).to_zhu_u64().unwrap();
    assert_eq!(
        rig.chain
            .storage(&rig.contract, &channel_key("c_left_claimed_", &left)),
        Value::Bool(true)
    );
    assert_eq!(
        rig.chain.balance(&rig.contract.to_addr()).to_zhu_u64(),
        Ok(SPENT_ZHU)
    );
    let cost = (before + OWED_ZHU)
        .checked_sub(after)
        .expect("the user is paid");
    assert!(after > before);

    // Three steps, three signatures, nine deaths.
    assert_eq!(
        rig.signings.len(),
        3,
        "nine deaths produced {} signatures: {:?}",
        rig.signings.len(),
        rig.signings
    );
    assert_eq!(rig.submissions.len(), 3);
    for (step, hash, timestamp) in &rig.signings {
        println!("  {step:?} signed once as {} at {timestamp}", &hash[..16]);
    }
    println!(
        "PAID after nine deaths: {OWED_ZHU} zhu recovered for {cost} zhu across {} wallet \
         sessions",
        rig.sessions
    );
}

// ---------------------------------------------------------------------------
// THE NEGATIVE CONTROL
// ---------------------------------------------------------------------------

/// Would this harness notice if the durable record were not there?
///
/// A test that only ever passes proves nothing about the thing it names. This
/// is the same rig, the same chain and the same kill point, driven by a wallet
/// that does exactly what this codebase did before the durable record existed:
/// it re-plans from the chain on reopen and signs whatever the chain still
/// appears to need.
///
/// It is a `#[test]`, not a comment, because the failure it demonstrates is
/// the reason the record was built.
#[tokio::test]
async fn without_the_record_a_reopened_wallet_signs_the_same_step_a_second_time() {
    let (mut rig, _hub) = dead_hub_rig("control", 2).await;

    // --- session one: the pre-record wallet plans, signs, submits, and dies
    // before any block carries the bytes.
    let snapshot = rig.snapshot();
    let tip = rig.chain.height();
    let plan = plan_user_exit_step(&rig.kit, &snapshot, tip, 0).expect("planned");
    let first = build_user_exit_transaction(
        rig.wallet.inner(),
        &rig.kit,
        &plan,
        FEE_ZHU,
        1_700_004_000,
        GAS_MAX,
    )
    .expect("signed");
    let raw = hex::decode(&first.signed_transaction_hex).unwrap();
    rig.chain
        .submit_signed_transaction_raw(&raw, TxOutput::None)
        .expect("the node has the bytes");
    rig.mempool.push(first.transaction_hash.clone());
    println!(
        "session one submitted challenge {} and died before the receipt",
        first.transaction_hash
    );

    // --- session two: no record, so the chain is the only memory. The chain
    // still reads OPEN, because the mempool is not the chain.
    let snapshot = rig.snapshot();
    assert_eq!(
        snapshot.channel.status.value, 2,
        "still OPEN, nothing mined"
    );
    let replan =
        plan_user_exit_step(&rig.kit, &snapshot, rig.chain.height(), 0).expect("replanned");
    assert_eq!(replan, plan, "the chain asks for the very same step");
    let second = build_user_exit_transaction(
        rig.wallet.inner(),
        &rig.kit,
        &plan,
        FEE_ZHU,
        1_700_008_000,
        GAS_MAX,
    )
    .expect("signed again");

    assert_ne!(
        second.transaction_hash, first.transaction_hash,
        "a wallet with no record signs a SECOND transaction for a step already on the wire"
    );
    println!(
        "session two signed a second challenge {} at a different timestamp",
        second.transaction_hash
    );

    // And it is not harmless: both sets of bytes are valid, both are accepted
    // by the node, and the block that carries the pair is not executable.
    let raw = hex::decode(&second.signed_transaction_hex).unwrap();
    rig.chain
        .submit_signed_transaction_raw(&raw, TxOutput::None)
        .expect("the node takes the duplicate too");
    let outcome = rig.chain.confirm_formal_block(rig.miner);
    println!("the block carrying both: {outcome:?}");
    assert!(
        outcome.is_err(),
        "a block carrying both challenges executed cleanly, so this control proves nothing"
    );
}

// ---------------------------------------------------------------------------
// THE PROOF THIS FILE EXISTS FOR, DRIVEN BY SHIPPED CODE
// ---------------------------------------------------------------------------

/// Fund a channel, pay on it, kill the Hub, start the exit, close the wallet
/// mid-sequence — twice — reopen it, finish, and be paid on chain from the
/// user's own key alone.
///
/// Every decision in this test is made by `wallet-core`:
/// [`advance_registry_exit`] plans from the chain, consults the durable
/// record, announces the signature before the key, makes the bytes durable
/// before the wire, and confirms only after a block carries them. The test
/// supplies a chain, a key and the moments the app is closed. Nothing here
/// re-implements any of that, which is exactly what the previous version of
/// this file did and why its result did not transfer to the product.
#[tokio::test]
async fn the_shipped_driver_is_closed_mid_exit_and_the_user_is_still_paid() {
    // `dead_hub_rig` funds the channel, spends part of it through the live
    // Hub, then aborts the Hub's server and proves at the socket that a
    // request to it now fails. Nothing below this line can reach a provider.
    let (mut rig, _hub) = dead_hub_rig("shipped", 2).await;
    let left = Address::from_readable(&rig.binding.left_address).unwrap();
    let before = rig.chain.balance(&left).to_zhu_u64().unwrap();
    println!(
        "a funded, paid channel with a dead Hub: deposit {DEPOSIT_ZHU} zhu, spent {SPENT_ZHU} zhu, owed {OWED_ZHU} zhu"
    );

    // ---- Close 1: the app dies with signed bytes that never reached a node.
    let first = rig.shipped_session(Some(ShippedClose::BeforeTheWire)).await;
    assert_eq!(
        first,
        SessionEnd::Killed,
        "session one must end by being closed, not by finishing"
    );
    println!("CLOSE 1: the wallet is gone, holding a durable signature no node ever saw");

    // ---- Close 2: reopened, it puts that same transaction on the wire and is
    // closed again after one unit of progress.
    let second = rig
        .shipped_session(Some(ShippedClose::AfterPasses(1)))
        .await;
    assert_eq!(second, SessionEnd::Killed);
    println!("CLOSE 2: the wallet is gone again, mid-objection-window");

    // ---- And now let it finish.
    let mut ended = SessionEnd::Killed;
    for _ in 0..8 {
        ended = rig.shipped_session(None).await;
        if ended != SessionEnd::Killed {
            break;
        }
    }
    assert_eq!(
        ended,
        SessionEnd::ExitComplete,
        "the reopened wallet must finish the exit it started"
    );

    // ---- What the chain says, which is the only thing that counts.
    let after = rig.chain.balance(&left).to_zhu_u64().unwrap();
    assert_eq!(
        rig.chain
            .storage(&rig.contract, &channel_key("c_status_", &left)),
        Value::U8(4),
        "the channel must be FINAL"
    );
    assert_eq!(
        rig.chain
            .storage(&rig.contract, &channel_key("c_left_claimed_", &left)),
        Value::Bool(true),
        "the user's share must be claimed"
    );
    assert_eq!(
        rig.chain.balance(&rig.contract.to_addr()).to_zhu_u64(),
        Ok(SPENT_ZHU),
        "only the Hub's earned share may remain inside the contract"
    );
    assert!(after > before, "the user must end richer than they started");
    let cost = (before + OWED_ZHU)
        .checked_sub(after)
        .expect("the payout must have reached the user's own address");
    assert!(cost < OWED_ZHU, "the exit must cost less than it recovers");

    // ---- One signature per step, one transaction per step, across every
    // close. This is the invariant the durable record exists for.
    for step in [
        HvmRegistryExitStep::Challenge,
        HvmRegistryExitStep::Finalize,
        HvmRegistryExitStep::Claim,
    ] {
        let signed: Vec<_> = rig
            .shipped_signings
            .iter()
            .filter(|(taken, _, _)| *taken == step)
            .collect();
        assert!(!signed.is_empty(), "{step:?} was never signed at all");
        let (_, first_hash, first_timestamp) = signed[0];
        for (_, hash, timestamp) in &signed {
            assert_eq!(
                hash, first_hash,
                "{step:?} was signed as two different transactions"
            );
            assert_eq!(timestamp, first_timestamp, "{step:?} moved its timestamp");
        }
        let submitted: Vec<_> = rig
            .shipped_submissions
            .iter()
            .filter(|hash| *hash == first_hash)
            .collect();
        assert_eq!(
            submitted.len(),
            1,
            "{step:?} was put on the wire {} times",
            submitted.len()
        );
        println!(
            "  {step:?}: signed {} time(s), all as {} at timestamp {first_timestamp}; on the wire once",
            signed.len(),
            &first_hash[..16]
        );
    }
    let mut distinct = rig.shipped_submissions.clone();
    distinct.sort();
    distinct.dedup();
    assert_eq!(
        distinct.len(),
        rig.shipped_submissions.len(),
        "the shipped driver put the same bytes on the wire twice"
    );
    println!(
        "PAID: {OWED_ZHU} zhu recovered for {cost} zhu across {} wallet sessions, with the Hub \
         dead the whole time and the wallet closed twice mid-exit",
        rig.sessions
    );
}
