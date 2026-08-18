//! THE MANAGER DRIVES THE EXIT, AND THE OWNER IS PAID ON CHAIN.
//!
//! # What this is for
//!
//! `hacash_wallet_core::hvm_registry_exit_driver::advance_registry_exit` has
//! been proven on a real chain for some time, and until the change this test
//! accompanies its only caller in the entire tree was a test. A driver whose
//! only caller is a test is not a way out of a channel, and this workspace has
//! shipped that exact shape twice.
//!
//! So the subject here is deliberately **not** the driver. It is
//! [`AgentWalletManager::advance_hvm_registry_exit`] — the production method
//! the desktop command calls — driven against a real deployed
//! `hpay_channel_registry_v2` contract in real blocks, with a real Hub that is
//! started, used and then killed. Every signature the exit needs is produced
//! by the shipped signing boundary,
//! `AgentTransactionSigner::sign_exact_registry_exit`, from a key this test
//! never handles after setup: it is inside the wallet's own encrypted vault
//! and the manager reaches it through the ordinary unlocked session.
//!
//! # What the test is allowed to do that a user is not
//!
//! Two things, both setup and neither on the path being proven.
//!
//! 1. **It reads the wallet's own secret out of its own vault** to open,
//!    initialise and fund the channel. This is not a shortcut around the
//!    signer: it is the only way to have a registry channel whose left party
//!    is an Agent Wallet at all, because nothing in the shipped product opens
//!    one. That gap is real and is stated in the report accompanying this
//!    test; it is not what this test is about.
//! 2. **It writes the adopted binding through the manager's own journalled
//!    transition** rather than through `verify_and_bind_hvm_registry`, which
//!    needs a live HTTP fullnode. The state it writes is byte-for-byte the
//!    state adoption writes, built by the same
//!    `AgentHvmRegistryBinding::from_verified_status` and seeded with the same
//!    `AgentHvmRegistryExitHead::seed`.
//!
//! Everything after that point is production code. Nothing here weakens a
//! check, and nothing here signs.
//!
//! Nothing is broadcast. `testkit::sim::memchain` is an in-process chain on
//! chain id 7.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use field::Address;
use hacash_wallet_core::hvm_registry_exit_driver::{
    HvmRegistryExitChainV1, HvmRegistryExitSightingV1,
};
use l2_fast_pay_hub::HubState;
use l2_fast_pay_hub::hvm_pilot::{HvmLocalPilotNetwork, HvmPilotSignedTransaction};
use l2_fast_pay_hub::hvm_registry::{
    HPAY_REGISTRY_SETTLEMENT_PROFILE, HVM_REGISTRY_CHANNEL_KEY_COUNT,
    HVM_REGISTRY_LIVE_SNAPSHOT_SCHEMA, HVM_REGISTRY_STORAGE_KEY_COUNT, HvmRegistryBindingV2,
    HvmRegistryChannelStorageV2, HvmRegistryGlobalStorageV2, HvmRegistryLiveSnapshotV2,
    HvmRegistryRecoveryBundleV2, HvmRegistryRefundCountersignRequestV2,
};
use l2_fast_pay_hub::hvm_registry_ledger::{
    HVM_REGISTRY_CHANNEL_STATUS_SCHEMA, HvmRegistryChannelStatusV2,
};
use l2_fast_pay_hub::hvm_registry_pilot::{
    HvmRegistryPilotChannelParameters, build_hvm_registry_pilot_channel_init,
    build_hvm_registry_pilot_deployment, build_hvm_registry_pilot_exact_funding,
    build_hvm_registry_pilot_refund_countersign_request,
};
use l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding;
use l2_fast_pay_hub::node::HvmStorageEntry;
use sys::Account;
use testkit::sim::memchain::{MemChain, TxOutput};
use vm::ContractAddress;
use vm::value::Value;

use super::{AgentHvmRegistryBinding, AgentHvmRegistryExitHead};
use crate::journal::AgentJournalEventKind;
use crate::service::{AgentWalletManager, CreateAgentWallet};
use crate::types::AgentWalletId;

const PASSPHRASE: &str = "agent wallet passphrase 123";
const DEPOSIT_ZHU: u64 = 5_000_000_000;
const CHALLENGE_BLOCKS: u64 = 6;
const SETUP_FEE_ZHU: u64 = 500_000;
const GAS_MAX: u8 = u8::MAX;
const CHANNEL_ID: &str = "7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e7e";
const TESTNET_ANCHOR: &str = "000008c8c945c4ca797f5aa70530caa51030ee0037e76410fd113852d50f2dff";

// ---------------------------------------------------------------------------
// Chain plumbing, lifted unchanged from
// `crates/wallet-core/tests/kill_mid_exit_on_chain.rs`. Two copies of a reader
// would be two places to be wrong about the same eighteen storage keys, but
// that file is a test binary in another crate and has nothing to export.
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

fn confirm_wallet_bytes(
    chain: &mut MemChain,
    miner: Address,
    signed: &HvmPilotSignedTransaction,
    output: TxOutput,
) {
    let raw = hex::decode(&signed.signed_transaction_hex).expect("setup transaction is hex");
    let hash = chain
        .submit_signed_transaction_raw(&raw, output)
        .expect("chain accepted the setup transaction");
    assert_eq!(hex::encode(hash.as_bytes()), signed.transaction_hash);
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

async fn spawn_hub(
    hub: &Account,
    directory: &tempfile::TempDir,
) -> (String, Arc<HubState>, tokio::task::JoinHandle<()>) {
    let state_path: PathBuf = directory.path().join("hub-state.json");
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "pressable exit proof",
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
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(format!("HTTP {status}: {body}"));
    }
    response.json().await.map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// The chain, as the production driver asks to see it.
// ---------------------------------------------------------------------------

/// A `MemChain` behind the four read-or-submit methods the driver needs.
///
/// `RefCell` because the manager holds itself mutably while it holds this by
/// shared reference, exactly as the desktop holds an open wallet and an HTTP
/// client at the same time.
struct MemChainExitView {
    chain: RefCell<MemChain>,
    contract: ContractAddress,
    binding: HvmRegistryBindingV2,
    miner: Address,
    block_hashes: RefCell<HashMap<u64, String>>,
    mempool: RefCell<Vec<String>>,
    submissions: RefCell<Vec<String>>,
    /// Encoded size of every transaction this exit put on the wire.
    ///
    /// The chain reserves gas as `budget * fee / billing_size`, so the
    /// *smallest* exit transaction is the most expensive one to run. The
    /// affordability figure the owner is shown is derived from an assumed
    /// minimum size, and this is what proves that assumption is not larger
    /// than reality.
    encoded_sizes: RefCell<Vec<usize>>,
    /// When set, every read reports this many live blocks on the six shared
    /// registry globals, whatever the chain actually holds.
    ///
    /// This is a node that will not show the lease rising: a stale storage
    /// index, a forked follower, a hostile pin. It is the exact shape the
    /// unbounded-renewal drain took, and it is stated as a node behaviour
    /// rather than as a wallet behaviour because the wallet cannot tell the
    /// difference and must be safe either way.
    stalled_registry_lease: RefCell<Option<u64>>,
}

impl MemChainExitView {
    fn node_lookup(&self, transaction_hash: &str) -> Option<(u64, String)> {
        let chain = self.chain.borrow();
        chain
            .receipts()
            .iter()
            .find(|receipt| hex::encode(receipt.tx_hash.as_bytes()) == transaction_hash)
            .map(|receipt| {
                (
                    receipt.height,
                    self.block_hashes
                        .borrow()
                        .get(&receipt.height)
                        .cloned()
                        .expect("every mined height has a block hash"),
                )
            })
    }

    fn mine(&self) {
        let confirmed = self
            .chain
            .borrow_mut()
            .confirm_formal_block(self.miner)
            .expect("block executed");
        self.block_hashes.borrow_mut().insert(
            confirmed.height,
            hex::encode(confirmed.block_hash.as_bytes()),
        );
        self.mempool.borrow_mut().clear();
    }

    fn mine_empty_to(&self, height: u64) {
        assert!(self.mempool.borrow().is_empty());
        let mut chain = self.chain.borrow_mut();
        let first = chain.height() + 1;
        chain
            .confirm_empty_formal_blocks_to_height(self.miner, height)
            .expect("age the chain");
        let mut hashes = self.block_hashes.borrow_mut();
        for h in first..=height {
            hashes.entry(h).or_insert_with(|| "0".repeat(64));
        }
        hashes.insert(
            chain.height(),
            hex::encode(chain.last_block_hash().as_bytes()),
        );
    }

    fn settled(&self) -> bool {
        let left = Address::from_readable(&self.binding.left_address).unwrap();
        let chain = self.chain.borrow();
        chain.storage(&self.contract, &channel_key("c_status_", &left)) == Value::U8(4)
            && chain.storage(&self.contract, &channel_key("c_left_claimed_", &left))
                == Value::Bool(true)
    }

    fn balance_zhu(&self, address: &str) -> u64 {
        let address = Address::from_readable(address).unwrap();
        self.chain.borrow().balance(&address).to_zhu_u64().unwrap()
    }
}

impl HvmRegistryExitChainV1 for MemChainExitView {
    async fn registry_snapshot(
        &self,
    ) -> Result<HvmRegistryLiveSnapshotV2, hacash_wallet_core::WalletError> {
        let mut snapshot = read_snapshot(&self.chain.borrow(), &self.contract, &self.binding);
        if let Some(stalled) = *self.stalled_registry_lease.borrow() {
            let registry = &mut snapshot.registry;
            registry.g_network.live_blocks = stalled;
            registry.g_hub.live_blocks = stalled;
            registry.g_locked.live_blocks = stalled;
            registry.g_left_claimable.live_blocks = stalled;
            registry.g_hub_claimable.live_blocks = stalled;
            registry.g_open_count.live_blocks = stalled;
        }
        Ok(snapshot)
    }

    async fn chain_tip(&self) -> Result<(u64, u64), hacash_wallet_core::WalletError> {
        Ok((self.chain.borrow().height(), 0))
    }

    async fn transaction_sighting(
        &self,
        hash: &str,
    ) -> Result<HvmRegistryExitSightingV1, hacash_wallet_core::WalletError> {
        if let Some((block_height, block_hash)) = self.node_lookup(hash) {
            return Ok(HvmRegistryExitSightingV1::Mined {
                block_height,
                block_hash,
            });
        }
        if self.mempool.borrow().iter().any(|pending| pending == hash) {
            return Ok(HvmRegistryExitSightingV1::Pending);
        }
        Ok(HvmRegistryExitSightingV1::Unknown)
    }

    async fn submit_exit_transaction(
        &self,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> Result<(), hacash_wallet_core::WalletError> {
        if self.node_lookup(transaction_hash).is_some()
            || self
                .mempool
                .borrow()
                .iter()
                .any(|pending| pending == transaction_hash)
        {
            return Ok(());
        }
        let raw = hex::decode(signed_transaction_hex).expect("exit transaction is hex");
        let hash = self
            .chain
            .borrow_mut()
            .submit_signed_transaction_raw(&raw, TxOutput::None)
            .map_err(|error| hacash_wallet_core::WalletError::L2(format!("{error:?}")))?;
        assert_eq!(
            hex::encode(hash.as_bytes()),
            transaction_hash,
            "the chain must agree with the wallet about the transaction hash"
        );
        self.encoded_sizes.borrow_mut().push(raw.len());
        self.mempool.borrow_mut().push(transaction_hash.to_owned());
        self.submissions
            .borrow_mut()
            .push(transaction_hash.to_owned());
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The proof.
// ---------------------------------------------------------------------------

/// A real Agent Wallet, a real contract, a real Hub that is then killed, and
/// the manager's own exit drive walking the owner out with their own key.
#[tokio::test]
async fn the_managers_own_exit_drive_pays_the_owner_on_chain_with_the_hub_dead() {
    // Protocol setup is global and install-once, and this test shares a binary
    // with 282 others that also touch it. So all three steps are stated
    // explicitly rather than relying on which test happened to run first: the
    // Hub crate installs its protocol registry, MemChain builds its chain, and
    // the VM assigner is then set unconditionally. Leaving that last step to
    // `MemChain::new` alone is what makes this test pass alone and fail inside
    // the suite.
    let network = HvmLocalPilotNetwork::canonical();
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let mut chain = MemChain::new();
    testkit::sim::integration::enable_default_vm_setup();
    chain.set_chain_id(network.chain_id);
    chain.set_height(protocol::upgrade::ONLINE_OPEN_HEIGHT);

    let hub = Account::create_by("pressable-exit-hub").unwrap();
    let miner = addr(&Account::create_by("pressable-exit-miner").unwrap());

    // ---- a real Agent Wallet, created and unlocked through the manager ----
    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    // Real wall-clock time: the Hub validates the refund ask against its own
    // clock, so a fixed timestamp would be an ask that expired years ago.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.into(),
                network_mode: "testnet".into(),
                node_url: "http://127.0.0.1:18081".into(),
                block_one_fingerprint: Some(TESTNET_ANCHOR.into()),
                mainnet_pilot_acknowledgement: None,
            },
            now,
        )
        .unwrap();
    let wallet_id: AgentWalletId = created.wallet_id.clone();
    manager.unlock(&wallet_id, PASSPHRASE, now).unwrap();

    // Setup only: the channel's left party has to be this wallet, and nothing
    // in the shipped product opens a registry channel, so the test opens one
    // with the wallet's own key. Nothing below this block touches the key
    // again - every exit signature comes from the manager's signing boundary.
    let left = {
        let paths = manager.storage.paths(&wallet_id).unwrap();
        let vault = crate::vault::AgentEncryptedVault::load(&paths.vault_path()).unwrap();
        let secrets = vault.unlock(PASSPHRASE).unwrap();
        hacash_wallet_core::account::WalletAccount::from_secret_hex(secrets.blockchain_secret_hex())
            .unwrap()
            .inner()
            .clone()
    };
    assert_eq!(left.readable(), created.address);

    for account in [&hub, &left] {
        chain.mint_hac(&addr(account), 30_000_000_000_000);
    }

    // ---- a real deployment, a real channel, a real deposit ----
    let deployment =
        build_hvm_registry_pilot_deployment(&hub, &network, SETUP_FEE_ZHU, 100, GAS_MAX).unwrap();
    let contract =
        ContractAddress::from_addr(Address::from_readable(&deployment.contract_address).unwrap())
            .unwrap();
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
        SETUP_FEE_ZHU,
        101,
        GAS_MAX,
    )
    .unwrap();
    confirm_wallet_bytes(&mut chain, miner, &init, TxOutput::None);

    // ---- a real Hub, alive exactly long enough to countersign the refund ----
    let hub_directory = tempfile::tempdir().unwrap();
    let (hub_url, hub_state, hub_server) = spawn_hub(&hub, &hub_directory).await;
    let ask = build_hvm_registry_pilot_refund_countersign_request(
        &left,
        hub.readable(),
        &deployment,
        deployment_height,
        &parameters(),
        now,
        now + 300,
    )
    .unwrap();
    let answer = ask_hub(&hub_url, &ask).await.expect("Hub countersigned");
    let bundle: HvmRegistryRecoveryBundleV2 = ask
        .attach_hub_countersignature(&answer.hub_refund_signature_hex)
        .expect("the Hub signature verifies against the wallet's own binding");
    let binding = bundle.binding.clone();

    let funding = build_hvm_registry_pilot_exact_funding(
        &left,
        &bundle,
        &network,
        SETUP_FEE_ZHU,
        102,
        GAS_MAX,
    )
    .unwrap();
    confirm_wallet_bytes(&mut chain, miner, &funding, TxOutput::None);
    assert_eq!(
        chain.balance(&contract.to_addr()).to_zhu_u64(),
        Ok(DEPOSIT_ZHU),
        "the deposit is inside the contract"
    );

    // ---- the adopted binding, written exactly as adoption writes it ----

    let status = HvmRegistryChannelStatusV2 {
        schema: HVM_REGISTRY_CHANNEL_STATUS_SCHEMA.into(),
        binding_commitment: binding.commitment().unwrap(),
        recovery_bundle: bundle.clone(),
        activation_snapshot_commitment: hex::encode([0x5c; 32]),
        minimum_required_live_blocks: 1,
        minimum_required_recover_blocks: 1,
        latest_fully_signed_bill: bundle.initial_recovery_bill.clone(),
        latest_anchor_receipts: Vec::new(),
        activated_unix: now,
        updated_unix: now,
    };
    let network_binding = L1ChannelNetworkBinding::from_node_identity(
        &network.network_kind,
        false,
        network.chain_id,
        &network.block_1_hash,
        &network.node_profile_id,
        Some(&network.network_instance_id),
        2,
    )
    .unwrap();
    let adopted = AgentHvmRegistryBinding::from_verified_status(
        wallet_id.clone(),
        &created.address,
        "testnet",
        network_binding,
        hub_url.clone(),
        hub.readable().to_owned(),
        status,
        now,
    )
    .expect("the binding this wallet would adopt");
    {
        let (state_master, journal_key) = {
            let session = manager.session(&wallet_id).unwrap();
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let mut state = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        state.hvm_registry_exit_head = Some(AgentHvmRegistryExitHead::seed(&adopted, now));
        state.hvm_registry_binding = Some(adopted);
        state.updated_at = now;
        manager
            .persist_event(
                &mut state,
                &state_master,
                &journal_key,
                AgentJournalEventKind::HvmBindingVerified,
                None,
                None,
                now,
            )
            .unwrap();
    }

    // ---- kill the Hub. Everything from here happens without it. ----
    hub_server.abort();
    drop(hub_state);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        ask_hub(&hub_url, &ask).await.is_err(),
        "this proof is worthless unless the Hub is actually dead"
    );

    let view = MemChainExitView {
        chain: RefCell::new(chain),
        contract,
        binding: binding.clone(),
        miner,
        block_hashes: RefCell::new(HashMap::new()),
        mempool: RefCell::new(Vec::new()),
        submissions: RefCell::new(Vec::new()),
        encoded_sizes: RefCell::new(Vec::new()),
        stalled_registry_lease: RefCell::new(None),
    };
    // ---- the renewal drain, closed ----
    //
    // A node that will not show the shared registry lease rising used to turn
    // this button into an unbounded drain: the planner answers a lease below
    // the exit floor by renewing, the driver gives a terminal renewal record a
    // fresh attempt number, and the fresh attempt derives fresh bytes at a
    // fresh fee. Measured by a reviewer at roughly 234,000,000 zhu a press
    // against this same 5,000,000,000 zhu deposit, with the exit never
    // starting and nothing anywhere to stop it.
    //
    // Driven here through the same production method the exit itself uses, so
    // this is the button's behaviour and not a driver unit test.
    *view.stalled_registry_lease.borrow_mut() = Some(1);
    let drain_start = view.balance_zhu(&created.address);
    let first = manager
        .advance_hvm_registry_exit(&wallet_id, &view, now)
        .await
        .expect("a genuinely short lease is renewed once");
    assert_eq!(first.outcome, "stepped");
    assert_eq!(first.step.as_deref(), Some("renew_registry_lease"));
    assert_eq!(
        view.submissions.borrow().len(),
        1,
        "the first renewal is legitimate and is sent"
    );
    view.mine();

    // One more pass records the confirmation. It touches no key and spends
    // nothing: the record already held exact bytes, so this arm only looks the
    // hash up and writes down the block it landed in.
    let confirming = manager
        .advance_hvm_registry_exit(&wallet_id, &view, now)
        .await
        .expect("the renewal's own confirmation is recorded");
    assert_eq!(confirming.phase.as_deref(), Some("confirmed"));
    assert_eq!(view.submissions.borrow().len(), 1);

    // Press again, and again. The chain says the lease is no higher than it
    // was before the renewal this wallet already paid for, so the renewal is
    // not working and a second one at the same price will not work either.
    for press in 3..=7 {
        let refusal = manager
            .advance_hvm_registry_exit(&wallet_id, &view, now)
            .await
            .expect_err("a renewal that is not taking effect must not be bought again");
        let sentence = refusal.to_string();
        assert!(
            sentence.contains("renewal is not taking effect"),
            "press {press} refused without saying why: {sentence}"
        );
        assert!(
            sentence.contains("renew_registry_lease"),
            "press {press} refused without naming the step: {sentence}"
        );
        assert_eq!(
            view.submissions.borrow().len(),
            1,
            "press {press} spent another fee on a renewal that is not working"
        );
    }
    println!("  renewal drain: 8 presses -> 1 transaction, then {}", {
        let refusal = manager
            .advance_hvm_registry_exit(&wallet_id, &view, now)
            .await
            .expect_err("still refused");
        refusal.to_string()
    });
    let drain_cost = drain_start - view.balance_zhu(&created.address);
    assert!(
        drain_cost < DEPOSIT_ZHU / 10,
        "the bounded renewal still cost {drain_cost} zhu"
    );

    // The refusal was about what the node reported, not about the chain: with
    // the node telling the truth again the lease is well clear of the floor
    // and the exit proceeds, which is what makes this a bound on spending
    // rather than a wallet that has locked itself out.
    *view.stalled_registry_lease.borrow_mut() = None;

    let before = view.balance_zhu(&created.address);

    // ---- the production drive, one press at a time ----
    let mut passes = 0_u32;
    let claimed = loop {
        passes += 1;
        assert!(passes < 40, "the manager's exit drive did not terminate");
        let progress = manager
            .advance_hvm_registry_exit(&wallet_id, &view, now)
            .await
            .expect("the manager drives its own exit");
        println!(
            "  pass {passes}: {} {:?} {:?} fees confirmed {} at risk {}",
            progress.outcome,
            progress.step,
            progress.waiting_reason,
            progress.network_fees_confirmed_zhu,
            progress.network_fees_at_risk_zhu
        );
        match progress.outcome.as_str() {
            "complete" => {
                break progress
                    .claimed_zhu
                    .expect("a complete exit names its payout");
            }
            "stepped" => {
                if !view.mempool.borrow().is_empty() {
                    view.mine();
                }
            }
            "waiting" => {
                if !view.mempool.borrow().is_empty() {
                    view.mine();
                    continue;
                }
                if view.settled() {
                    continue;
                }
                let status = progress.channel_status.expect("waiting names the status");
                let deadline = progress
                    .deadline_height
                    .expect("waiting names the deadline");
                let height = view.chain.borrow().height();
                if status == 3 && deadline > height {
                    // A laptop cannot mine blocks. This is the objection
                    // window passing, which is what an exit spends most of its
                    // life waiting for.
                    view.mine_empty_to(deadline);
                    continue;
                }
                panic!(
                    "the exit stalled: {:?}",
                    progress.waiting_reason.unwrap_or_default()
                );
            }
            other => panic!("unknown outcome {other}"),
        }
    };

    // ---- the owner is paid, on chain, from their own key alone ----
    assert!(
        view.settled(),
        "the channel is FINAL and the payout is made"
    );
    assert_eq!(
        claimed, DEPOSIT_ZHU,
        "the exit pays this wallet its whole settled balance"
    );
    let after = view.balance_zhu(&created.address);
    let contract_after = view
        .chain
        .borrow()
        .balance(&view.contract.to_addr())
        .to_zhu_u64()
        .unwrap();
    assert_eq!(
        contract_after, 0,
        "the deposit left the contract; nothing of this channel's principal is still inside it"
    );
    assert!(
        after > before,
        "the exit has to leave the owner better off than not running it: {before} -> {after}"
    );
    let recovered = after - before;
    let cost = DEPOSIT_ZHU - recovered;
    println!(
        "  recovered {recovered} zhu of a {DEPOSIT_ZHU} zhu deposit; the chain charged \
         {cost} zhu in fees and gas across {} transactions",
        view.submissions.borrow().len()
    );
    assert!(
        recovered <= DEPOSIT_ZHU,
        "the exit cannot pay the owner more than the channel settled at"
    );
    // The affordability figure the owner is shown before the irreversible
    // press is derived from an assumed minimum transaction size, because the
    // chain reserves gas as `budget * fee / billing_size` and a smaller
    // transaction therefore reserves more. If a real exit transaction is ever
    // smaller than the assumption, the quote silently under-states what the
    // owner must hold, which is the direction that sends someone into a press
    // they cannot finish.
    let sizes = view.encoded_sizes.borrow().clone();
    println!("  encoded exit transaction sizes: {sizes:?}");
    let smallest = sizes.iter().copied().min().expect("the exit sent bytes");
    assert!(
        smallest as u64 >= super::AGENT_REGISTRY_EXIT_MIN_BILLING_BYTES,
        "an exit transaction encoded to {smallest} bytes, below the          {} the fee quote assumes; the quote now under-states the gas reserve",
        super::AGENT_REGISTRY_EXIT_MIN_BILLING_BYTES
    );
    assert!(
        cost < DEPOSIT_ZHU / 10,
        "the exit cost {cost} zhu to recover {DEPOSIT_ZHU} zhu, which is not worth pressing"
    );

    // One transaction per step, and never two for one step.
    let submissions = view.submissions.borrow().clone();
    let mut unique = submissions.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        submissions.len(),
        unique.len(),
        "no transaction was submitted twice under a different hash for the same step"
    );

    // Pressing again after the exit is finished must not spend another fee.
    let again = manager
        .advance_hvm_registry_exit(&wallet_id, &view, now)
        .await
        .expect("a finished exit answers rather than refusing");
    assert_eq!(again.outcome, "complete");
    assert_eq!(
        view.submissions.borrow().len(),
        submissions.len(),
        "a second press on a finished exit put nothing further on the wire"
    );
}

// ---------------------------------------------------------------------------
// The chain, as OPENING and FUNDING a channel ask to see it.
//
// Same `MemChain`, same struct: the full circle needs one chain that the open,
// the funding, the adoption and the exit all see, and two views of two chains
// would prove nothing about the sequence.
// ---------------------------------------------------------------------------

impl hacash_wallet_core::hvm_registry_open::HvmRegistryOpenChainV1 for MemChainExitView {
    async fn network_binding(
        &self,
    ) -> Result<L1ChannelNetworkBinding, hacash_wallet_core::WalletError> {
        let network = HvmLocalPilotNetwork::canonical();
        L1ChannelNetworkBinding::from_node_identity(
            &network.network_kind,
            false,
            network.chain_id,
            &network.block_1_hash,
            &network.node_profile_id,
            Some(&network.network_instance_id),
            2,
        )
        .map_err(|error| hacash_wallet_core::WalletError::Node(error.to_string()))
    }

    async fn registry_snapshot(
        &self,
        binding: &HvmRegistryBindingV2,
    ) -> Result<HvmRegistryLiveSnapshotV2, hacash_wallet_core::WalletError> {
        let contract =
            ContractAddress::from_addr(Address::from_readable(&binding.contract_address).map_err(
                |_| hacash_wallet_core::WalletError::Node("contract address is unreadable".into()),
            )?)
            .map_err(|_| hacash_wallet_core::WalletError::Node("not a contract address".into()))?;
        Ok(read_snapshot(&self.chain.borrow(), &contract, binding))
    }

    async fn submit_funding_transaction(
        &self,
        _binding: &HvmRegistryBindingV2,
        signed_transaction_hex: &str,
        transaction_hash: &str,
    ) -> Result<(), hacash_wallet_core::WalletError> {
        HvmRegistryExitChainV1::submit_exit_transaction(
            self,
            signed_transaction_hex,
            transaction_hash,
        )
        .await
    }

    async fn funding_sighting(
        &self,
        transaction_hash: &str,
    ) -> Result<HvmRegistryExitSightingV1, hacash_wallet_core::WalletError> {
        HvmRegistryExitChainV1::transaction_sighting(self, transaction_hash).await
    }
}

/// THE FULL CIRCLE, through the production path, with the provider killed.
///
/// A real Agent Wallet opens a provider channel, pays the deposit into a real
/// deployed contract in real blocks, adopts the channel **without asking the
/// provider anything**, and then - with the provider's process aborted and its
/// socket asserted dead - drives its own unilateral exit until the contract
/// holds nothing and the owner has been paid from their own key.
///
/// # What is production here, and what is setup
///
/// Setup is the *provider's* side and nothing else: the Hub deploys the
/// registry and co-signs the channel `init`, because that is what a provider
/// does and there is no wallet-side story in which the user does it. The
/// wallet's key is never handled by this test at any point: it is created
/// inside the vault by `create_wallet` and every signature below comes out of
/// the manager's own signing boundaries.
///
/// The hop this test exists to prove did not exist when the exit proof beside
/// it was written. That one had to read the wallet's secret out of its own
/// vault to fund, and had to write the adopted binding directly into state,
/// because nothing shipped could do either. Both of those are now method calls
/// on `AgentWalletManager`:
///
/// * `open_hvm_registry_channel`
/// * `fund_hvm_registry_channel`
/// * `adopt_hvm_registry_channel_from_chain`
/// * `advance_hvm_registry_exit`
///
/// Nothing is broadcast. `testkit::sim::memchain` is an in-process chain on
/// chain id 7.
#[tokio::test]
async fn a_wallet_opens_pays_and_walks_out_with_the_provider_deleted() {
    let network = HvmLocalPilotNetwork::canonical();
    l2_fast_pay_hub::protocol_registry::ensure_hacash_protocol_setup();
    let mut chain = MemChain::new();
    testkit::sim::integration::enable_default_vm_setup();
    chain.set_chain_id(network.chain_id);
    chain.set_height(protocol::upgrade::ONLINE_OPEN_HEIGHT);

    let hub = Account::create_by("full-circle-hub").unwrap();
    let miner = addr(&Account::create_by("full-circle-miner").unwrap());

    let root = tempfile::tempdir().unwrap();
    let mut manager = AgentWalletManager::open(root.path()).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let created = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: PASSPHRASE.into(),
                network_mode: "testnet".into(),
                node_url: "http://127.0.0.1:18081".into(),
                // The wallet is pinned to the chain this test actually runs,
                // and the open path refuses a node whose block 1 is not this.
                block_one_fingerprint: Some(network.block_1_hash.clone()),
                mainnet_pilot_acknowledgement: None,
            },
            now,
        )
        .unwrap();
    let wallet_id: AgentWalletId = created.wallet_id.clone();
    manager.unlock(&wallet_id, PASSPHRASE, now).unwrap();

    chain.mint_hac(&addr(&hub), 30_000_000_000_000);
    chain.mint_hac(
        &Address::from_readable(&created.address).unwrap(),
        30_000_000_000_000,
    );

    // ---- the provider's side: a real deployment and a real channel init ----
    let deployment =
        build_hvm_registry_pilot_deployment(&hub, &network, SETUP_FEE_ZHU, 100, GAS_MAX).unwrap();
    let contract =
        ContractAddress::from_addr(Address::from_readable(&deployment.contract_address).unwrap())
            .unwrap();
    confirm_wallet_bytes(
        &mut chain,
        miner,
        &deployment.transaction,
        TxOutput::ContractAddress(contract.clone()),
    );
    let deployment_height = chain.height();

    // `init` is co-signed, so the wallet's key is needed for it and only for
    // it. This is the provider's half of the setup and is the one place the
    // test opens the vault; nothing on the path being proven does.
    let left = {
        let paths = manager.storage.paths(&wallet_id).unwrap();
        let vault = crate::vault::AgentEncryptedVault::load(&paths.vault_path()).unwrap();
        let secrets = vault.unlock(PASSPHRASE).unwrap();
        hacash_wallet_core::account::WalletAccount::from_secret_hex(secrets.blockchain_secret_hex())
            .unwrap()
            .inner()
            .clone()
    };
    assert_eq!(left.readable(), created.address);
    let init = build_hvm_registry_pilot_channel_init(
        &left,
        &hub,
        &deployment.contract_address,
        &network,
        &parameters(),
        SETUP_FEE_ZHU,
        101,
        GAS_MAX,
    )
    .unwrap();
    confirm_wallet_bytes(&mut chain, miner, &init, TxOutput::None);

    // The channel description the provider publishes and the owner hands in.
    let binding = HvmRegistryBindingV2 {
        schema: l2_fast_pay_hub::hvm_registry::HVM_REGISTRY_BINDING_SCHEMA.into(),
        settlement_profile: HPAY_REGISTRY_SETTLEMENT_PROFILE.into(),
        network_mode: "testnet".into(),
        chain_id: network.chain_id,
        network_instance_id: network.network_instance_id.clone(),
        contract_address: deployment.contract_address.clone(),
        deployment_tx_hash: deployment.transaction.transaction_hash.clone(),
        deployment_height,
        bytecode_sha3: deployment.bytecode_sha3.clone(),
        channel_id: CHANNEL_ID.into(),
        reuse_version: 0,
        left_address: created.address.clone(),
        right_hub_address: hub.readable().to_owned(),
        left_deposit_zhu: DEPOSIT_ZHU,
        right_hub_deposit_zhu: 0,
        challenge_blocks: CHALLENGE_BLOCKS,
    };
    binding.validate().expect("a reviewed-profile channel");

    let view = MemChainExitView {
        chain: RefCell::new(chain),
        contract: contract.clone(),
        binding: binding.clone(),
        miner,
        block_hashes: RefCell::new(HashMap::new()),
        mempool: RefCell::new(Vec::new()),
        submissions: RefCell::new(Vec::new()),
        encoded_sizes: RefCell::new(Vec::new()),
        stalled_registry_lease: RefCell::new(None),
    };

    // ---- HOP 1: the owner presses "open a channel with this provider" ----
    let hub_directory = tempfile::tempdir().unwrap();
    let (hub_url, hub_state, hub_server) = spawn_hub(&hub, &hub_directory).await;

    // Before the press: nothing may fund, and the reason is the refund, not
    // the chain.
    let refused = manager
        .hvm_registry_funding_authorization(&wallet_id, &view, now)
        .await
        .expect_err("no refund, no funding");
    assert!(
        matches!(
            refused,
            crate::error::AgentWalletError::RegistryOpenRefundNotCountersigned
        ),
        "unexpected refusal before the open: {refused}"
    );

    let bundle = manager
        .open_hvm_registry_channel(&wallet_id, &hub_url, binding.clone(), &view, now)
        .await
        .expect("the provider countersigns the serial-1 full refund");
    assert_eq!(bundle.initial_recovery_bill.serial, 1);
    assert_eq!(
        bundle.initial_recovery_bill.left_balance_zhu, DEPOSIT_ZHU,
        "the bill this wallet now holds returns the entire deposit"
    );
    assert_eq!(bundle.initial_recovery_bill.hub_balance_zhu, 0);

    // ---- HOP 2: the deposit ----
    let owner_before_funding = view.balance_zhu(&created.address);
    let pending = manager
        .fund_hvm_registry_channel(&wallet_id, &view, now)
        .await
        .expect_err("the bytes are on the wire and not yet in a block");
    assert!(
        matches!(
            pending,
            crate::error::AgentWalletError::RegistryFundingNotConfirmed
        ),
        "unexpected refusal while funding was pending: {pending}"
    );
    assert_eq!(
        view.submissions.borrow().len(),
        1,
        "exactly one funding transaction was put on the wire"
    );
    // Durable before the wire: the record exists while the transaction is
    // still only in a mempool.
    let stored = manager
        .hvm_registry_channel_open(&wallet_id, now)
        .unwrap()
        .expect("the open record");
    let funding_hash = stored
        .funding()
        .expect("funding is durable")
        .transaction_hash()
        .to_owned();
    assert!(!stored.funding().unwrap().is_confirmed());

    view.mine();
    let funded = manager
        .fund_hvm_registry_channel(&wallet_id, &view, now)
        .await
        .expect("the deposit is in a block");
    assert!(funded.is_confirmed());
    assert_eq!(funded.transaction_hash(), funding_hash);
    assert_eq!(funded.amount_zhu(), DEPOSIT_ZHU);
    assert_eq!(
        view.submissions.borrow().len(),
        1,
        "pressing again must never sign a second transfer into one channel"
    );
    assert_eq!(
        view.chain
            .borrow()
            .balance(&contract.to_addr())
            .to_zhu_u64(),
        Ok(DEPOSIT_ZHU),
        "the deposit is inside the contract"
    );
    println!(
        "  FUNDED: owner {} -> {} zhu, contract holds {} zhu, tx {}",
        owner_before_funding,
        view.balance_zhu(&created.address),
        DEPOSIT_ZHU,
        funding_hash
    );

    // A channel that has taken coin cannot be funded a second time by any
    // route: the gate itself refuses, because the chain no longer shows the
    // exact unfunded channel the refund is signed over.
    let second = manager
        .hvm_registry_funding_authorization(&wallet_id, &view, now)
        .await
        .expect_err("a funded channel is not fundable again");
    assert!(
        matches!(
            second,
            crate::error::AgentWalletError::RegistryOpenChainMismatch
        ),
        "unexpected refusal on a funded channel: {second}"
    );

    // ---- HOP 3: adoption, with the provider ALREADY dead ----
    //
    // This is the trap a reviewer drove: an honest countersignature, an honest
    // deposit, and then a provider that vanishes before the wallet ever adopts.
    // The chain would pay; the wallet had no path to it.
    hub_server.abort();
    drop(hub_state);
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let dead_ask = build_hvm_registry_pilot_refund_countersign_request(
        &left,
        hub.readable(),
        &deployment,
        deployment_height,
        &parameters(),
        now,
        now + 300,
    )
    .unwrap();
    assert!(
        ask_hub(&hub_url, &dead_ask).await.is_err(),
        "this proof is worthless unless the provider is actually dead"
    );

    // A wallet is created with agent payments suspended and adoption requires
    // it, so nothing has to be done here; this asserts it rather than assuming.
    {
        let (state_master, journal_key) = {
            let session = manager.session(&wallet_id).unwrap();
            (
                zeroize::Zeroizing::new(*session.state_master),
                zeroize::Zeroizing::new(*session.journal_key),
            )
        };
        let state = manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap();
        assert!(
            state.payments_suspended,
            "adoption requires agent payments suspended"
        );
    }
    let adopted = manager
        .adopt_hvm_registry_channel_from_chain(&wallet_id, &view, now)
        .await
        .expect("the wallet adopts its own funded channel from the chain alone");
    assert_eq!(adopted.hub_address(), hub.readable());
    assert_eq!(
        adopted.recovery_bundle(),
        &bundle,
        "the adopted evidence is the bundle this wallet built and validated itself"
    );
    let kit = manager
        .hvm_registry_exit_kit(&wallet_id)
        .expect("the exit head was seeded in the same transition");
    assert_eq!(kit.latest_bill.serial, 1);

    // ---- HOP 4: the exit, already proven, now reachable ----
    let before = view.balance_zhu(&created.address);
    let mut passes = 0;
    let mut fees;
    let claimed = loop {
        passes += 1;
        assert!(passes < 60, "the exit did not finish");
        let progress = manager
            .advance_hvm_registry_exit(&wallet_id, &view, now)
            .await
            .expect("a pass of the owner's own exit");
        fees = progress.network_fees_confirmed_zhu;
        match progress.outcome.as_str() {
            "complete" => {
                break progress
                    .claimed_zhu
                    .expect("a complete exit names its payout");
            }
            "stepped" => {
                if !view.mempool.borrow().is_empty() {
                    view.mine();
                }
            }
            "waiting" => {
                if !view.mempool.borrow().is_empty() {
                    view.mine();
                    continue;
                }
                if view.settled() {
                    continue;
                }
                let status = progress.channel_status.expect("waiting names the status");
                let deadline = progress
                    .deadline_height
                    .expect("waiting names the deadline");
                let height = view.chain.borrow().height();
                if status == 3 && deadline > height {
                    view.mine_empty_to(deadline);
                    continue;
                }
                panic!(
                    "the exit stalled: {:?}",
                    progress.waiting_reason.unwrap_or_default()
                );
            }
            other => panic!("unknown outcome {other}"),
        }
    };
    assert_eq!(
        claimed, DEPOSIT_ZHU,
        "the exit pays this wallet its whole settled balance"
    );

    let after = view.balance_zhu(&created.address);
    assert_eq!(
        view.chain
            .borrow()
            .balance(&contract.to_addr())
            .to_zhu_u64(),
        Ok(0),
        "the contract must hold nothing when the owner has walked out"
    );
    assert!(
        after > before,
        "the owner was not paid: {before} -> {after} zhu"
    );
    println!(
        "  EXITED with the provider deleted: owner {before} -> {after} zhu (+{}), contract 0 zhu, \
         confirmed fees {fees} zhu, {passes} passes",
        after - before
    );
    println!(
        "  FULL CIRCLE: open -> fund -> adopt (no provider) -> exit -> paid, all through \
         AgentWalletManager."
    );
}
