//! THE EXIT, ON A REAL CHAIN, WITH THE HUB DEAD.
//!
//! Everything here is `#[ignore]`. A plain `cargo test` does not run it: it
//! needs a real chain-7 fullnode listening, real mined blocks, real coin at a
//! real address, and minutes of wall clock waiting for confirmations. It is an
//! instrument, not a gate.
//!
//! Nothing is mocked. The node is the private HPAY Local Pilot `fullnode.exe`
//! on chain 7. The Hub is the real [`l2_fast_pay_hub::HubState`] behind the
//! real [`l2_fast_pay_hub::build_router`], served over real HTTP on a real TCP
//! port, exactly as `fast-pay-hub.exe` serves it. The wallet is the real
//! [`AgentWalletManager`], and every step below is a shipped method: the
//! channel is opened by `prepare_l2_channel_setup` / `confirm_l2_channel_setup`,
//! the voucher is taken by `take_l2_channel_close_voucher`, the payment runs
//! the shipped intent / mobile-approval / sign / submit chain, and the exit is
//! broadcast by `broadcast_l2_channel_close_voucher`.
//!
//! NO REAL VALUE. Chain 7 is a private development network: `chain.id` is 7
//! and `chain.mainnet` is false, and every function here that touches the node
//! re-reads `/query/capabilities` and refuses anything else, so it can never
//! be pointed at Hacash mainnet.
//!
//! THE TRUST, undressed. The Hub countersigns the voucher once, at the start,
//! and nothing in Hacash can compel it to. If it refuses, the deposit is
//! stuck. There is a genuine hostage window between the open confirming and
//! the voucher arriving. Afterwards the Hub carries the whole exposure: the
//! owner can spend the channel down and still recover the balances recorded at
//! open. That is acceptable here only because the owner runs the Hub. Nothing
//! on this path is trustless.
//!
//! Environment:
//!
//! * `HPAY_LIVE_NODE_URL`     - default `http://127.0.0.1:8197`.
//! * `HPAY_LIVE_WORKDIR`      - required. Keep it SHORT: the wallet applies a
//!   Windows ACL to every file it writes and `SetFileSecurityW` fails once the
//!   full path passes 260 characters.
//! * `HPAY_LIVE_FUNDING_DPAPI` - required. The DPAPI identity file holding the
//!   funded chain-7 address that pays the owner wallet its deposit. It is used
//!   for exactly one L1 transfer and never again.
//! * `HPAY_LIVE_DEPOSIT_HAC`  - optional, default `1`.
//! * `HPAY_LIVE_FUND_HAC`     - optional, default `1.5`.
//! * `HPAY_LIVE_WAIT_SECS`    - optional, default `2400`.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

// Only the Windows funding path drives a second WalletService; the
// non-Windows `fund_owner_address` panics on the DPAPI requirement.
#[cfg(windows)]
use hacash_wallet_core::WalletService;
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::l1_channel_close_safety::verify_channel_close_voucher_bytes;
use hpay_companion_protocol::{
    AgentFastPayApprovalDecision, DeviceRole, SignedAgentFastPayApprovalDecision,
    SoftwareDeviceIdentity,
};
use l2_fast_pay_hub::{HubState, build_router};

use super::*;
use crate::fast_pay_operation::{AgentFastPayRequest, AgentFastPayStatus};
use crate::service::AgentAuthorization;
use crate::service::l2::AgentChannelCloseVoucherPhase;

const OWNER_PASSPHRASE: &str = "chain7 live voucher owner passphrase";
#[cfg(windows)]
const FUNDER_PASSPHRASE: &str = "chain7 live voucher funder passphrase";

fn optional_env(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} must be set; see the module docs at the top of this file")
    })
}

fn node_url() -> String {
    optional_env("HPAY_LIVE_NODE_URL", "http://127.0.0.1:8197")
}

fn workdir() -> PathBuf {
    let dir = PathBuf::from(required_env("HPAY_LIVE_WORKDIR"));
    std::fs::create_dir_all(&dir).expect("workdir");
    dir
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Re-read the node's own capability document and refuse anything that is not
/// the private chain-7 pilot. Called before every stage that touches the node,
/// every time, never once at the top.
async fn require_chain_seven(label: &str) -> serde_json::Value {
    let url = node_url();
    let capabilities: serde_json::Value = reqwest::get(format!("{url}/query/capabilities"))
        .await
        .expect("pilot fullnode is not reachable")
        .json()
        .await
        .expect("capability document");
    assert_eq!(
        capabilities["chain"]["id"].as_u64(),
        Some(7),
        "[{label}] this instrument only runs on private chain 7"
    );
    assert_eq!(
        capabilities["chain"]["mainnet"].as_bool(),
        Some(false),
        "[{label}] this instrument must never be pointed at a mainnet node"
    );
    assert_eq!(
        capabilities["network"]["kind"].as_str(),
        Some("local_pilot_v1"),
        "[{label}] not the Local Pilot network"
    );
    println!(
        "[node/{label}] chain id {} mainnet {} kind {} height {}",
        capabilities["chain"]["id"],
        capabilities["chain"]["mainnet"],
        capabilities["network"]["kind"],
        capabilities["chain"]["height"]
    );
    capabilities
}

async fn chain_height() -> u64 {
    let url = node_url();
    let capabilities: serde_json::Value = reqwest::get(format!("{url}/query/capabilities"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    capabilities["chain"]["height"].as_u64().unwrap()
}

async fn block_one_hash() -> String {
    let url = node_url();
    let block: serde_json::Value = reqwest::get(format!("{url}/query/block/intro?height=1"))
        .await
        .expect("block 1")
        .json()
        .await
        .expect("block 1 document");
    block["hash"].as_str().expect("block 1 hash").to_owned()
}

/// Whole Zhu at an address, read through the Hub crate's own production node
/// client, which floors the protocol-valid sub-Zhu dust a mining chain leaves
/// behind rather than guessing at it.
async fn balance_zhu(address: &str) -> u128 {
    l2_fast_pay_hub::node::NodeClient::new(node_url())
        .expect("node client")
        .query_balance_zhu(address)
        .await
        .expect("balance")
}

async fn channel_document(channel_id: &str) -> serde_json::Value {
    let url = node_url();
    reqwest::get(format!("{url}/query/channel?unit=mei&id={channel_id}"))
        .await
        .expect("channel query")
        .json()
        .await
        .expect("channel document")
}

/// Load the funded pilot identity, move exactly one funding transfer out of it
/// with the shipped Personal Wallet send path, and never touch it again.
///
/// The identity is the chain-7 pilot's own funded address. It is used here
/// only because a brand new Agent Wallet address has no coin and no shipped
/// code path can mint one; the owner of this machine holds the key either way.
#[cfg(windows)]
async fn fund_owner_address(
    _work: &std::path::Path,
    owner_address: &str,
    amount_hac: f64,
    wait_budget: Duration,
) {
    require_chain_seven("funding").await;
    let identity_file = PathBuf::from(required_env("HPAY_LIVE_FUNDING_DPAPI"));
    let (funder_address, funder_secret, _journal, _state) =
        l2_fast_pay_hub::windows_identity::load_dpapi_hub_identity(&identity_file)
            .expect("DPAPI funding identity")
            .into_parts();
    let before = balance_zhu(&funder_address).await;
    println!("[fund] funder {funder_address} balance {before} Zhu");
    assert!(
        before > 0,
        "the funding identity has no chain-7 coin at {funder_address}"
    );

    let mut funder = WalletService::new(Some(node_url()), None).unwrap();
    match funder.unlock(FUNDER_PASSPHRASE) {
        Ok(address) => assert_eq!(address, funder_address),
        Err(_) => {
            let address = funder
                .import_wallet(&funder_secret, FUNDER_PASSPHRASE, &funder_address)
                .expect("import the chain-7 funding key");
            assert_eq!(address, funder_address);
        }
    }
    let mut settings = funder.get_settings();
    settings.node_url = node_url();
    settings.l2_hub_url = None;
    settings.hub_right_address = None;
    settings.channel_id_hex = None;
    settings.send.prefer_fast_pay = false;
    funder.update_settings(settings).expect("funder settings");

    let owner_before = balance_zhu(owner_address).await;
    let result = funder
        .send_hac(owner_address, amount_hac, Default::default())
        .await
        .expect("the funding transfer left the funder");
    println!("[fund] transfer {result:?}");

    let target = owner_before + (amount_hac * 100_000_000.0) as u128;
    let deadline = Instant::now() + wait_budget;
    loop {
        let now = balance_zhu(owner_address).await;
        if now >= target {
            println!("[fund] owner {owner_address} funded: {now} Zhu");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the funding transfer never confirmed; owner has {now} Zhu, needs {target}"
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
}

#[cfg(not(windows))]
async fn fund_owner_address(
    _work: &std::path::Path,
    _owner_address: &str,
    _amount_hac: f64,
    _wait_budget: Duration,
) {
    panic!("the chain-7 funding identity is a Windows DPAPI file");
}

struct LiveHub {
    url: String,
    address: String,
    task: tokio::task::JoinHandle<()>,
}

/// The Hub identity, stable across runs.
///
/// The channel is derived from (owner, hub, reuse 1) and the wallet's durable
/// setup record pins the Hub URL, so a resumed run has to bring back the exact
/// same Hub address on the exact same port or it is talking to a stranger.
fn persistent_hub_account(work: &std::path::Path, tag: &str) -> WalletAccount {
    let seed_file = work.join(format!("hub-{tag}.seed"));
    let seed = match std::fs::read_to_string(&seed_file) {
        Ok(seed) if !seed.trim().is_empty() => seed.trim().to_owned(),
        _ => {
            let mut raw = [0u8; 32];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
            let seed = format!("chain7-live-voucher-hub-{}", hex::encode(raw));
            std::fs::write(&seed_file, &seed).unwrap();
            seed
        }
    };
    WalletAccount::create(&seed).unwrap()
}

async fn start_hub(work: &std::path::Path, account: &WalletAccount, tag: &str) -> LiveHub {
    let listener =
        tokio::net::TcpListener::bind(optional_env("HPAY_LIVE_HUB_LISTEN", "127.0.0.1:8791"))
            .await
            .unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let address = account.address();
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "HPAY chain-7 live voucher Hub",
            address.clone(),
            node_url(),
            None,
            work.join(format!("hub-{tag}.sealed.json")),
            account.secret_hex().to_string(),
            &"6a".repeat(32),
            &"6b".repeat(32),
            "local-pilot",
            100_000_000,
            100_000_000,
        )
        .expect("hub state"),
    );
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, build_router(state)).await;
    });
    println!("[hub ] {url} address {address} profile local-pilot");
    LiveHub { url, address, task }
}

/// Everything, in order, on the real chain.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn the_owner_exits_alone_while_the_hub_is_dead() {
    let work = workdir();
    // The Personal Wallet used for the single funding transfer reads these at
    // construction. Set before anything else runs.
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let deposit_hac = optional_env("HPAY_LIVE_DEPOSIT_HAC", "1");
    let fund_hac: f64 = optional_env("HPAY_LIVE_FUND_HAC", "1.5").parse().unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    // ---------------------------------------------------------------- 1. node
    require_chain_seven("open").await;
    let anchor = block_one_hash().await;
    println!("[node] block 1 {anchor}");

    // -------------------------------------------------------------- 2. wallet
    let root = work.join("owner");
    std::fs::create_dir_all(&root).unwrap();
    let mut manager = AgentWalletManager::open(&root).unwrap();
    // A re-run reuses the wallet the last run funded rather than stranding
    // pilot coin at a fresh address every time.
    let (wallet_id, owner_address) = match manager.list_wallets().unwrap().first() {
        Some(existing) => {
            println!("[wall] reusing the owner wallet from a previous run");
            (existing.wallet_id.clone(), existing.address.clone())
        }
        None => {
            let created = manager
                .create_wallet(
                    CreateAgentWallet {
                        passphrase: OWNER_PASSPHRASE.to_owned(),
                        network_mode: "testnet".to_owned(),
                        node_url: node_url(),
                        block_one_fingerprint: Some(anchor.clone()),
                        mainnet_pilot_acknowledgement: None,
                    },
                    unix_now(),
                )
                .expect("create the owner Agent Wallet");
            (created.wallet_id, created.address)
        }
    };
    manager
        .unlock(&wallet_id, OWNER_PASSPHRASE, unix_now())
        .unwrap();
    manager
        .enable_agent_payments_locally(&wallet_id, unix_now())
        .unwrap();
    println!("[wall] owner Agent Wallet {owner_address}");

    let needed = (fund_hac * 100_000_000.0) as u128;
    if balance_zhu(&owner_address).await >= needed {
        println!("[fund] the owner is already funded; no transfer needed");
    } else {
        fund_owner_address(&work, &owner_address, fund_hac, wait_budget).await;
    }

    // ----------------------------------------------------------------- 3. hub
    let hub_account = persistent_hub_account(&work, "a");
    let hub = start_hub(&work, &hub_account, "a").await;

    // -------------------------------------------------------- 4. channel open
    let pending_setup = {
        let (state_master, journal_key) = fixtures::keys(&manager, &wallet_id);
        manager
            .load_verified_state(&wallet_id, &state_master, &journal_key)
            .unwrap()
            .l2_channel_setup
            .clone()
    };
    let review = match pending_setup {
        Some(setup) => {
            println!(
                "[chan] resuming {} channel {} phase {:?}",
                setup.review.operation_id, setup.review.channel_id, setup.review.phase
            );
            setup.review
        }
        None => {
            let review = manager
                .prepare_l2_channel_setup(&wallet_id, &hub.url, &deposit_hac, unix_now())
                .await
                .expect("prepare the owner-reviewed channel open");
            println!(
                "[chan] prepared {} channel {} deposit {} units hub {}",
                review.operation_id,
                review.channel_id,
                review.deposit_units.get(),
                review.hub_address
            );
            match manager
                .confirm_l2_channel_setup(
                    &wallet_id,
                    &review.operation_id,
                    &review.review_commitment,
                    unix_now(),
                )
                .await
            {
                Ok(done) => println!("[chan] confirm returned phase {:?}", done.phase),
                Err(error) => println!("[chan] confirm not finished yet: {error:?}"),
            }
            review
        }
    };
    let channel_id = review.channel_id.clone();
    assert_eq!(
        review.hub_address, hub.address,
        "resumed against a different Hub"
    );

    // The open is finished when the wallet holds the voucher, not when a call
    // returns Ok. `confirm_l2_channel_setup` answers AwaitingConfirmations
    // while the six confirmations accumulate, and only takes the voucher once
    // the open is finality evidenced.
    let deadline = Instant::now() + wait_budget;
    let held = loop {
        // Six confirmations take longer than the wallet's idle auto-lock, and
        // an owner waiting it out would unlock again. So does this.
        let _ = manager.unlock(&wallet_id, OWNER_PASSPHRASE, unix_now());
        if let Some(view) = manager
            .l2_channel_close_voucher(&wallet_id, unix_now())
            .unwrap()
            && view.phase == AgentChannelCloseVoucherPhase::Held
        {
            break view;
        }
        assert!(
            Instant::now() < deadline,
            "the channel open never reached a bound channel with a voucher"
        );
        tokio::time::sleep(Duration::from_secs(20)).await;
        require_chain_seven("confirm").await;
        match manager
            .recover_l2_channel_setup(&wallet_id, unix_now())
            .await
        {
            Ok(done) => println!(
                "[chan] recover phase {:?} at height {}",
                done.phase,
                chain_height().await
            ),
            Err(error) => println!(
                "[chan] still waiting ({error:?}) at height {}",
                chain_height().await
            ),
        }
    };

    // ------------------------------------------------------------ 5. voucher
    let _ = manager.unlock(&wallet_id, OWNER_PASSPHRASE, unix_now());
    let voucher_hex = held.signed_transaction_hex.clone().unwrap();
    let voucher_hash = held.transaction_hash.clone().unwrap();
    println!(
        "[exit] voucher tx {voucher_hash} refund {:?} deposit {:?} fee {:?}",
        held.refund_units, held.deposit_units, held.network_fee_units
    );

    // Owner-side, from the bytes, with nothing taken on the Hub's word.
    let verified = verify_channel_close_voucher_bytes(
        &voucher_hex,
        &voucher_hash,
        &owner_address,
        &hub.address,
        &channel_id,
        7,
    )
    .expect("the owner re-proves the exit from the bytes");
    assert_eq!(verified.transaction_hash, voucher_hash);
    println!(
        "[exit] owner-side verification passed, commitment {}",
        verified.signed_transaction_commitment
    );

    // The channel is still open on chain, and still the shape the voucher names.
    let channel = channel_document(&channel_id).await;
    println!("[chan] on chain after the voucher: {channel}");
    assert_eq!(channel["ret"].as_i64(), Some(0));
    assert_eq!(
        channel["status"].as_u64(),
        Some(u64::from(
            hacash_wallet_core::channel::CHANNEL_STATUS_OPENING
        )),
        "taking a voucher must leave the channel open"
    );

    // The same probe, run while the ledger is still delta zero, so the request
    // is one the wallet is happy to build and the refusal is the Hub's own.
    let refusal =
        ask_again_from_a_copy(&manager, &wallet_id, &work, "probe-delta-zero", &hub.url).await;
    println!("[neg ] a second, different voucher at delta zero: {refusal}");

    // ---------------------------------------------------------- 6. a payment
    let _ = manager.unlock(&wallet_id, OWNER_PASSPHRASE, unix_now());
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let mobile_record = fixtures::register_mobile(&mut manager, &wallet_id, &mobile, unix_now());
    let (agent_id, identity_key_sha256) =
        install_paying_agent(&mut manager, &wallet_id, &hub.address);
    let authorization = AgentAuthorization {
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(&wallet_id),
        agent_id,
        authorization_epoch: 1,
        identity_key_sha256,
        capability: AgentPermission::CreatePaymentIntent,
    };
    let now = unix_now();
    let requested = manager
        .request_fast_pay_intent(
            &authorization,
            AgentFastPayRequest {
                idempotency_key: "chain7-live-voucher-payment-0001".to_owned(),
                amount_units: HacUnits::new(8_000),
                recipient: hub.address.clone(),
                reason: "chain-7 live delta so the ledger is not zero".to_owned(),
                expires_at: now + 600,
            },
            now,
        )
        .expect("Fast Pay opens once the exit is held");
    let approval = manager
        .pending_fast_pay_approval(
            &wallet_id,
            Some(&requested.operation_id),
            mobile.device_id(),
            unix_now(),
        )
        .unwrap()
        .unwrap();
    let decision = AgentFastPayApprovalDecision::from_commitment(
        approval,
        ApprovalDecision::Approve,
        mobile.device_id().clone(),
        mobile_record.authorization_epoch,
        1,
        unix_now(),
    )
    .unwrap();
    let signed_decision = SignedAgentFastPayApprovalDecision::sign(decision, &mobile)
        .await
        .unwrap();
    manager
        .apply_mobile_fast_pay_approval(&wallet_id, signed_decision, unix_now())
        .unwrap();
    let signed = manager
        .sign_prepared_approved_fast_pay_bill(&wallet_id, &requested.operation_id, unix_now())
        .await
        .expect("the owner signs the Fast Pay bill");
    assert_eq!(signed.status, AgentFastPayStatus::Signed);
    let committed = manager
        .submit_signed_approved_fast_pay_bill(&wallet_id, &requested.operation_id, unix_now())
        .await
        .expect("the Hub settles the bill");
    assert_eq!(committed.status, AgentFastPayStatus::Committed);
    println!(
        "[pay ] committed {} units, ledger delta is now non-zero",
        committed.amount_units.get()
    );

    // ------------------------------------------------- 7. negative proofs
    let _ = manager.unlock(&wallet_id, OWNER_PASSPHRASE, unix_now());
    // Asking again through the shipped method replays the one voucher: same
    // transaction, same hash, no second signature anywhere.
    let second = manager
        .take_l2_channel_close_voucher(&wallet_id, unix_now())
        .await
        .expect("asking again replays the one voucher");
    assert_eq!(
        second.transaction_hash, held.transaction_hash,
        "a second ask must never produce a second signed close"
    );

    // A sacrificial copy of the wallet that has been made to forget its
    // voucher, which is the only way to get the shipped client to build a
    // *different* request naming the same channel. This one is taken while the
    // ledger is still delta zero, so nothing wallet side objects and the
    // refusal has to come from the Hub, over real HTTP.
    let refusal =
        ask_again_from_a_copy(&manager, &wallet_id, &work, "probe-post-payment", &hub.url).await;
    println!("[neg ] a second, different voucher after a payment: {refusal}");

    // --------------------------------------------------- 8. kill the Hub
    hub.task.abort();
    let dead = reqwest::Client::new()
        .get(format!("{}/v1/health", hub.url))
        .timeout(Duration::from_secs(3))
        .send()
        .await;
    assert!(dead.is_err(), "the Hub must be dead before the exit runs");
    println!("[hub ] dead: {dead:?}");

    // ------------------------------ 9. close the wallet, restore from backup
    let _ = manager.unlock(&wallet_id, OWNER_PASSPHRASE, unix_now());
    let backup = manager
        .create_agent_wallet_backup(
            &wallet_id,
            OWNER_PASSPHRASE,
            crate::service::AgentWalletBackupAcknowledgement::complete(),
            unix_now(),
        )
        .unwrap();
    drop(manager);
    let restore_root = work.join("restored");
    std::fs::create_dir_all(&restore_root).unwrap();
    let mut restored = AgentWalletManager::open(&restore_root).unwrap();
    restored
        .restore_agent_wallet_backup(
            &backup,
            OWNER_PASSPHRASE,
            crate::service::AgentWalletBackupAcknowledgement::complete(),
            unix_now(),
        )
        .unwrap();
    restored
        .unlock(&wallet_id, OWNER_PASSPHRASE, unix_now())
        .unwrap();
    let after_restore = restored
        .l2_channel_close_voucher(&wallet_id, unix_now())
        .unwrap()
        .expect("a voucher that does not survive a restore is not an exit");
    assert_eq!(
        after_restore.signed_transaction_hex,
        held.signed_transaction_hex
    );
    assert_eq!(after_restore.transaction_hash, held.transaction_hash);
    println!("[exit] the voucher survived a close, an encrypted backup and a restore");

    // ------------------------------------------------ 10. broadcast it alone
    require_chain_seven("broadcast").await;
    let owner_before = balance_zhu(&owner_address).await;
    let hub_before = balance_zhu(&hub.address).await;
    let height_before = chain_height().await;
    let _ = restored.unlock(&wallet_id, OWNER_PASSPHRASE, unix_now());
    let broadcast = restored
        .broadcast_l2_channel_close_voucher(&wallet_id, unix_now())
        .await
        .expect("the owner's own node accepts the exit with no Hub alive");
    assert_eq!(broadcast.phase, AgentChannelCloseVoucherPhase::Broadcast);
    let record = broadcast.broadcast.clone().expect("a broadcast record");
    println!(
        "[exit] BROADCAST tx {} via {} at height {height_before}",
        record.transaction_hash, record.node_url
    );
    assert_eq!(record.transaction_hash, voucher_hash);

    // ---------------------------------------------------- 11. read it back
    let deadline = Instant::now() + wait_budget;
    let mined = loop {
        let url = node_url();
        let found: serde_json::Value =
            reqwest::get(format!("{url}/query/transaction?hash={voucher_hash}"))
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        if found["ret"].as_i64() == Some(0) && found["block"]["height"].as_u64().is_some() {
            break found;
        }
        assert!(
            Instant::now() < deadline,
            "the exit never made it into a block: {found}"
        );
        tokio::time::sleep(Duration::from_secs(15)).await;
    };
    println!("[exit] mined: {mined}");

    let owner_after = balance_zhu(&owner_address).await;
    let hub_after = balance_zhu(&hub.address).await;
    let closed = channel_document(&channel_id).await;
    println!("[chan] on chain after the exit: {closed}");
    println!(
        "[coin] owner {owner_before} -> {owner_after} Zhu, hub {hub_before} -> {hub_after} Zhu"
    );
    // The exit pays the owner the deposit recorded at open, minus only the L1
    // fee the owner pays out of their own balance to broadcast it.
    let deposit_zhu = u128::from(held.deposit_units.get()) * 100;
    let fee_zhu = u128::from(held.network_fee_units.get()) * 100;
    let expected = owner_before + deposit_zhu - fee_zhu;
    println!("[coin] expected owner after: {expected} Zhu (deposit {deposit_zhu}, fee {fee_zhu})");
    assert!(
        owner_after.abs_diff(expected) <= 1,
        "the owner was not paid the whole deposit back minus the broadcast fee"
    );
    assert_eq!(
        hub_after, hub_before,
        "a delta-zero close pays the Hub exactly nothing"
    );
    assert_eq!(hub_after, 0, "the Hub never held any of this coin on chain");
    let still_open = closed["ret"].as_i64() == Some(0)
        && closed["status"].as_u64()
            == Some(u64::from(
                hacash_wallet_core::channel::CHANNEL_STATUS_OPENING,
            ));
    assert!(!still_open, "the channel must not still be open");
}

/// Take a backup, restore it into a throwaway store, erase that copy's memory
/// of its voucher, and ask for one again. The live wallet is untouched.
async fn ask_again_from_a_copy(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    work: &std::path::Path,
    tag: &str,
    hub_url: &str,
) -> String {
    let backup = manager
        .create_agent_wallet_backup(
            wallet_id,
            OWNER_PASSPHRASE,
            crate::service::AgentWalletBackupAcknowledgement::complete(),
            unix_now(),
        )
        .unwrap();
    let root = work.join(tag);
    std::fs::create_dir_all(&root).unwrap();
    let mut copy = AgentWalletManager::open(&root).unwrap();
    copy.restore_agent_wallet_backup(
        &backup,
        OWNER_PASSPHRASE,
        crate::service::AgentWalletBackupAcknowledgement::complete(),
        unix_now(),
    )
    .unwrap();
    copy.unlock(wallet_id, OWNER_PASSPHRASE, unix_now())
        .unwrap();
    forget_the_voucher(&mut copy, wallet_id);
    let wallet_said = match copy
        .take_l2_channel_close_voucher(wallet_id, unix_now())
        .await
    {
        Ok(view) => panic!("a second voucher was issued: {view:?}"),
        Err(error) => format!("{error:?}"),
    };
    // The wallet collapses every Hub answer into one error, so put the Hub's
    // own words on the record by presenting the exact request it just signed.
    let (state_master, journal_key) = fixtures::keys(&copy, wallet_id);
    let stored = copy
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
        .l2_channel_close_voucher
        .as_ref()
        .and_then(|operation| operation.signed_request.clone());
    let hub_said = match stored {
        Some(request) => {
            match reqwest::Client::new()
                .post(format!("{hub_url}/v1/l1/channel/close-voucher"))
                .json(&request)
                .timeout(Duration::from_secs(15))
                .send()
                .await
            {
                Ok(response) => {
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    format!("HTTP {status} {body}")
                }
                Err(error) => format!("transport error {error}"),
            }
        }
        None => "the copy kept no signed request to present".to_owned(),
    };
    format!("wallet said {wallet_said}; Hub said {hub_said}")
}

/// Erase this wallet's memory of its voucher, the way a restore from a stale
/// backup would. Nothing production does this; it exists so the Hub can be
/// asked, over real HTTP, for a second signed close on a channel that already
/// has one.
fn forget_the_voucher(manager: &mut AgentWalletManager, wallet_id: &AgentWalletId) {
    let (state_master, journal_key) = fixtures::keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    state.l2_channel_close_voucher = None;
    state.updated_at = unix_now();
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::RecoveryRequired,
            None,
            None,
            unix_now(),
        )
        .unwrap();
}

fn install_paying_agent(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    recipient: &str,
) -> (AgentId, String) {
    let (state_master, journal_key) = fixtures::keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    let agent_identity = AgentIdentityKey::generate();
    let server_identity = ServerIdentityKey::generate()
        .pinned_identity(state.primary_signing_device_id.clone())
        .unwrap();
    let agent_id = AgentId::new();
    let permissions = BTreeSet::from([AgentPermission::CreatePaymentIntent]);
    let paired = PairedAgent {
        agent_id: agent_id.clone(),
        wallet_id: wallet_id.clone(),
        wallet_scope: WalletScope::for_agent_wallet(wallet_id),
        name: "chain-7 live voucher agent".to_owned(),
        version: "1.0.0".to_owned(),
        identity_public_key_sec1_hex: agent_identity.public_key_sec1_hex(),
        identity_fingerprint: agent_identity.fingerprint(),
        capabilities: permissions.clone(),
        status: PairedAgentStatus::Active,
        paired_at_unix: unix_now(),
        authorization_epoch: 1,
        server_identity: server_identity.clone(),
    };
    let identity_key_sha256 = paired.identity_key_sha256().unwrap();
    state.agents.insert(
        agent_id.as_str().to_owned(),
        AgentRecord {
            agent_id: agent_id.clone(),
            wallet_scope: paired.wallet_scope,
            name: paired.name,
            version: paired.version,
            identity_public_key_sec1: paired.identity_public_key_sec1_hex,
            identity_fingerprint: paired.identity_fingerprint,
            identity_key_sha256: identity_key_sha256.clone(),
            server_identity,
            status: AgentStatus::Active,
            authorization_epoch: 1,
            policy: AgentPolicy {
                permissions,
                max_per_payment_units: HacUnits::new(1_000_000),
                max_daily_units: HacUnits::new(10_000_000),
                max_pending_operations: 4,
                allowed_recipients: BTreeSet::from([recipient.to_owned()]),
                blocked_recipients: BTreeSet::new(),
                allow_unlisted_recipient_with_approval: false,
                approval_mode: ApprovalMode::MobileManual,
                policy_epoch: state.policy_epoch,
            },
            paired_at: unix_now(),
        },
    );
    state.updated_at = unix_now();
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::AgentPaired,
            None,
            None,
            unix_now(),
        )
        .unwrap();
    (agent_id, identity_key_sha256)
}

/// The owner's verifier, run against the exact bytes the Hub really signed and
/// against four things that are not them.
///
/// Reads the restored store the run above left behind, so it needs no chain
/// time and no second channel. Run it after
/// `the_owner_exits_alone_while_the_hub_is_dead`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn the_wallet_refuses_a_voucher_that_is_not_exactly_one() {
    use basis::interface::Transaction as _;
    use field::{AddrOrPtr, Address, Amount, ChannelId, Field as _, Serialize as _, Uint4};
    use protocol::action::{ChainAllow, ChainIDList, HacToTrs};
    use protocol::transaction::TransactionType2;

    fn channel_id_of(hex_id: &str) -> ChannelId {
        let raw = hex::decode(hex_id).unwrap();
        let bytes: [u8; 16] = raw.try_into().unwrap();
        ChannelId::from(bytes)
    }

    let work = workdir();
    let mut manager = AgentWalletManager::open(work.join("restored")).unwrap();
    let wallet_id = manager
        .list_wallets()
        .unwrap()
        .first()
        .expect("the restored store holds the owner wallet")
        .wallet_id
        .clone();
    manager
        .unlock(&wallet_id, OWNER_PASSPHRASE, unix_now())
        .unwrap();
    let (state_master, journal_key) = fixtures::keys(&manager, &wallet_id);
    let state = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    let voucher = state
        .l2_channel_close_voucher
        .clone()
        .expect("the restored wallet still holds the exit");
    let hex_bytes = voucher.view.signed_transaction_hex.clone().unwrap();
    let hash = voucher.view.transaction_hash.clone().unwrap();
    let owner = voucher.view.owner_address.clone();
    let hub = voucher.view.hub_address.clone();
    let channel_id = voucher.view.channel_id.clone();

    // Control: the real thing verifies.
    let verified =
        verify_channel_close_voucher_bytes(&hex_bytes, &hash, &owner, &hub, &channel_id, 7)
            .expect("the real voucher verifies");
    println!("[neg ] control: the Hub-countersigned bytes verify");

    // 1. The owner's own signature only. These are the exact bytes the wallet
    //    sent to the Hub, before it countersigned. `fill_sign` does not change
    //    `hash()`, so this passes every check up to the signature count.
    let partial = voucher
        .signed_request
        .as_ref()
        .expect("the wallet kept the exact request it presented")
        .partial_transaction_hex
        .clone();
    assert_ne!(partial, hex_bytes);
    let refusal = verify_channel_close_voucher_bytes(&partial, &hash, &owner, &hub, &channel_id, 7)
        .expect_err("a close the Hub never countersigned is not an exit");
    println!("[neg ] one signature only: {refusal}");

    // 2. One byte flipped inside the Hub's countersignature.
    let mut tampered = hex_bytes.clone().into_bytes();
    let inside_the_signature = tampered.len() - 100;
    tampered[inside_the_signature] = if tampered[inside_the_signature] == b'a' {
        b'b'
    } else {
        b'a'
    };
    let tampered = String::from_utf8(tampered).unwrap();
    let refusal =
        verify_channel_close_voucher_bytes(&tampered, &hash, &owner, &hub, &channel_id, 7)
            .expect_err("a flipped countersignature is not an exit");
    println!("[neg ] flipped Hub signature: {refusal}");

    // 2b. One byte flipped at the very end of the encoding. This one is worth
    //     being exact about, because the bytes-only check does NOT reject it:
    //     the transaction still parses, still hashes to the same value and
    //     still carries two valid party signatures, so `hash()` plainly does
    //     not cover this byte. What refuses it is the durable record, which
    //     also pins a SHA-256 over the exact bytes the Hub returned.
    let mut trailing = hex_bytes.clone().into_bytes();
    let last = trailing.len() - 1;
    trailing[last] = if trailing[last] == b'a' { b'b' } else { b'a' };
    let trailing = String::from_utf8(trailing).unwrap();
    let still_verifies =
        verify_channel_close_voucher_bytes(&trailing, &hash, &owner, &hub, &channel_id, 7)
            .expect("the bytes-only check does not cover the final byte");
    assert_ne!(
        still_verifies.signed_transaction_commitment, verified.signed_transaction_commitment,
        "the commitment must at least notice the difference"
    );
    println!(
        "[neg ] final byte flipped: bytes-only check STILL PASSES, commitment moves {} -> {}",
        verified.signed_transaction_commitment, still_verifies.signed_transaction_commitment
    );
    let mut altered = voucher.clone();
    altered.view.signed_transaction_hex = Some(trailing);
    let refusal = altered
        .verified_bytes()
        .expect_err("the durable record pins the exact bytes and must refuse");
    println!("[neg ] final byte flipped, durable record: {refusal:?}");

    // 3. Topology: [ChainAllow, ChannelClose, HacToTrs]. Everything else about
    //    it is right, including the channel it names.
    let mut three = TransactionType2::new_by(
        Address::from_readable(&owner).unwrap(),
        Amount::coin(1, 244),
        sys::curtimes(),
    );
    let mut guard = ChainAllow::new();
    guard.chains = ChainIDList::from_list(vec![Uint4::from(7u32)]).unwrap();
    three.push_action(Box::new(guard)).unwrap();
    let mut close = mint::action::ChannelClose::new();
    close.channel_id = channel_id_of(&channel_id);
    three.push_action(Box::new(close)).unwrap();
    let mut extra = HacToTrs::new();
    extra.to = AddrOrPtr::from_addr(Address::from_readable(&hub).unwrap());
    extra.hacash = Amount::coin(1, 248);
    three.push_action(Box::new(extra)).unwrap();
    let three_hex = hex::encode(three.serialize());
    let three_hash = hex::encode(basis::interface::TransactionRead::hash(&three).as_bytes());
    let refusal =
        verify_channel_close_voucher_bytes(&three_hex, &three_hash, &owner, &hub, &channel_id, 7)
            .expect_err("three actions is not the delta-zero shape");
    println!("[neg ] three actions: {refusal}");

    // 4. Topology: [ChainAllow, HacToTrs]. Two actions, wrong second kind.
    let mut two = TransactionType2::new_by(
        Address::from_readable(&owner).unwrap(),
        Amount::coin(1, 244),
        sys::curtimes(),
    );
    let mut guard = ChainAllow::new();
    guard.chains = ChainIDList::from_list(vec![Uint4::from(7u32)]).unwrap();
    two.push_action(Box::new(guard)).unwrap();
    let mut only = HacToTrs::new();
    only.to = AddrOrPtr::from_addr(Address::from_readable(&hub).unwrap());
    only.hacash = Amount::coin(1, 248);
    two.push_action(Box::new(only)).unwrap();
    let two_hex = hex::encode(two.serialize());
    let two_hash = hex::encode(basis::interface::TransactionRead::hash(&two).as_bytes());
    let refusal =
        verify_channel_close_voucher_bytes(&two_hex, &two_hash, &owner, &hub, &channel_id, 7)
            .expect_err("a payment is not a close");
    println!("[neg ] wrong second action: {refusal}");

    // 5. The real bytes, judged against a chain they do not bind.
    let refusal =
        verify_channel_close_voucher_bytes(&hex_bytes, &hash, &owner, &hub, &channel_id, 1)
            .expect_err("a voucher bound to chain 7 is not a voucher on chain 1");
    println!("[neg ] wrong chain: {refusal}");
}
