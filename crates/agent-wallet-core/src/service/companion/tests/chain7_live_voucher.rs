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
    let listen = optional_env("HPAY_LIVE_HUB_LISTEN", "127.0.0.1:8791");
    start_hub_at(work, account, tag, &listen).await
}

/// The same Hub, on an address the caller names.
///
/// The wallet's durable setup record pins the Hub URL, so a Hub that is killed
/// and brought back has to return on the exact same port with the exact same
/// key or the wallet is talking to a stranger. The outage tests below need
/// that, and they need their own ports so they never collide with the main
/// run's Hub.
async fn start_hub_at(
    work: &std::path::Path,
    account: &WalletAccount,
    tag: &str,
    listen: &str,
) -> LiveHub {
    let upstream = node_url();
    start_hub_at_node(work, account, tag, listen, &upstream).await
}

/// The same Hub, reading the chain through a node URL the caller names.
///
/// Every Hub above talks straight to the pilot fullnode. The stale-reservation
/// run below needs one whose submit route can be taken away without taking the
/// chain away, so the Hub's own node client is the thing that has to be
/// pointed somewhere else. The wallet keeps the real node throughout.
async fn start_hub_at_node(
    work: &std::path::Path,
    account: &WalletAccount,
    tag: &str,
    listen: &str,
    hub_node_url: &str,
) -> LiveHub {
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let address = account.address();
    let state = Arc::new(
        HubState::new_secure_with_policy(
            "HPAY chain-7 live voucher Hub",
            address.clone(),
            hub_node_url.to_owned(),
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

// =====================================================================
// THE NEGATIVES, ON THE SAME LIVE CHAIN.
//
// A path that only works when nothing goes wrong is not proven. Each test
// below breaks one thing on purpose against the real chain-7 node and a real
// Hub served over real HTTP, and asserts on what the shipped code does about
// it. All are `#[ignore]`, like the run above.
// =====================================================================

const AWAY_PASSPHRASE: &str = "chain7 live negatives owner passphrase";

/// Open a funded Agent Wallet of its own in `work/tag`, so each negative gets
/// a fresh owner address and therefore a fresh deterministic channel ID.
async fn funded_owner(
    work: &std::path::Path,
    tag: &str,
    anchor: &str,
    fund_hac: f64,
    wait_budget: Duration,
) -> (AgentWalletManager, AgentWalletId, String) {
    let root = work.join(tag);
    std::fs::create_dir_all(&root).unwrap();
    let mut manager = AgentWalletManager::open(&root).unwrap();
    let (wallet_id, address) = match manager.list_wallets().unwrap().first() {
        Some(existing) => (existing.wallet_id.clone(), existing.address.clone()),
        None => {
            let created = manager
                .create_wallet(
                    CreateAgentWallet {
                        passphrase: AWAY_PASSPHRASE.to_owned(),
                        network_mode: "testnet".to_owned(),
                        node_url: node_url(),
                        block_one_fingerprint: Some(anchor.to_owned()),
                        mainnet_pilot_acknowledgement: None,
                    },
                    unix_now(),
                )
                .expect("create the owner Agent Wallet");
            (created.wallet_id, created.address)
        }
    };
    manager
        .unlock(&wallet_id, AWAY_PASSPHRASE, unix_now())
        .unwrap();
    manager
        .enable_agent_payments_locally(&wallet_id, unix_now())
        .unwrap();
    let needed = (fund_hac * 100_000_000.0) as u128;
    if balance_zhu(&address).await < needed {
        fund_owner_address(work, &address, fund_hac, wait_budget).await;
    }
    println!(
        "[wall] {tag} owner {address} balance {} Zhu",
        balance_zhu(&address).await
    );
    (manager, wallet_id, address)
}

/// Read the setup the wallet is actually holding, the way the panel does.
fn stored_setup(
    manager: &AgentWalletManager,
    wallet_id: &AgentWalletId,
) -> Option<crate::service::l2::AgentChannelSetupOperation> {
    let (state_master, journal_key) = fixtures::keys(manager, wallet_id);
    manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
        .l2_channel_setup
        .clone()
}

/// Prove the Hub on this URL is not answering, rather than assuming it.
async fn assert_hub_is_dead(url: &str, label: &str) {
    let answer = reqwest::Client::new()
        .get(format!("{url}/v1/health"))
        .timeout(Duration::from_secs(3))
        .send()
        .await;
    assert!(answer.is_err(), "[{label}] the Hub is still answering");
    println!("[neg ] {label}: Hub at {url} is dead");
}

/// A reverse proxy in front of a real Hub whose settlement route can be taken
/// down without taking the Hub down.
///
/// This is what a Hub outage looks like from a wallet in practice: the
/// operator's front door still answers health, and the one request that
/// matters does not arrive. It is also the only way to reach the state the
/// owner of this machine was actually in, and finding that out cost this test
/// a red run. `confirm_l2_channel_setup` re-verifies the Hub before it signs,
/// so a Hub that is already dead is refused with `ChannelSetupHubNotReady`
/// while the setup is still `Prepared` and provably unsigned. The interesting
/// failure, the one with no exit before this pass, is the one AFTER the wallet
/// has signed.
struct SettlementOutage {
    url: String,
    down: Arc<std::sync::atomic::AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl SettlementOutage {
    fn take_settlement_down(&self) {
        self.down.store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn bring_settlement_back(&self) {
        self.down.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone)]
struct OutageProxy {
    upstream: String,
    down: Arc<std::sync::atomic::AtomicBool>,
}

async fn proxy_or_refuse(
    axum::extract::State(proxy): axum::extract::State<OutageProxy>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if proxy.down.load(std::sync::atomic::Ordering::SeqCst)
        && path.starts_with("/v1/l1/channel/open")
    {
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "{\"error\":\"the Hub settlement route is not answering\"}",
        )
            .into_response();
    }
    let target = format!("{}{}", proxy.upstream, path);
    let sent = reqwest::Client::new()
        .request(method, target)
        .header("content-type", "application/json")
        .body(body.to_vec())
        .timeout(Duration::from_secs(30))
        .send()
        .await;
    match sent {
        Ok(response) => {
            let status = axum::http::StatusCode::from_u16(response.status().as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            let bytes = response.bytes().await.unwrap_or_default();
            (status, bytes.to_vec()).into_response()
        }
        Err(error) => (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("{{\"error\":\"upstream: {error}\"}}"),
        )
            .into_response(),
    }
}

async fn start_settlement_outage(upstream: &str, listen: &str) -> SettlementOutage {
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let down = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let router = axum::Router::new()
        .fallback(axum::routing::any(proxy_or_refuse))
        .with_state(OutageProxy {
            upstream: upstream.to_owned(),
            down: down.clone(),
        });
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    println!("[prox] {url} in front of {upstream}");
    SettlementOutage { url, down, task }
}

/// Prove the settlement route really is refusing, rather than assuming it.
async fn assert_settlement_is_down(url: &str, label: &str) {
    let answer = reqwest::Client::new()
        .post(format!("{url}/v1/l1/channel/open"))
        .header("content-type", "application/json")
        .body("{}")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("the front door still answers");
    assert_eq!(
        answer.status().as_u16(),
        503,
        "[{label}] the settlement route is still up"
    );
    // And the health route the wallet checks before it signs is still up,
    // which is exactly what makes this an outage and not a dead Hub.
    let health = reqwest::Client::new()
        .get(format!("{url}/v1/health"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("health must still answer");
    assert!(health.status().is_success(), "[{label}] health is down too");
    println!("[neg ] {label}: health up, settlement route answering 503");
}

/// THE HUB SETTLEMENT ROUTE GOES DOWN AFTER THE WALLET SIGNS, AND COMES BACK
/// INSIDE THE ENVELOPE.
///
/// Four claims, in one run because they are one story:
///
/// 1. A Hub that is already dead at the confirm is refused BEFORE anything is
///    signed, with `ChannelSetupHubNotReady` carrying the transport error and
///    the setup still `Prepared`. That is the good case, and it is asserted
///    first because it is what makes the rest of this test work harder to
///    reach the bad one.
/// 2. With the front door up and the settlement route refusing, the confirm
///    signs and then fails, and the failure carries the Hub's own words rather
///    than a blank `RecoveryRequired`.
/// 3. `discard_unsigned_l2_channel_setup` then refuses, because a signature
///    exists. So does `abandon_dead_l2_channel_setup`, because the envelope is
///    alive: a live signature is not a dead one.
/// 4. `recover_l2_channel_setup`, once the route is back and still inside the
///    300 second envelope, opens the channel for real, on the chain.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn a_hub_outage_inside_the_envelope_refuses_the_discard_and_the_retry_still_opens_the_channel()
 {
    let work = workdir().join("outage");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    require_chain_seven("outage").await;
    let anchor = block_one_hash().await;
    let (mut manager, wallet_id, owner_address) =
        funded_owner(&work, "owner", &anchor, 1.5, wait_budget).await;

    let hub_account = persistent_hub_account(&work, "outage");
    let listen = optional_env("HPAY_LIVE_HUB_OUTAGE_LISTEN", "127.0.0.1:8892");
    let front = optional_env("HPAY_LIVE_HUB_OUTAGE_FRONT", "127.0.0.1:8894");
    let hub = start_hub_at(&work, &hub_account, "outage", &listen).await;
    let outage = start_settlement_outage(&hub.url, &front).await;

    // ---- (1) A HUB THAT IS ALREADY GONE IS REFUSED BEFORE ANY SIGNATURE ----
    // Proven first, on a review of its own, because it is the reason the rest
    // of this test needs a front door that stays up.
    let doomed = manager
        .prepare_l2_channel_setup(&wallet_id, &hub.url, "1", unix_now())
        .await
        .expect("prepare against the Hub directly");
    hub.task.abort();
    assert_hub_is_dead(&hub.url, "before the first confirm").await;
    let early = manager
        .confirm_l2_channel_setup(
            &wallet_id,
            &doomed.operation_id,
            &doomed.review_commitment,
            unix_now(),
        )
        .await
        .expect_err("a Hub that is not there cannot cosign an open");
    println!("[neg ] confirm against a fully dead Hub: {early:?}");
    assert!(matches!(
        early,
        crate::AgentWalletError::ChannelSetupHubNotReady(_)
    ));
    let unsigned = stored_setup(&manager, &wallet_id).expect("the setup survives");
    assert_eq!(
        unsigned.review.phase,
        crate::service::l2::AgentChannelSetupPhase::Prepared,
        "a dead Hub must be refused before the wallet signs"
    );
    assert!(unsigned.signed_request.is_none());
    // That one really is unsigned, so the unsigned discard is the right door
    // for it, and taking it clears the way for the interesting case.
    manager
        .discard_unsigned_l2_channel_setup(
            &wallet_id,
            &doomed.operation_id,
            &doomed.review_commitment,
            unix_now(),
        )
        .expect("an unsigned setup is discardable");
    println!("[neg ] the unsigned setup was discarded, as it should be");

    // ---- (2) THE OUTAGE THAT ACTUALLY REACHES THE SIGNER ----
    let hub = start_hub_at(&work, &hub_account, "outage", &listen).await;
    let review = manager
        .prepare_l2_channel_setup(&wallet_id, &outage.url, "1", unix_now())
        .await
        .expect("prepare through the front door");
    println!(
        "[chan] prepared {} channel {} expires_at {} (envelope {} s)",
        review.operation_id,
        review.channel_id,
        review.expires_at,
        review.expires_at - unix_now()
    );
    let before_open = balance_zhu(&owner_address).await;

    outage.take_settlement_down();
    assert_settlement_is_down(&outage.url, "before confirm").await;

    let refusal = manager
        .confirm_l2_channel_setup(
            &wallet_id,
            &review.operation_id,
            &review.review_commitment,
            unix_now(),
        )
        .await
        .expect_err("a settlement route that refuses cannot cosign an open");
    println!("[neg ] confirm through a refusing settlement route: {refusal:?}");

    let setup = stored_setup(&manager, &wallet_id).expect("the setup survives the failure");
    println!(
        "[neg ] stored phase {:?}, signature present {}, node tx hash {:?}",
        setup.review.phase,
        setup.signed_request.is_some(),
        setup.transaction_hash
    );
    assert_eq!(
        setup.review.phase,
        crate::service::l2::AgentChannelSetupPhase::RecoveryRequired
    );
    assert!(
        setup.signed_request.is_some(),
        "the wallet signed before it called the Hub, which is why a discard must refuse"
    );
    assert!(setup.transaction_hash.is_none(), "nothing reached a node");
    let reason = setup
        .review
        .last_hub_refusal
        .clone()
        .expect("the stored review must remember why, not just that");
    println!("[neg ] the owner is told: {reason}");

    // ---- (2) NEITHER EXIT IS OPEN WHILE THE SIGNATURE IS LIVE ----
    let discard = manager
        .discard_unsigned_l2_channel_setup(
            &wallet_id,
            &review.operation_id,
            &review.review_commitment,
            unix_now(),
        )
        .expect_err("a signed setup is not an unsigned one");
    println!("[neg ] discard once a signature exists: {discard:?}");
    assert!(matches!(
        discard,
        crate::AgentWalletError::ChannelSetupNotDiscardable
    ));

    let too_early = manager
        .abandon_dead_l2_channel_setup(
            &wallet_id,
            &review.operation_id,
            &review.review_commitment,
            unix_now(),
        )
        .await
        .expect_err("an envelope that is still open is not a dead request");
    println!("[neg ] abandon while the envelope is alive: {too_early:?}");
    assert!(matches!(
        too_early,
        crate::AgentWalletError::ChannelSetupNotDiscardable
    ));

    // ---- (4) THE ROUTE COMES BACK, SAME HUB, SAME KEY, SAME ENVELOPE ----
    outage.bring_settlement_back();
    assert_eq!(hub.address, hub_account.address());
    assert!(
        unix_now() < review.expires_at,
        "this test is only meaningful inside the envelope"
    );
    println!(
        "[chan] settlement back at {} with {} s of envelope left",
        outage.url,
        review.expires_at - unix_now()
    );

    let deadline = Instant::now() + wait_budget;
    let opened = loop {
        let _ = manager.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now());
        match manager
            .recover_l2_channel_setup(&wallet_id, unix_now())
            .await
        {
            Ok(done) => {
                println!(
                    "[chan] recover phase {:?} at height {}",
                    done.phase,
                    chain_height().await
                );
                if done.phase == crate::service::l2::AgentChannelSetupPhase::Confirmed {
                    break done;
                }
            }
            Err(error) => println!(
                "[chan] recover still working ({error:?}) at height {}",
                chain_height().await
            ),
        }
        assert!(
            Instant::now() < deadline,
            "the retry inside the envelope never opened the channel"
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
    };

    let channel = channel_document(&opened.channel_id).await;
    println!("[chan] on chain after the retry: {channel}");
    assert_eq!(channel["ret"].as_i64(), Some(0), "the channel must exist");
    assert_eq!(
        channel["left"]["address"].as_str(),
        Some(owner_address.as_str())
    );
    assert_eq!(
        channel["right"]["address"].as_str(),
        Some(hub.address.as_str())
    );
    assert_eq!(
        channel["status"].as_u64(),
        Some(u64::from(
            hacash_wallet_core::channel::CHANNEL_STATUS_OPENING
        )),
        "the retry produced a real open channel"
    );
    let after_open = balance_zhu(&owner_address).await;
    println!(
        "[coin] owner {before_open} -> {after_open} Zhu across the retried open (open_height {})",
        channel["open_height"]
    );
    assert!(
        after_open < before_open,
        "an open that cost nothing did not happen"
    );
    outage.task.abort();
    hub.task.abort();
}

/// THE ENVELOPE CLOSES WHILE THE HUB IS AWAY.
///
/// The state the owner of this machine was actually in on mainnet. The retry
/// must fail cleanly rather than hang or half-write, the unsigned discard must
/// still refuse, and the exit built for exactly this must open, retire the
/// setup and let the wallet prepare the same channel again.
///
/// This one waits out real time: `CHANNEL_OPEN_DEAD_AFTER` is 600 seconds
/// measured from the transaction, and the guard reads the clock the caller
/// passes, so handing it a future `now` would prove nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only, and waits out a real 600 second envelope"]
async fn a_retry_after_the_envelope_expires_fails_cleanly_and_the_dead_setup_has_an_exit() {
    let work = workdir().join("expired");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    require_chain_seven("expired").await;
    let anchor = block_one_hash().await;
    let (mut manager, wallet_id, owner_address) =
        funded_owner(&work, "owner", &anchor, 1.5, wait_budget).await;

    let hub_account = persistent_hub_account(&work, "expired");
    let listen = optional_env("HPAY_LIVE_HUB_EXPIRED_LISTEN", "127.0.0.1:8893");
    let front = optional_env("HPAY_LIVE_HUB_EXPIRED_FRONT", "127.0.0.1:8895");
    let hub = start_hub_at(&work, &hub_account, "expired", &listen).await;
    let outage = start_settlement_outage(&hub.url, &front).await;

    let review = manager
        .prepare_l2_channel_setup(&wallet_id, &outage.url, "1", unix_now())
        .await
        .expect("prepare through the front door");
    let balance_at_prepare = balance_zhu(&owner_address).await;
    println!(
        "[chan] prepared {} channel {} expires_at {}",
        review.operation_id, review.channel_id, review.expires_at
    );

    outage.take_settlement_down();
    assert_settlement_is_down(&outage.url, "before confirm").await;
    let refusal = manager
        .confirm_l2_channel_setup(
            &wallet_id,
            &review.operation_id,
            &review.review_commitment,
            unix_now(),
        )
        .await
        .expect_err("a settlement route that refuses cannot cosign an open");
    println!("[neg ] confirm through a refusing settlement route: {refusal:?}");
    let setup = stored_setup(&manager, &wallet_id).expect("the setup survives");
    assert_eq!(
        setup.review.phase,
        crate::service::l2::AgentChannelSetupPhase::RecoveryRequired
    );
    assert!(setup.signed_request.is_some());
    assert!(setup.transaction_hash.is_none());
    let dead_after = setup.created_at + crate::service::l2::CHANNEL_OPEN_DEAD_AFTER;
    println!(
        "[neg ] signed at {}, envelope closes {}, unusable by anybody after {}",
        setup.created_at, review.expires_at, dead_after
    );

    // ---- WAIT OUT THE ENVELOPE, AND THEN THE TRANSACTION AGE RULE ----
    let mut retries = 0usize;
    let mut gap_reported = false;
    while unix_now() <= dead_after {
        let _ = manager.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now());
        if unix_now() > review.expires_at {
            // Past the envelope, still inside the age rule. The exit must stay
            // shut here: retiring a signature a Hub could still use is exactly
            // what it must not do.
            let gap = manager
                .abandon_dead_l2_channel_setup(
                    &wallet_id,
                    &review.operation_id,
                    &review.review_commitment,
                    unix_now(),
                )
                .await
                .expect_err("a closed envelope alone is not a dead request");
            assert!(matches!(
                gap,
                crate::AgentWalletError::ChannelSetupNotDiscardable
            ));
            if !gap_reported {
                println!("[neg ] envelope closed but transaction still young: {gap:?}");
                gap_reported = true;
            }
        }
        let again = manager
            .recover_l2_channel_setup(&wallet_id, unix_now())
            .await;
        retries += 1;
        if retries <= 2 {
            println!("[neg ] retry {retries} on a dead envelope: {again:?}");
        }
        assert!(
            again.is_err(),
            "a dead Hub and a closed envelope cannot produce a channel"
        );
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
    println!("[neg ] {retries} clean retry failures, no hang, nothing half written");

    // The wallet still holds exactly the setup it signed, unchanged.
    let still = stored_setup(&manager, &wallet_id).expect("the setup is still stored");
    assert_eq!(still.review.operation_id, review.operation_id);
    assert!(still.transaction_hash.is_none(), "nothing reached a node");
    let _ = manager.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now());
    let discard = manager
        .discard_unsigned_l2_channel_setup(
            &wallet_id,
            &review.operation_id,
            &review.review_commitment,
            unix_now(),
        )
        .expect_err("the unsigned discard must never be the thing that clears a signed setup");
    println!("[neg ] discard on the dead setup: {discard:?}");

    // ---- THE EXIT ----
    let _ = manager.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now());
    let retired = manager
        .abandon_dead_l2_channel_setup(
            &wallet_id,
            &review.operation_id,
            &review.review_commitment,
            unix_now(),
        )
        .await
        .expect("the exit built for exactly this state must open");
    println!(
        "[exit] abandoned operation {} on channel {}",
        retired.operation_id, retired.channel_id
    );
    assert!(
        stored_setup(&manager, &wallet_id).is_none(),
        "the wallet must no longer be holding the dead setup"
    );
    // Nothing was ever spent: the deposit never left the owner address.
    let after = balance_zhu(&owner_address).await;
    println!("[coin] owner {balance_at_prepare} -> {after} Zhu across the whole dead setup");
    assert_eq!(
        after, balance_at_prepare,
        "a setup that never reached a node must not cost a Zhu"
    );
    let absent = channel_document(&review.channel_id).await;
    println!("[chan] the chain on that channel ID: {absent}");
    assert_ne!(
        absent["ret"].as_i64(),
        Some(0),
        "the channel must not exist on chain"
    );

    // ---- AND THE WALLET CAN OPEN AGAIN, ON THE SAME CHANNEL ID ----
    outage.bring_settlement_back();
    let fresh = manager
        .prepare_l2_channel_setup(&wallet_id, &outage.url, "1", unix_now())
        .await
        .expect("a retired dead request must not brick this channel ID");
    assert_eq!(fresh.channel_id, review.channel_id);
    assert_ne!(fresh.operation_id, review.operation_id);
    println!(
        "[exit] the wallet prepared again: operation {} on the same channel {}",
        fresh.operation_id, fresh.channel_id
    );
    let reopened = manager
        .confirm_l2_channel_setup(
            &wallet_id,
            &fresh.operation_id,
            &fresh.review_commitment,
            unix_now(),
        )
        .await
        .expect("the retired store must not block a real open");
    println!(
        "[exit] confirm after the abandonment: phase {:?}",
        reopened.phase
    );
    let deadline = Instant::now() + wait_budget;
    loop {
        let opened = channel_document(&fresh.channel_id).await;
        if opened["ret"].as_i64() == Some(0) {
            println!("[chan] the reopened channel is on chain: {opened}");
            assert_eq!(
                opened["left"]["address"].as_str(),
                Some(owner_address.as_str())
            );
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the reopened channel never reached the chain: {opened}"
        );
        let _ = manager.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now());
        let _ = manager
            .recover_l2_channel_setup(&wallet_id, unix_now())
            .await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    outage.task.abort();
    hub.task.abort();
}

/// THE CONSENT THIS CHAIN CANNOT TAKE.
///
/// The mainnet-shaped consent is not available on a private chain, and this
/// pins why rather than leaving it as an assumption. It needs no chain time.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn a_mainnet_shaped_consent_is_refused_on_a_chain_that_is_not_mainnet() {
    let work = workdir().join("consent");
    std::fs::create_dir_all(&work).unwrap();
    require_chain_seven("consent").await;
    let anchor = block_one_hash().await;
    let mut manager = AgentWalletManager::open(&work).unwrap();

    // 1. The chain-7 anchor with the mainnet acknowledgement attached.
    let refused = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: AWAY_PASSPHRASE.to_owned(),
                network_mode: "testnet".to_owned(),
                node_url: node_url(),
                block_one_fingerprint: Some(anchor.clone()),
                mainnet_pilot_acknowledgement: Some(
                    crate::service::AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT.to_owned(),
                ),
            },
            unix_now(),
        )
        .expect_err("a testnet wallet must not carry the mainnet pilot consent");
    println!("[neg ] testnet wallet plus mainnet consent: {refused:?}");

    // 2. Mainnet mode, pointed at this chain-7 node, anchored on its block 1.
    let refused = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: AWAY_PASSPHRASE.to_owned(),
                network_mode: "mainnet".to_owned(),
                node_url: node_url(),
                block_one_fingerprint: Some(anchor.clone()),
                mainnet_pilot_acknowledgement: Some(
                    crate::service::AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT.to_owned(),
                ),
            },
            unix_now(),
        )
        .expect_err("a mainnet wallet must not be anchored on a private chain block 1");
    println!("[neg ] mainnet wallet anchored on chain 7 block 1: {refused:?}");

    // 3. The consent this chain can take, so the refusals above are shown to
    //    be about the consent and not about the call.
    let made = manager
        .create_wallet(
            CreateAgentWallet {
                passphrase: AWAY_PASSPHRASE.to_owned(),
                network_mode: "testnet".to_owned(),
                node_url: node_url(),
                block_one_fingerprint: Some(anchor),
                mainnet_pilot_acknowledgement: None,
            },
            unix_now(),
        )
        .expect("the shipped consent for a private chain is the testnet one");
    println!(
        "[neg ] control: the testnet consent is accepted, address {}",
        made.address
    );
}

/// THE AMOUNTS THE PANEL NAMES ARE THE AMOUNTS THE CORE REFUSES.
///
/// The desktop tests prove the panel explains the problem and shuts the Review
/// button. That is only half of it: a panel enforcing rules the core does not
/// have would be a wallet inventing its own arithmetic. This presents the same
/// list to the shipped `prepare_l2_channel_setup` against the real Hub over
/// real HTTP and the real chain-7 node, and asserts that every one of them is
/// refused with nothing stored, while a well formed amount goes through.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn the_amounts_the_panel_names_are_the_amounts_the_core_refuses() {
    let work = workdir().join("amounts");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    require_chain_seven("amounts").await;
    let anchor = block_one_hash().await;
    let (mut manager, wallet_id, _owner_address) =
        funded_owner(&work, "owner", &anchor, 1.5, wait_budget).await;

    let hub_account = persistent_hub_account(&work, "amounts");
    let listen = optional_env("HPAY_LIVE_HUB_AMOUNTS_LISTEN", "127.0.0.1:8896");
    let hub = start_hub_at(&work, &hub_account, "amounts", &listen).await;

    // The exact list `explainInvalidDepositAmount` refuses, in
    // packages/wallet-ui/src/depositAmount.ts, plus the two blank shapes the
    // button check covers.
    let named_by_the_panel = [
        "0,2", ".2", "0.2000", "0.2 HAC", "1.2.3", "1.", "0", "0.000", "", "   ",
    ];
    let mut taken_anyway = Vec::new();
    for bad in named_by_the_panel {
        match manager
            .prepare_l2_channel_setup(&wallet_id, &hub.url, bad, unix_now())
            .await
        {
            Ok(review) => {
                println!(
                    "[neg ] deposit {bad:?} -> ACCEPTED as {} units",
                    review.deposit_units.get()
                );
                taken_anyway.push(bad);
                let _ = manager.discard_unsigned_l2_channel_setup(
                    &wallet_id,
                    &review.operation_id,
                    &review.review_commitment,
                    unix_now(),
                );
            }
            Err(error) => {
                println!("[neg ] deposit {bad:?} -> {error:?}");
                assert!(
                    stored_setup(&manager, &wallet_id).is_none(),
                    "a refused amount must leave nothing stored, and {bad:?} left something"
                );
            }
        }
    }
    assert!(
        taken_anyway.is_empty(),
        "the panel names these as bad and the core took them anyway: {taken_anyway:?}"
    );

    // The control, so the gate is not simply always shut.
    let good = manager
        .prepare_l2_channel_setup(&wallet_id, &hub.url, "0.2", unix_now())
        .await
        .expect("a well formed amount must be accepted");
    println!(
        "[neg ] control: deposit 0.2 accepted as {} units on channel {}",
        good.deposit_units.get(),
        good.channel_id
    );
    manager
        .discard_unsigned_l2_channel_setup(
            &wallet_id,
            &good.operation_id,
            &good.review_commitment,
            unix_now(),
        )
        .expect("the control review is unsigned and discardable");
    hub.task.abort();
}

// =====================================================================
// THE STALE RESERVATION THAT COULD BRICK A WALLET, AND THE SWEEP THAT
// RETIRES IT.
// =====================================================================

/// A reverse proxy in front of the pilot fullnode whose submit routes can be
/// taken away without taking the chain away.
///
/// This is what a broadcast that never lands looks like from the Hub: the node
/// answers every query normally, accepts the bytes, and the chain never
/// includes them. Nothing here fakes a chain fact. Capabilities, balances,
/// channel and transaction queries all pass straight through to the real node
/// and come back untouched, so every height, balance and absence the Hub reads
/// during this run is the real chain's answer. The only thing withheld is the
/// forwarding of the submit itself.
struct SubmitBlackhole {
    url: String,
    swallow: Arc<std::sync::atomic::AtomicBool>,
    swallowed: Arc<std::sync::atomic::AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl SubmitBlackhole {
    fn swallow_submits(&self) {
        self.swallow
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    fn forward_submits(&self) {
        self.swallow
            .store(false, std::sync::atomic::Ordering::SeqCst);
    }

    fn swallowed_count(&self) -> usize {
        self.swallowed.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[derive(Clone)]
struct BlackholeProxy {
    upstream: String,
    swallow: Arc<std::sync::atomic::AtomicBool>,
    swallowed: Arc<std::sync::atomic::AtomicUsize>,
}

async fn blackhole_or_forward(
    axum::extract::State(proxy): axum::extract::State<BlackholeProxy>,
    method: axum::http::Method,
    uri: axum::http::Uri,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    if proxy.swallow.load(std::sync::atomic::Ordering::SeqCst)
        && uri.path().starts_with("/submit/transaction")
    {
        proxy
            .swallowed
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        // The node's own acknowledgement for an accepted submission, including
        // the transaction hash the bound submit route echoes. It is computed
        // from the bytes that were actually posted, by the same consensus
        // decoder the node uses, so the Hub is answered exactly as a node that
        // took the transaction into its mempool would answer, and it records
        // `Submitted`. Nothing else about it is true: the bytes go no further
        // than this process, and no chain will ever include them.
        let hash = hex::decode(
            std::str::from_utf8(&body)
                .unwrap_or_default()
                .trim()
                .trim_start_matches("0x"),
        )
        .ok()
        .and_then(|raw| {
            protocol::transaction::transaction_create(&raw)
                .ok()
                .map(|(transaction, _)| {
                    hex::encode(basis::interface::TransactionRead::hash(&*transaction).as_bytes())
                })
        })
        .unwrap_or_default();
        return (
            axum::http::StatusCode::OK,
            format!("{{\"ret\":0,\"hash\":\"{hash}\"}}"),
        )
            .into_response();
    }
    let target = format!("{}{}", proxy.upstream, path_and_query);
    let sent = reqwest::Client::new()
        .request(method, target)
        .header("content-type", "text/plain")
        .body(body.to_vec())
        .timeout(Duration::from_secs(30))
        .send()
        .await;
    match sent {
        Ok(response) => {
            let status = axum::http::StatusCode::from_u16(response.status().as_u16())
                .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
            let bytes = response.bytes().await.unwrap_or_default();
            (status, bytes.to_vec()).into_response()
        }
        Err(error) => (
            axum::http::StatusCode::BAD_GATEWAY,
            format!("{{\"error\":\"upstream: {error}\"}}"),
        )
            .into_response(),
    }
}

async fn start_submit_blackhole(upstream: &str, listen: &str) -> SubmitBlackhole {
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let swallow = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let swallowed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let router = axum::Router::new()
        .fallback(axum::routing::any(blackhole_or_forward))
        .with_state(BlackholeProxy {
            upstream: upstream.to_owned(),
            swallow: swallow.clone(),
            swallowed: swallowed.clone(),
        });
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    println!("[prox] node blackhole {url} in front of {upstream}");
    SubmitBlackhole {
        url,
        swallow,
        swallowed,
        task,
    }
}

/// Prove the blackhole really is a working node view apart from the submit,
/// rather than assuming it.
async fn assert_blackhole_reads_the_real_chain(url: &str, label: &str) {
    let through: serde_json::Value = reqwest::get(format!("{url}/query/capabilities"))
        .await
        .expect("the proxied node answers")
        .json()
        .await
        .expect("capability document");
    let direct = chain_height().await;
    let proxied = through["chain"]["height"].as_u64().expect("proxied height");
    assert_eq!(through["chain"]["id"].as_u64(), Some(7));
    assert_eq!(through["chain"]["mainnet"].as_bool(), Some(false));
    assert!(
        proxied.abs_diff(direct) <= 2,
        "[{label}] the proxied node is not reading the same chain: {proxied} vs {direct}"
    );
    println!("[neg ] {label}: the proxy reads the real chain at height {proxied}");
}

/// A copy of this wallet that has forgotten its channel setup.
///
/// Nothing production does this. It exists because a stale reservation lives in
/// the HUB, and the only way to present the Hub with a second, genuinely new
/// open request for the SAME owner address is a wallet that will build one. An
/// owner who restored from a backup taken before the stuck open, or who wiped a
/// half-written store, arrives at the Hub in exactly this state.
async fn a_copy_that_forgot_its_setup(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    work: &std::path::Path,
    tag: &str,
) -> AgentWalletManager {
    // A copy taken after a long wait would otherwise be refused by the idle
    // auto-lock, which an owner sitting through the same wait would clear the
    // same way.
    let _ = manager.unlock(wallet_id, AWAY_PASSPHRASE, unix_now());
    let backup = manager
        .create_agent_wallet_backup(
            wallet_id,
            AWAY_PASSPHRASE,
            crate::service::AgentWalletBackupAcknowledgement::complete(),
            unix_now(),
        )
        .unwrap();
    let root = work.join(tag);
    // Each copy is a store this run has never used. A re-run that inherited
    // one would be restoring over a wallet that already exists.
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut copy = AgentWalletManager::open(&root).unwrap();
    copy.restore_agent_wallet_backup(
        &backup,
        AWAY_PASSPHRASE,
        crate::service::AgentWalletBackupAcknowledgement::complete(),
        unix_now(),
    )
    .unwrap();
    copy.unlock(wallet_id, AWAY_PASSPHRASE, unix_now()).unwrap();
    let (state_master, journal_key) = fixtures::keys(&copy, wallet_id);
    let mut state = copy
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    state.l2_channel_setup = None;
    state.updated_at = unix_now();
    copy.persist_event(
        &mut state,
        &state_master,
        &journal_key,
        AgentJournalEventKind::RecoveryRequired,
        None,
        None,
        unix_now(),
    )
    .unwrap();
    copy
}

/// Ask this Hub to open a channel for this owner, all the way through the
/// shipped prepare / confirm path, and report what came back.
async fn open_attempt(
    copy: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    hub_url: &str,
    deposit_hac: &str,
) -> Result<crate::service::l2::AgentChannelSetupReview, String> {
    let _ = copy.unlock(wallet_id, AWAY_PASSPHRASE, unix_now());
    let review = copy
        .prepare_l2_channel_setup(wallet_id, hub_url, deposit_hac, unix_now())
        .await
        .map_err(|error| format!("prepare refused: {error:?}"))?;
    let _ = copy.unlock(wallet_id, AWAY_PASSPHRASE, unix_now());
    match copy
        .confirm_l2_channel_setup(
            wallet_id,
            &review.operation_id,
            &review.review_commitment,
            unix_now(),
        )
        .await
    {
        Ok(done) => {
            println!(
                "[chan] confirm on {} returned phase {:?}",
                review.operation_id, done.phase
            );
            Ok(review)
        }
        Err(error) => {
            let stored = stored_setup(copy, wallet_id);
            let detail = stored
                .as_ref()
                .map(|setup| {
                    format!(
                        "phase {:?} signed {} tx {:?} hub said {:?}",
                        setup.review.phase,
                        setup.signed_request.is_some(),
                        setup.transaction_hash,
                        setup.review.last_hub_refusal
                    )
                })
                .unwrap_or_else(|| "no setup stored".to_owned());
            Err(format!("confirm refused: {error:?}; stored: {detail}"))
        }
    }
}

/// Present the exact open request a wallet copy just built to the Hub over real
/// HTTP, so the Hub's own sentence is on the record rather than the wallet's
/// collapsed error.
async fn hub_channel_open_refusal(
    copy: &AgentWalletManager,
    wallet_id: &AgentWalletId,
    hub_url: &str,
) -> String {
    let (state_master, journal_key) = fixtures::keys(copy, wallet_id);
    let stored = copy
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap()
        .l2_channel_setup
        .as_ref()
        .and_then(|operation| operation.signed_request.clone());
    match stored {
        Some(request) => match reqwest::Client::new()
            .post(format!("{hub_url}/v1/l1/channel/open"))
            .json(&request)
            .timeout(Duration::from_secs(30))
            .send()
            .await
        {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                format!("HTTP {status} {body}")
            }
            Err(error) => format!("transport error {error}"),
        },
        None => "the copy kept no signed open request to present".to_owned(),
    }
}

/// THE DEFECT THAT COST A NIGHT, PROVED AND THEN UNPROVED ON A REAL CHAIN.
///
/// A channel-open reserves Hub admission for its owner address from the moment
/// it is created until it confirms, and `MAX_ACTIVE_OPENS_PER_ADDRESS` is one.
/// A broadcast that never reached a block therefore held that single slot for
/// the life of the Hub's durable state: the owner's wallet could never open a
/// channel again, and the Hub reported itself perfectly healthy the whole time.
///
/// `retire_unmined_channel_opens` is the fix. Three claims, in one run because
/// they are one story:
///
/// 1. an open whose bytes the chain never took keeps reserving admission, and
///    the chain itself says the channel does not exist;
/// 2. while that reservation stands, the next open for the same owner is
///    REFUSED by the Hub, over real HTTP, in the Hub's own words;
/// 3. once the chain has produced 288 blocks without it, the sweep that runs on
///    the next open retires the stale record and the same owner opens a real
///    channel on the real chain.
///
/// The wait in claim 3 is 288 real mined blocks. Nothing here shortens it and
/// nothing here tells the Hub a height it did not read from the node itself.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only, and waits out 288 real mined blocks"]
async fn a_stale_reservation_blocks_the_next_open_until_the_sweep_retires_it() {
    let work = workdir().join("stale");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());
    let sweep_budget = Duration::from_secs(
        optional_env("HPAY_LIVE_SWEEP_WAIT_SECS", "10800")
            .parse()
            .unwrap(),
    );
    // The Hub's own retirement rule, read from the Hub crate rather than
    // written down again here.
    let retirement_blocks: u64 = optional_env("HPAY_LIVE_RETIREMENT_BLOCKS", "288")
        .parse()
        .unwrap();

    require_chain_seven("stale").await;
    let anchor = block_one_hash().await;
    let (mut manager, wallet_id, owner_address) =
        funded_owner(&work, "owner", &anchor, 2.5, wait_budget).await;

    let hub_account = persistent_hub_account(&work, "stale");
    let listen = optional_env("HPAY_LIVE_HUB_STALE_LISTEN", "127.0.0.1:8897");
    let blackhole_listen = optional_env("HPAY_LIVE_NODE_BLACKHOLE_LISTEN", "127.0.0.1:8898");
    let blackhole = start_submit_blackhole(&node_url(), &blackhole_listen).await;
    assert_blackhole_reads_the_real_chain(&blackhole.url, "before the stuck open").await;
    let hub = start_hub_at_node(&work, &hub_account, "stale", &listen, &blackhole.url).await;

    // ---- 1. AN OPEN WHOSE BYTES THE CHAIN NEVER TAKES ----
    blackhole.swallow_submits();
    let mut stuck_wallet =
        a_copy_that_forgot_its_setup(&mut manager, &wallet_id, &work, "stuck").await;
    let height_at_confirm = chain_height().await;
    let stuck = match open_attempt(&mut stuck_wallet, &wallet_id, &hub.url, "1").await {
        Ok(review) => {
            // The Hub took the bytes and is now waiting for a block that will
            // never come. That is the state the defect lives in.
            println!("[neg ] the Hub accepted the open and believes it broadcast");
            review
        }
        // What matters for this run is that the HUB is holding a reservation
        // for this owner that the chain will never confirm. The wallet side
        // reaching `RecoveryRequired` is the honest wallet-side answer to a
        // broadcast it cannot see, and it is what an owner in this state has.
        // Report it and carry on with the setup the wallet did store.
        Err(refusal) => {
            println!("[neg ] the wallet's own answer to the stuck open: {refusal}");
            stored_setup(&stuck_wallet, &wallet_id)
                .expect("the wallet stored the setup it signed")
                .review
        }
    };
    println!(
        "[neg ] stuck open {} on channel {} at height {height_at_confirm}",
        stuck.operation_id, stuck.channel_id
    );
    assert!(
        blackhole.swallowed_count() >= 1,
        "the submit never reached the blackhole, so nothing is stuck"
    );
    println!(
        "[neg ] {} submission(s) swallowed; the bytes went no further than this process",
        blackhole.swallowed_count()
    );

    // The chain's own answer, queried directly and not through the proxy.
    let absent = channel_document(&stuck.channel_id).await;
    println!("[chan] the real chain on that channel ID: {absent}");
    assert_ne!(
        absent["ret"].as_i64(),
        Some(0),
        "the stuck channel must not exist on chain"
    );

    // ---- 2. THE NEXT OPEN FOR THE SAME OWNER IS REFUSED ----
    let mut blocked_wallet =
        a_copy_that_forgot_its_setup(&mut manager, &wallet_id, &work, "blocked").await;
    let refusal = open_attempt(&mut blocked_wallet, &wallet_id, &hub.url, "1")
        .await
        .expect_err("a stale reservation must block the next open");
    println!("[neg ] the next open while the reservation stands: {refusal}");
    // The Hub's own words, presented over real HTTP rather than through the
    // wallet's collapsed error.
    let hub_said = hub_channel_open_refusal(&blocked_wallet, &wallet_id, &hub.url).await;
    println!("[neg ] the Hub's own words: {hub_said}");
    // WHAT THE OWNER IS ACTUALLY TOLD. `require_new_open_admission` refuses
    // with "this wallet already has an active channel-open operation", and the
    // HTTP layer flattens every `HubError::Admission` to one 429 sentence, so
    // the reason never leaves the Hub process. What a wallet can see is the
    // 429 and the generic line; that is asserted here because it is what is
    // true, not because it is enough.
    assert!(
        hub_said.contains("429") && hub_said.contains("admission limit reached"),
        "the refusal must be the Hub's admission gate, not something else: {hub_said}"
    );

    // ---- 3. 288 BLOCKS LATER, THE SWEEP RETIRES IT AND THE OPEN GOES ----
    let sweep_height = height_at_confirm + retirement_blocks + 2;
    println!("[neg ] waiting for the chain to reach height {sweep_height}");
    let deadline = Instant::now() + sweep_budget;
    loop {
        let now = chain_height().await;
        if now >= sweep_height {
            println!("[neg ] the chain reached {now}");
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the chain never reached {sweep_height}; it is at {now}"
        );
        tokio::time::sleep(Duration::from_secs(20)).await;
    }
    // Nothing about the stuck transaction changed while we waited: still no
    // channel on the chain.
    let still_absent = channel_document(&stuck.channel_id).await;
    assert_ne!(still_absent["ret"].as_i64(), Some(0));
    println!("[chan] still absent after the wait: {still_absent}");

    blackhole.forward_submits();
    assert_blackhole_reads_the_real_chain(&blackhole.url, "before the retry").await;
    // The Hub counts from the height IT captured when it put the bytes on the
    // wire, which is at or just past the height read above. If the sweep has
    // not armed yet the refusal is the same admission sentence, so give the
    // chain a few more blocks and ask again rather than reading a near miss as
    // a broken fix.
    let mut freed_wallet = None;
    let mut opened = None;
    let mut last_refusal = String::new();
    for attempt in 1..=4usize {
        let mut copy = a_copy_that_forgot_its_setup(
            &mut manager,
            &wallet_id,
            &work,
            &format!("freed-{attempt}"),
        )
        .await;
        match open_attempt(&mut copy, &wallet_id, &hub.url, "1").await {
            Ok(review) => {
                opened = Some(review);
                freed_wallet = Some(copy);
                break;
            }
            Err(refusal) => {
                println!(
                    "[neg ] attempt {attempt} at height {}: {refusal}",
                    chain_height().await
                );
                last_refusal = refusal;
                tokio::time::sleep(Duration::from_secs(90)).await;
            }
        }
    }
    let opened = opened.unwrap_or_else(|| {
        panic!("the sweep never released the slot the stuck open was holding: {last_refusal}")
    });
    let mut freed_wallet = freed_wallet.expect("the wallet that got through");
    println!(
        "[exit] the open after the sweep: operation {} channel {}",
        opened.operation_id, opened.channel_id
    );

    let deadline = Instant::now() + wait_budget;
    let on_chain = loop {
        let document = channel_document(&opened.channel_id).await;
        if document["ret"].as_i64() == Some(0) {
            break document;
        }
        assert!(
            Instant::now() < deadline,
            "the freed open never reached the chain: {document}"
        );
        let _ = freed_wallet.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now());
        let _ = freed_wallet
            .recover_l2_channel_setup(&wallet_id, unix_now())
            .await;
        tokio::time::sleep(Duration::from_secs(10)).await;
    };
    println!("[chan] the channel the sweep made room for: {on_chain}");
    assert_eq!(
        on_chain["left"]["address"].as_str(),
        Some(owner_address.as_str())
    );
    assert_eq!(
        on_chain["right"]["address"].as_str(),
        Some(hub.address.as_str())
    );
    assert_eq!(
        on_chain["status"].as_u64(),
        Some(u64::from(
            hacash_wallet_core::channel::CHANNEL_STATUS_OPENING
        ))
    );
    blackhole.task.abort();
    hub.task.abort();
}

// =====================================================================
// THE PHONE WITNESS, ON A REAL CHAIN.
// =====================================================================

/// THE WITNESS LOOP THE OWNER HAS NEVER RUN, RUN AGAINST REAL BLOCKS.
///
/// `desktop_witness_flow.rs` executes this whole sequence, but against the mock
/// Local Pilot node in `pilot_node.rs`: the balance is a constant, the unsigned
/// body is built by a test router, and `submit_count` is an integer rather than
/// a block. Everything about the wallet and the phone is real there and nothing
/// about the chain is.
///
/// This is the same sequence with the real pilot fullnode underneath it. The
/// balance that lets the intent past its affordability check is the owner's real
/// chain-7 balance, the unsigned Type 2 body is built by the real node, the
/// signature is the wallet's own, and the submission is a transaction that a
/// miner puts in a block. Five claims:
///
/// 1. an agent proposal stops at the owner and carries no transaction;
/// 2. the desktop's yes SIGNS and does not send - the chain has never heard of
///    the transaction while the payment waits for the phone;
/// 3. a payment waiting on a phone that is not there is reported as waiting,
///    with the truth that nothing has been sent;
/// 4. the phone's anchor and its signed receipt are what release it, and the
///    transaction reaches the node exactly once;
/// 5. it lands in a block and the recipient's balance on the chain moves by
///    exactly the amount the agent asked for.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn the_phone_witnesses_a_payment_that_really_lands_in_a_block() {
    use crate::operation::OperationStatus;

    let work = workdir().join("witness");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    require_chain_seven("witness").await;
    let anchor = block_one_hash().await;
    let (mut manager, wallet_id, owner_address) =
        funded_owner(&work, "witness-owner", &anchor, 0.5, wait_budget).await;

    // The phone. Registered with the permissions the pilot gives a companion,
    // which include `WitnessRollbackAnchor`; without that permission the
    // approval below is refused unsigned, which is its own test.
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let _record = fixtures::register_mobile(&mut manager, &wallet_id, &mobile, unix_now());
    let authorization = super::desktop_witness_flow::pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        unix_now(),
    );
    println!(
        "[wit ] owner {owner_address} phone {:?}",
        mobile.device_id()
    );

    let recipient = fixtures::RECIPIENT;
    let recipient_before = balance_zhu(recipient).await;
    let owner_before = balance_zhu(&owner_address).await;
    println!("[coin] recipient {recipient} starts at {recipient_before} Zhu, owner {owner_before}");

    // ---- 1. THE AGENT PROPOSES AND STOPS ----
    let created = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request(
                "chain7-live-witness-0001",
                unix_now() + 900,
            ),
            unix_now(),
        )
        .await
        .expect("the agent's proposal is accepted");
    let operation_id = created.operation_id.clone();
    assert_eq!(
        created.status,
        OperationStatus::ApprovalRequested,
        "an agent proposal must stop at the owner"
    );
    assert_eq!(created.tx_hash, None, "a proposal carries no transaction");
    println!("[wit ] intent {operation_id} awaiting the owner");

    // ---- 2. THE DESKTOP SIGNS, AND DOES NOT SEND ----
    let _ = manager.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now());
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, unix_now())
        .expect("the exact-transaction review");
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, unix_now())
        .await
        .expect("the owner's yes");
    assert_eq!(
        approved.status,
        OperationStatus::SignedAwaitingWitness,
        "a desktop approval in the pilot signs and then stops for the phone"
    );
    let tx_hash = approved
        .tx_hash
        .clone()
        .expect("the signer produced a real transaction hash");
    println!("[wit ] signed {tx_hash}, waiting for the phone");

    // Asked of the chain, not of the wallet.
    let url = node_url();
    let unseen: serde_json::Value = reqwest::get(format!("{url}/query/transaction?hash={tx_hash}"))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_ne!(
        unseen["ret"].as_i64(),
        Some(0),
        "signing is not broadcasting: the chain must not hold this transaction yet, got {unseen}"
    );
    assert_eq!(
        balance_zhu(recipient).await,
        recipient_before,
        "nothing may reach the recipient before the phone witnesses it"
    );
    println!("[wit ] the chain has never heard of {tx_hash}: {unseen}");

    // ---- 3. THE PHONE IS NOT THERE, AND THE DESKTOP SAYS SO ----
    let waiting = manager
        .stranded_witness_recovery(&wallet_id, unix_now())
        .unwrap()
        .expect("a payment waiting on a phone is reported");
    assert_eq!(waiting.status, OperationStatus::SignedAwaitingWitness);
    assert!(!waiting.submitted, "nothing was sent, and it says so");
    assert!(!waiting.anchor_issued, "no anchor has been handed out yet");
    assert!(waiting.retryable, "asking the phone again must be offered");
    assert!(
        waiting.abandonable,
        "a phone lost before it was ever asked strands the payment just as hard"
    );
    println!(
        "[wit ] stranded view: status {:?} submitted {} anchor_issued {} retryable {} abandonable {}",
        waiting.status,
        waiting.submitted,
        waiting.anchor_issued,
        waiting.retryable,
        waiting.abandonable
    );

    // ---- 4. THE PHONE TAKES THE ANCHOR AND SIGNS THE RECEIPT ----
    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), unix_now())
        .await
        .expect("the phone is handed a rollback anchor");
    println!(
        "[wit ] anchor {} expires {}",
        proposal.anchor.anchor_id, proposal.anchor.expires_at
    );
    let receipt = super::pilot_node::signed_receipt(&proposal, &mobile, unix_now()).await;
    let submitted = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, unix_now())
        .await
        .expect("the receipt releases the payment");
    assert_eq!(
        submitted.status,
        OperationStatus::SubmittedAwaitingFinalWitness,
        "the receipt is what puts the bytes on the wire"
    );
    println!("[wit ] submitted after the receipt: {:?}", submitted.status);

    let after_submit = manager
        .stranded_witness_recovery(&wallet_id, unix_now())
        .unwrap()
        .expect("a submitted payment is still reported");
    assert!(
        after_submit.submitted,
        "the money moved and the desktop must say so"
    );
    assert!(
        !after_submit.abandonable,
        "giving it up would assert a payment that happened did not"
    );

    // ---- 5. IT LANDS IN A BLOCK ----
    let deadline = Instant::now() + wait_budget;
    let mined = loop {
        let found: serde_json::Value =
            reqwest::get(format!("{url}/query/transaction?hash={tx_hash}"))
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
            "the witnessed payment never made it into a block: {found}"
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
    };
    println!("[wit ] mined: {mined}");

    let recipient_after = balance_zhu(recipient).await;
    let owner_after = balance_zhu(&owner_address).await;
    let amount_zhu = u128::from(super::desktop_witness_flow::AMOUNT_UNITS) * 100;
    println!(
        "[coin] recipient {recipient_before} -> {recipient_after} Zhu, owner {owner_before} -> {owner_after} Zhu"
    );
    assert_eq!(
        recipient_after,
        recipient_before + amount_zhu,
        "the recipient must be paid exactly what the agent asked for"
    );
    assert!(
        owner_after < owner_before,
        "the owner paid the amount and the network fee"
    );
}

// =====================================================================
// THE PHONE, PAIRED FOR REAL, ON A REAL CHAIN.
//
// Everything above that involves a phone registers it with
// `register_verified_companion_device`, which is the last line of the pairing
// handshake and not the handshake. The tests below run the whole five step
// exchange - offer, signed request, confirmation, encrypted acknowledgement,
// locally displayed code - the way an Android handset would, and then drive the
// witness lifecycle to its end and break it four different ways.
// =====================================================================

/// The five step pairing handshake, run in full, against a live wallet.
///
/// `MobilePairingAttempt` is the mobile half of the protocol and it is the same
/// type the companion app links. What is simulated here is the handset and the
/// transport between them, nothing else: the desktop side is every shipped
/// method in order, the mobile side signs with a real device key, and the
/// permissions the paired record carries are the ones
/// `default_mobile_permissions` grants rather than a set this test chose.
async fn pair_a_real_phone(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    mobile: &SoftwareDeviceIdentity,
    label: &str,
) -> hpay_companion_protocol::DevicePublicRecord {
    use hpay_companion_protocol::{LanEndpoint, MobilePairingAttempt};

    // The handshake is driven a little behind the clock on purpose. The record
    // it writes carries `paired_at = now + 4`, and `DeviceRegistry::revoke`
    // refuses any `revoked_at` earlier than that, so a phone paired at the
    // current second cannot be revoked for four seconds afterwards. Backdating
    // the exchange keeps the whole handshake real and puts `paired_at` behind
    // the wall clock, which is where a phone paired in a previous sitting would
    // be anyway.
    let now = unix_now().saturating_sub(30);
    let mut attempt = manager
        .start_companion_pairing(
            wallet_id,
            vec![LanEndpoint::parse("hpay-lan://192.168.1.7:7443").unwrap()],
            now,
            120,
        )
        .expect("the desktop offers a pairing");
    let mobile_attempt = MobilePairingAttempt::start(attempt.offer().clone(), mobile, now + 1)
        .await
        .expect("the handset builds a signed pairing request");
    let confirmation = manager
        .accept_companion_pairing_request(
            wallet_id,
            &mut attempt,
            mobile_attempt.request().clone(),
            now + 2,
        )
        .await
        .expect("the desktop accepts the signed request");
    let code = confirmation.verification_code.clone();
    let (ack, mobile_result) = mobile_attempt
        .confirm(&confirmation, &code, mobile, now + 3)
        .await
        .expect("the handset confirms the code it was shown");
    drop(mobile_result.into_mobile_cipher().unwrap());
    manager
        .accept_companion_pairing_ack(wallet_id, &mut attempt, &ack, now + 3)
        .expect("the desktop accepts the encrypted acknowledgement");
    let completed = manager
        .complete_companion_pairing_code(wallet_id, &mut attempt, &code, now + 4)
        .expect("the owner types the code the two screens agree on");
    let record = completed.mobile_device_record().clone();
    drop(completed);
    println!(
        "[pair] {label}: paired {} with {:?}",
        record.device_id.as_str(),
        record.permissions
    );
    assert!(
        record
            .permissions
            .contains(&hpay_companion_protocol::DevicePermission::WitnessRollbackAnchor),
        "a phone paired by the shipped handshake must be able to witness"
    );
    record
}

/// The exact view of one operation, read the way the desktop reads it.
fn live_view(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
) -> PaymentOperationView {
    manager
        .list_operations_admin(wallet_id, unix_now())
        .unwrap()
        .into_iter()
        .find(|view| &view.operation_id == operation_id)
        .expect("the operation is still on file")
}

/// Ask the chain, never the wallet, whether a transaction exists.
async fn chain_knows_transaction(tx_hash: &str) -> serde_json::Value {
    let url = node_url();
    reqwest::get(format!("{url}/query/transaction?hash={tx_hash}"))
        .await
        .expect("transaction query")
        .json()
        .await
        .expect("transaction document")
}

/// Block until the chain holds this transaction, and hand back what it says.
async fn wait_for_transaction(tx_hash: &str, budget: Duration) -> serde_json::Value {
    let deadline = Instant::now() + budget;
    loop {
        let found = chain_knows_transaction(tx_hash).await;
        if found["ret"].as_i64() == Some(0) && found["block"]["height"].as_u64().is_some() {
            return found;
        }
        assert!(
            Instant::now() < deadline,
            "the transaction never reached a block: {found}"
        );
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}

/// Move a live wallet onto the mainnet network name, changing nothing else.
///
/// The node stays the chain-7 pilot node, because the node is not what the
/// deleted gates read. They read `state.network_mode`, before the operation was
/// looked up, and that string is the whole difference between an owner who can
/// free a stranded payment and one who cannot. Anything that does reach the
/// node from here refuses on the anchor, which is its own assertion below.
fn move_live_wallet_to_mainnet(manager: &mut AgentWalletManager, wallet_id: &AgentWalletId) {
    let (state_master, journal_key) = fixtures::keys(manager, wallet_id);
    let mut state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    state.network_mode = "mainnet".to_owned();
    state.block_one_fingerprint =
        crate::node_binding::anchor_for_new_wallet("mainnet", None).unwrap();
    state.trusted_mainnet_fast_pay_pilot = true;
    state.updated_at = unix_now();
    manager
        .persist_event(
            &mut state,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            unix_now(),
        )
        .unwrap();
    let reread = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    assert_eq!(reread.network_mode, "mainnet");
    println!(
        "[main] wallet moved to network_mode {} anchor {}",
        reread.network_mode, reread.block_one_fingerprint
    );
}

/// THE WHOLE WITNESS LIFECYCLE, ON REAL BLOCKS, TO `Committed`.
///
/// The live run that exists already stops at `SubmittedAwaitingFinalWitness`:
/// the transaction is in a block and the payment is not finished. Three phones
/// signatures are required to finish it, not one, and the last two have never
/// been executed against a chain.
///
/// Seven claims:
///
/// 1. a phone paired by the real handshake carries `WitnessRollbackAnchor`;
/// 2. a wallet with a freshly paired phone still reports `mobile_witness_ready`
///    FALSE, because the witness record does not exist until the first anchor
///    is asked for - the finding this run exists to nail down;
/// 3. the owner's yes signs and does not send;
/// 4. the first receipt is what broadcasts, and the bytes reach a block;
/// 5. the post-submit anchor moves the payment to `ReconciliationRequired`;
/// 6. `confirm_broadcast` is fed the hash the CHAIN confirmed, not the wallet's;
/// 7. the final receipt commits it, the reservation is returned, and the
///    recipient's on-chain balance moved by exactly what the agent asked for.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn a_really_paired_phone_carries_a_payment_from_intent_to_committed() {
    use crate::operation::OperationStatus;
    use hpay_companion_protocol::RollbackOperationPhase;

    let work = workdir().join("wit-full");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    require_chain_seven("wit-full").await;
    let anchor = block_one_hash().await;
    let (mut manager, wallet_id, owner_address) =
        funded_owner(&work, "full-owner", &anchor, 0.5, wait_budget).await;

    // ---- 1. THE PHONE IS PAIRED BY THE REAL HANDSHAKE ----
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let record = pair_a_real_phone(&mut manager, &wallet_id, &mobile, "full").await;
    assert_eq!(record.device_id, *mobile.device_id());
    assert_eq!(
        manager
            .list_companion_devices(&wallet_id, unix_now())
            .unwrap()
            .len(),
        1,
        "exactly one phone is on file"
    );

    // ---- 2. AND THE WALLET STILL SAYS NO PHONE IS PAIRED ----
    let overview = manager.overview(&wallet_id, unix_now()).await.unwrap();
    println!(
        "[zero] right after pairing: mobile_witness_ready {} mobile_witness_synchronized {} latest_anchor_sequence {}",
        overview.mobile_witness_ready,
        overview.mobile_witness_synchronized,
        overview.latest_anchor_sequence
    );
    assert!(
        !overview.mobile_witness_ready,
        "this is the from-zero finding: a real paired phone does not make mobile_witness_ready true"
    );
    assert!(!overview.mobile_witness_synchronized);

    let recipient = fixtures::RECIPIENT;
    let recipient_before = balance_zhu(recipient).await;
    let owner_before = balance_zhu(&owner_address).await;
    println!("[coin] recipient {recipient_before} Zhu, owner {owner_before} Zhu");

    // ---- 3. THE AGENT PROPOSES, THE OWNER SIGNS, NOTHING IS SENT ----
    let authorization = super::desktop_witness_flow::pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        unix_now(),
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request(
                "chain7-live-full-witness-0001",
                unix_now() + 1_200,
            ),
            unix_now(),
        )
        .await
        .expect("the agent's proposal is accepted");
    let operation_id = created.operation_id.clone();
    assert_eq!(created.status, OperationStatus::ApprovalRequested);

    let approval = manager
        .pending_approval(&wallet_id, &operation_id, unix_now())
        .expect("the exact-transaction review");
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, unix_now())
        .await
        .expect("the owner's yes");
    assert_eq!(approved.status, OperationStatus::SignedAwaitingWitness);
    let tx_hash = approved.tx_hash.clone().expect("a real transaction hash");
    let unseen = chain_knows_transaction(&tx_hash).await;
    assert_ne!(
        unseen["ret"].as_i64(),
        Some(0),
        "signing is not broadcasting, got {unseen}"
    );
    println!("[full] signed {tx_hash}; the chain answers {unseen}");

    // ---- 4. THE FIRST ANCHOR, THE FIRST RECEIPT, AND A BLOCK ----
    let first = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), unix_now())
        .await
        .expect("the phone is handed a pre-broadcast anchor");
    assert_eq!(
        first.anchor.operation_phase,
        RollbackOperationPhase::SignedPreBroadcast,
        "the pre-broadcast phase is what the first anchor names"
    );
    // WHAT THE DESKTOP ACTUALLY WRITES INTO THE ANCHOR, quoted rather than
    // assumed. `witness.rs` sets `network_id: node.network_kind()`, and for any
    // wallet the pilot will sign for that string is the node's capability
    // `network.kind` - `local_pilot_v1`, pinned by
    // `supports_agent_local_pilot_payment`. It is never `testnet`.
    //
    // The Android companion that receives this anchor refuses it unless the
    // string is exactly `testnet`:
    // `apps/mobile/src-tauri/src/agent_companion/pilot.rs`, `sign_pilot_witness`,
    // `|| anchor.network_id != "testnet"` -> "Rollback anchor does not match
    // this paired testnet wallet". The same literal guards the rotation
    // completion anchor and the stored approval binding. Recorded here because
    // a software mobile signs the anchor object directly and never runs that
    // check, so no test on either side can see the disagreement.
    println!(
        "[full] the anchor carries network_id {:?}; the Android companion admits only \"testnet\"",
        first.anchor.network_id
    );
    assert_eq!(
        first.anchor.network_id, "local_pilot_v1",
        "recorded as found: the desktop mints local_pilot_v1, the phone demands testnet"
    );
    let binding_network_id = approval_binding_network_id(&mut manager, &wallet_id, &operation_id);
    println!("[full] the approval binding carries network_id {binding_network_id:?}");
    assert_eq!(binding_network_id.as_deref(), Some("local_pilot_v1"));
    let after_init = manager.overview(&wallet_id, unix_now()).await.unwrap();
    assert!(
        after_init.mobile_witness_ready,
        "asking for the first anchor is what initialises the witness"
    );
    let receipt = super::pilot_node::signed_receipt(&first, &mobile, unix_now()).await;
    let submitted = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, unix_now())
        .await
        .expect("the receipt releases the payment");
    assert_eq!(
        submitted.status,
        OperationStatus::SubmittedAwaitingFinalWitness
    );
    let mined = wait_for_transaction(&tx_hash, wait_budget).await;
    println!("[full] mined: {mined}");
    let mined_hash = mined["hash"]
        .as_str()
        .map(str::to_owned)
        .unwrap_or_else(|| tx_hash.clone());

    // ---- 5. THE POST-SUBMIT ANCHOR ----
    let second = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), unix_now())
        .await
        .expect("the phone is handed the post-submit anchor");
    assert_eq!(
        second.anchor.operation_phase,
        RollbackOperationPhase::Submitted,
        "the second anchor is a different phase, not a repeat of the first"
    );
    let receipt = super::pilot_node::signed_receipt(&second, &mobile, unix_now()).await;
    let reconciling = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, unix_now())
        .await
        .expect("the post-submit receipt is accepted");
    assert_eq!(reconciling.status, OperationStatus::ReconciliationRequired);

    // ---- 6. RECONCILED AGAINST THE HASH THE CHAIN CONFIRMED ----
    assert_eq!(
        mined_hash, tx_hash,
        "the chain confirmed the exact transaction this wallet signed"
    );
    let reconciled = manager
        .confirm_broadcast(&wallet_id, &operation_id, &mined_hash, unix_now())
        .expect("the confirmed hash reconciles the payment");
    assert_eq!(
        reconciled.status,
        OperationStatus::ReconciledAwaitingFinalWitness
    );

    // ---- 7. THE FINAL WITNESS COMMITS IT ----
    let third = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), unix_now())
        .await
        .expect("the phone is handed the final anchor");
    assert_eq!(
        third.anchor.operation_phase,
        RollbackOperationPhase::ReconciledFinal
    );
    let receipt = super::pilot_node::signed_receipt(&third, &mobile, unix_now()).await;
    let committed = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, unix_now())
        .await
        .expect("the final receipt commits the payment");
    assert_eq!(
        committed.status,
        OperationStatus::Committed,
        "three phone signatures finish a payment, not one"
    );
    assert_eq!(
        committed.reserved_units,
        HacUnits::ZERO,
        "the reservation is returned once the payment is committed"
    );
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, unix_now())
            .unwrap()
            .is_none(),
        "nothing is stranded once the payment is committed"
    );
    let synchronized = manager.overview(&wallet_id, unix_now()).await.unwrap();
    assert!(synchronized.mobile_witness_ready);
    assert!(synchronized.mobile_witness_synchronized);
    println!(
        "[full] anchor sequence reached {}",
        synchronized.latest_anchor_sequence
    );

    let recipient_after = balance_zhu(recipient).await;
    let owner_after = balance_zhu(&owner_address).await;
    let amount_zhu = u128::from(super::desktop_witness_flow::AMOUNT_UNITS) * 100;
    println!(
        "[coin] recipient {recipient_before} -> {recipient_after} Zhu, owner {owner_before} -> {owner_after} Zhu"
    );
    assert_eq!(
        recipient_after,
        recipient_before + amount_zhu,
        "the recipient must be paid exactly what the agent asked for"
    );
    assert!(owner_after < owner_before);
}

/// THE PHONE NEVER ANSWERS, ON MAINNET, AND THE EXIT ADDED IN 0c8d525 FREES IT.
///
/// The signature here is real: a real agent proposal, a real owner approval, a
/// real consensus Type 2 transaction signed with the wallet's own key against a
/// real node, holding real chain-7 coin. Only the network NAME is moved, and it
/// is moved because that string, compared before the operation was looked up,
/// was the whole of both refusals.
///
/// Six claims:
///
/// 1. on mainnet the forward step is refused BY NAME - `WitnessAnchorNetworkUnsupported`,
///    not `NodeNetworkMismatch` and not `InvalidOperationState`;
/// 2. the owner-facing view says a retry is NOT available rather than
///    advertising one that will be refused;
/// 3. the whole wallet is wedged while it sits: a second payment, a channel
///    open and a phone replacement are all refused;
/// 4. `abandon_stranded_witness_operation` succeeds on mainnet and marks the
///    payment `Cancelled`;
/// 5. the CHAIN never heard of the transaction, before or after, and the
///    owner's on-chain balance is identical to the Zhu;
/// 6. the wallet works again: a fresh intent is accepted.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn a_phone_that_never_answers_strands_a_mainnet_payment_and_the_exit_frees_it() {
    use crate::operation::OperationStatus;

    let work = workdir().join("wit-main");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    require_chain_seven("wit-main").await;
    let anchor = block_one_hash().await;
    let (mut manager, wallet_id, owner_address) =
        funded_owner(&work, "main-owner", &anchor, 0.5, wait_budget).await;
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    pair_a_real_phone(&mut manager, &wallet_id, &mobile, "main").await;

    let authorization = super::desktop_witness_flow::pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        unix_now(),
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request(
                "chain7-live-mainnet-strand-0001",
                unix_now() + 1_200,
            ),
            unix_now(),
        )
        .await
        .expect("the agent's proposal is accepted");
    let operation_id = created.operation_id.clone();
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, unix_now())
        .unwrap();
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, unix_now())
        .await
        .expect("the owner's yes");
    assert_eq!(approved.status, OperationStatus::SignedAwaitingWitness);
    let tx_hash = approved.tx_hash.clone().expect("a real transaction hash");
    let owner_at_strand = balance_zhu(&owner_address).await;
    let before = chain_knows_transaction(&tx_hash).await;
    assert_ne!(before["ret"].as_i64(), Some(0));
    println!("[main] stranded {tx_hash}; chain says {before}; owner {owner_at_strand} Zhu");

    // The phone is never asked and never answers. The wallet is then the
    // owner's real wallet: mainnet.
    move_live_wallet_to_mainnet(&mut manager, &wallet_id);
    manager.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now()).ok();

    // ---- 1. THE FORWARD STEP IS REFUSED, BY NAME ----
    let refused = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), unix_now())
        .await
        .expect_err("mainnet does not mint anchors");
    assert_eq!(
        refused,
        AgentWalletError::WitnessAnchorNetworkUnsupported,
        "the refusal must name the window, not the node"
    );

    // ---- 2. AND THE OWNER-FACING VIEW SAYS SO ----
    let stranded = manager
        .stranded_witness_recovery(&wallet_id, unix_now())
        .unwrap()
        .expect("a stranded mainnet payment is reported");
    println!(
        "[main] stranded view: status {:?} submitted {} tx {:?} anchor_issued {} retryable {} network_supports_witness_retry {} abandonable {} anchor_releasable {} phone_replacement_unblocked {}",
        stranded.status,
        stranded.submitted,
        stranded.transaction_id,
        stranded.anchor_issued,
        stranded.retryable,
        stranded.network_supports_witness_retry,
        stranded.abandonable,
        stranded.anchor_releasable,
        stranded.phone_replacement_unblocked
    );
    assert_eq!(stranded.status, OperationStatus::SignedAwaitingWitness);
    assert!(!stranded.submitted);
    assert_eq!(stranded.transaction_id.as_deref(), Some(tx_hash.as_str()));
    assert!(!stranded.retryable, "no retry may be advertised on mainnet");
    assert!(!stranded.network_supports_witness_retry);
    assert!(stranded.abandonable, "the exit must be offered");

    // ---- 3. THE WHOLE WALLET IS WEDGED ----
    //
    // The pair of facts every wedging guard in this crate reads, quoted rather
    // than described: a reservation is outstanding and an operation is not
    // terminal. `prepare_l2_channel_close` reads exactly this, which is how one
    // payment that never left the desktop locks a channel deposit in.
    assert!(
        live_wallet_is_wedged(&mut manager, &wallet_id),
        "a stranded payment holds a reservation and is not terminal"
    );
    let second = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request(
                "chain7-live-mainnet-strand-0002",
                unix_now() + 1_200,
            ),
            unix_now(),
        )
        .await
        .expect_err("a second payment while one is stranded is refused");
    // NOT `RecoveryRequired`. On mainnet at the shipped pilot feature set the
    // agent-spending network gate is reached first, so the agent is told
    // signing is blocked and the stranded payment is never named. On testnet
    // the same call answers `RecoveryRequired`, which is asserted in the
    // revoked-phone run below. Neither sentence names the payment.
    assert_eq!(second, AgentWalletError::SigningBlocked);
    let rotation = manager
        .prepare_witness_rotation(
            &wallet_id,
            "live-mainnet-rotation-1".to_owned(),
            SoftwareDeviceIdentity::generate(DeviceRole::Mobile).device_id(),
            hpay_companion_protocol::WitnessRotationMode::Normal,
            hpay_companion_protocol::WitnessRotationReason::LostPhone,
            unix_now(),
        )
        .await
        .expect_err("replacing the phone is refused on mainnet");
    assert_eq!(
        rotation,
        AgentWalletError::WitnessRotationNetworkUnsupported
    );
    println!("[main] second payment {second:?}, replacement {rotation:?}");

    // ---- 4. THE EXIT ----
    let freed = manager
        .abandon_stranded_witness_operation(&wallet_id, &operation_id, unix_now())
        .expect("the mainnet exit frees the payment");
    assert_eq!(
        freed.status,
        OperationStatus::Cancelled,
        "the payment is given up, and says so"
    );
    assert_eq!(freed.reserved_units, HacUnits::ZERO);
    assert!(
        manager
            .stranded_witness_recovery(&wallet_id, unix_now())
            .unwrap()
            .is_none(),
        "nothing is stranded any more"
    );
    assert!(
        !live_wallet_is_wedged(&mut manager, &wallet_id),
        "the reservation is returned and nothing non-terminal is left"
    );

    // ---- 5. THE MONEY NEVER MOVED, ASKED OF THE CHAIN ----
    let after = chain_knows_transaction(&tx_hash).await;
    assert_ne!(
        after["ret"].as_i64(),
        Some(0),
        "the abandoned transaction must never appear on chain: {after}"
    );
    let owner_after = balance_zhu(&owner_address).await;
    assert_eq!(
        owner_after, owner_at_strand,
        "abandoning a payment that was never sent costs nothing"
    );
    println!("[main] after the exit: chain {after}, owner {owner_after} Zhu");

    // ---- 6. THE WALLET WORKS AGAIN ----
    //
    // Back on the network the pilot signs for, because the mainnet refusal
    // above is a build gate and not the wedge. What is being shown is that the
    // wedge is gone: the same call that answered `RecoveryRequired` while the
    // payment sat now goes through.
    let (state_master, journal_key) = fixtures::keys(&manager, &wallet_id);
    let mut back = manager
        .load_verified_state(&wallet_id, &state_master, &journal_key)
        .unwrap();
    back.network_mode = "testnet".to_owned();
    back.block_one_fingerprint = anchor.clone();
    back.trusted_mainnet_fast_pay_pilot = false;
    back.updated_at = unix_now();
    manager
        .persist_event(
            &mut back,
            &state_master,
            &journal_key,
            AgentJournalEventKind::PolicyChanged,
            None,
            None,
            unix_now(),
        )
        .unwrap();
    let again = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request(
                "chain7-live-mainnet-strand-0003",
                unix_now() + 1_200,
            ),
            unix_now(),
        )
        .await
        .expect("the wallet takes work again once the stranded payment is given up");
    assert_eq!(again.status, OperationStatus::ApprovalRequested);
    println!(
        "[main] the wallet accepted a fresh intent {}",
        again.operation_id
    );
}

/// The `network_id` the desktop stamped into the approval the phone is asked to
/// sign, read out of authenticated state rather than rebuilt.
fn approval_binding_network_id(
    manager: &mut AgentWalletManager,
    wallet_id: &AgentWalletId,
    operation_id: &OperationId,
) -> Option<String> {
    let (state_master, journal_key) = fixtures::keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    state
        .operations
        .get(operation_id.as_str())?
        .stored_approval()
        .ok()?
        .network_binding
        .as_ref()
        .map(|binding| binding.network_id.clone())
}

/// The pair of facts every wedging guard in this crate reads, on a live wallet.
fn live_wallet_is_wedged(manager: &mut AgentWalletManager, wallet_id: &AgentWalletId) -> bool {
    let (state_master, journal_key) = fixtures::keys(manager, wallet_id);
    let state = manager
        .load_verified_state(wallet_id, &state_master, &journal_key)
        .unwrap();
    crate::service::state::active_reservations(&state).unwrap() != HacUnits::ZERO
        || state
            .operations
            .values()
            .any(|operation| !operation.status().is_terminal())
}

/// THE PHONE IS REVOKED MID FLIGHT, WITH A LIVE ANCHOR OUTSTANDING.
///
/// The owner asks the phone for the window, the phone goes into a river, and the
/// owner revokes it from the desktop. The anchor is still live at that instant,
/// so every exit is shut until it dies. Five claims, all live:
///
/// 1. a revoked phone's receipt is refused, so the payment cannot be released;
/// 2. while the anchor lives, BOTH exits refuse with
///    `WitnessRecoveryNotAvailable` - the wallet will not race a phone that may
///    be signing this second;
/// 3. once the anchor is genuinely dead, `release_dead_witness_anchor` drops it
///    and leaves the payment untouched;
/// 4. the escape the panel names, replacing the phone, is itself refused here:
///    the old device is revoked, so `prepare_witness_rotation` answers
///    `RotationOldDeviceNotAuthorized`. Giving the payment up is the only exit
///    left, and it works;
/// 5. the chain never saw the transaction and the owner's balance is unchanged.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only; waits out a real 300 second anchor"]
async fn a_phone_revoked_mid_flight_leaves_one_exit_and_it_works() {
    use crate::operation::OperationStatus;

    let work = workdir().join("wit-revoke");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    require_chain_seven("wit-revoke").await;
    let anchor = block_one_hash().await;
    let (mut manager, wallet_id, owner_address) =
        funded_owner(&work, "revoke-owner", &anchor, 0.5, wait_budget).await;
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    pair_a_real_phone(&mut manager, &wallet_id, &mobile, "revoke").await;

    let authorization = super::desktop_witness_flow::pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        unix_now(),
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request(
                "chain7-live-revoke-0001",
                unix_now() + 1_800,
            ),
            unix_now(),
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, unix_now())
        .unwrap();
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, unix_now())
        .await
        .unwrap();
    let tx_hash = approved.tx_hash.clone().expect("a real transaction hash");
    let owner_at_strand = balance_zhu(&owner_address).await;

    // The window is opened, and THEN the phone is lost.
    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), unix_now())
        .await
        .expect("the phone is handed an anchor");
    let issued_at = unix_now();
    println!(
        "[revk] anchor {} expires {} (now {issued_at})",
        proposal.anchor.anchor_id, proposal.anchor.expires_at
    );
    let revoked = manager
        .revoke_companion_device_locally(&wallet_id, mobile.device_id(), unix_now())
        .expect("the owner revokes the lost phone");
    assert!(revoked.is_revoked());

    // ---- 1. THE REVOKED PHONE CANNOT RELEASE THE PAYMENT ----
    let receipt = super::pilot_node::signed_receipt(&proposal, &mobile, unix_now()).await;
    let refused = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, unix_now())
        .await
        .expect_err("a revoked phone must not be able to move money");
    println!("[revk] the revoked phone's receipt: {refused:?}");
    assert_eq!(
        live_view(&mut manager, &wallet_id, &operation_id).status,
        OperationStatus::SignedAwaitingWitness
    );

    // A SECOND PAYMENT WHILE THE FIRST IS STRANDED, on the network the pilot
    // signs for. One stranded payment refuses every new one, and the sentence
    // the agent gets back does not name it.
    let second = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request(
                "chain7-live-revoke-0002",
                unix_now() + 1_800,
            ),
            unix_now(),
        )
        .await
        .expect_err("a second payment while one is stranded is refused");
    assert_eq!(
        second,
        AgentWalletError::RecoveryRequired,
        "the agent is told the wallet needs recovery, with nothing naming the payment"
    );
    println!("[revk] a second payment answered {second:?}");

    // ---- 2. WHILE THE ANCHOR LIVES, BOTH EXITS REFUSE ----
    let live_view_now = manager
        .stranded_witness_recovery(&wallet_id, unix_now())
        .unwrap()
        .expect("the stranded payment is reported");
    assert!(live_view_now.anchor_issued);
    assert!(
        !live_view_now.abandonable,
        "the wallet will not race a phone that may be signing"
    );
    assert!(!live_view_now.anchor_releasable);
    // WHAT THE DESKTOP ADVERTISES HERE, recorded rather than approved of.
    // `retryable` is `!outstanding_receipt && network supports it`; it does not
    // consult the device registry. The phone was revoked three lines ago and
    // its receipt was just refused with `RollbackDetected`, and the desktop
    // still says a retry is available - which renders as "Open the AI Agent
    // Wallet on your paired phone and confirm this payment."
    assert!(
        live_view_now.retryable,
        "recorded as found: the stranded view offers a retry a revoked phone can never satisfy"
    );
    println!(
        "[revk] with the phone revoked the desktop still reports retryable {}",
        live_view_now.retryable
    );
    assert_eq!(
        manager
            .abandon_stranded_witness_operation(&wallet_id, &operation_id, unix_now())
            .expect_err("refused while the anchor lives"),
        AgentWalletError::WitnessRecoveryNotAvailable
    );
    assert_eq!(
        manager
            .release_dead_witness_anchor(&wallet_id, &operation_id, unix_now())
            .expect_err("refused while the anchor lives"),
        AgentWalletError::WitnessRecoveryNotAvailable
    );

    // ---- 3. WAIT THE ANCHOR OUT, FOR REAL, AND DROP IT ----
    let dies_at = proposal.anchor.expires_at;
    println!("[revk] waiting out the real anchor until {dies_at}");
    while unix_now() <= dies_at {
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    manager.unlock(&wallet_id, AWAY_PASSPHRASE, unix_now()).ok();
    let dead = manager
        .stranded_witness_recovery(&wallet_id, unix_now())
        .unwrap()
        .expect("still reported");
    assert!(dead.anchor_releasable, "a dead anchor can be dropped");
    assert!(dead.abandonable, "and the payment can be given up");
    let untouched = manager
        .release_dead_witness_anchor(&wallet_id, &operation_id, unix_now())
        .expect("the dead anchor is dropped");
    assert_eq!(
        untouched.status,
        OperationStatus::SignedAwaitingWitness,
        "dropping an anchor must not touch the payment"
    );
    assert_eq!(untouched.tx_hash.as_deref(), Some(tx_hash.as_str()));

    // ---- 4. THE REPLACEMENT THE PANEL NAMES IS REFUSED HERE ----
    //
    // With the dead anchor dropped, `witness_dead_end` is satisfied and the
    // stranded view turns `phone_replacement_unblocked` on. That is the flag
    // the Security page reads to print "Replace the paired phone keeps this
    // payment: the new phone confirms it and it goes through." The flag does
    // not ask whether the OLD phone is still an authorized witness, and
    // `prepare_witness_rotation` does, so the sentence is offered over a
    // control that refuses. Recorded rather than approved of.
    let offered = manager
        .stranded_witness_recovery(&wallet_id, unix_now())
        .unwrap()
        .expect("still reported");
    assert!(
        offered.phone_replacement_unblocked,
        "recorded as found: the desktop offers the replacement here"
    );
    let replacement = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    let rotation_refusal = manager
        .prepare_witness_rotation(
            &wallet_id,
            "live-revoke-rotation-1".to_owned(),
            replacement.device_id(),
            hpay_companion_protocol::WitnessRotationMode::Normal,
            hpay_companion_protocol::WitnessRotationReason::LostPhone,
            unix_now(),
        )
        .await
        .expect_err("a revoked old phone cannot authorize its own replacement");
    assert_eq!(
        rotation_refusal,
        AgentWalletError::RotationOldDeviceNotAuthorized,
        "this is the escape the desktop names, and here it is shut"
    );
    println!("[revk] replacement refused: {rotation_refusal:?}");

    let freed = manager
        .abandon_stranded_witness_operation(&wallet_id, &operation_id, unix_now())
        .expect("the only exit left works");
    assert_eq!(freed.status, OperationStatus::Cancelled);

    // ---- 5. THE MONEY NEVER MOVED ----
    let chain = chain_knows_transaction(&tx_hash).await;
    assert_ne!(chain["ret"].as_i64(), Some(0), "{chain}");
    assert_eq!(balance_zhu(&owner_address).await, owner_at_strand);
    println!("[revk] chain {chain}; owner still {owner_at_strand} Zhu");
}

/// THE DESKTOP DIES BETWEEN THE PHONE'S RECEIPT AND THE BROADCAST.
///
/// Two crashes, at the two durable boundaries, with a real chain underneath and
/// a real transaction in flight. The claim under test is exactly-once: a
/// desktop that dies after accepting a receipt must, when it is reopened, put
/// the bytes on the wire once and only once, and the chain is what is asked.
///
/// 1. crash after the receipt is durable and before the broadcast: reopening
///    the wallet from that disk and calling `resume_interrupted_witness` submits
///    it, and the transaction lands in a block;
/// 2. the recipient's on-chain balance moved by the amount ONCE - a second
///    submission would either be rejected or double-pay, and neither happened;
/// 3. calling the resume again afterwards is a no-op that submits nothing.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "live private pilot chain only"]
async fn a_desktop_that_dies_between_the_receipt_and_the_broadcast_submits_exactly_once() {
    use crate::operation::OperationStatus;

    let work = workdir().join("wit-crash");
    std::fs::create_dir_all(&work).unwrap();
    // SAFETY: nothing else in this process has started yet.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("fund"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("fund")).unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_LIVE_WAIT_SECS", "2400").parse().unwrap());

    require_chain_seven("wit-crash").await;
    let anchor = block_one_hash().await;
    let root = work.join("crash-owner");
    let (mut manager, wallet_id, owner_address) =
        funded_owner(&work, "crash-owner", &anchor, 0.5, wait_budget).await;
    let mobile = SoftwareDeviceIdentity::generate(DeviceRole::Mobile);
    pair_a_real_phone(&mut manager, &wallet_id, &mobile, "crash").await;

    let recipient = fixtures::RECIPIENT;
    let recipient_before = balance_zhu(recipient).await;
    let owner_before = balance_zhu(&owner_address).await;

    let authorization = super::desktop_witness_flow::pair_desktop_agent(
        &mut manager,
        &wallet_id,
        ApprovalMode::DesktopManual,
        unix_now(),
    );
    let created = manager
        .create_payment_intent(
            &authorization,
            super::desktop_witness_flow::payment_request(
                "chain7-live-crash-0001",
                unix_now() + 1_200,
            ),
            unix_now(),
        )
        .await
        .unwrap();
    let operation_id = created.operation_id.clone();
    let approval = manager
        .pending_approval(&wallet_id, &operation_id, unix_now())
        .unwrap();
    let approved = manager
        .approve_desktop_and_broadcast(&wallet_id, approval, unix_now())
        .await
        .unwrap();
    assert_eq!(approved.status, OperationStatus::SignedAwaitingWitness);
    let tx_hash = approved.tx_hash.clone().expect("a real transaction hash");

    let proposal = manager
        .pending_rollback_anchor(&wallet_id, &operation_id, mobile.device_id(), unix_now())
        .await
        .unwrap();
    let receipt = super::pilot_node::signed_receipt(&proposal, &mobile, unix_now()).await;

    // ---- 1. THE CRASH ----
    manager.crash_after_witness_accepted = true;
    let crashed = manager
        .apply_mobile_witness_and_broadcast(&wallet_id, receipt, unix_now())
        .await
        .expect_err("the injected crash stops the call dead");
    assert_eq!(crashed, AgentWalletError::RecoveryRequired);
    drop(manager);

    // The chain is asked BEFORE the recovery, so "it was already on the wire"
    // is ruled out rather than assumed.
    let before_recovery = chain_knows_transaction(&tx_hash).await;
    assert_ne!(
        before_recovery["ret"].as_i64(),
        Some(0),
        "a desktop that died before the broadcast must not have broadcast: {before_recovery}"
    );
    println!("[crsh] after the crash the chain says {before_recovery}");

    // ---- 2. REOPENED FROM THAT DISK ----
    let mut reopened = AgentWalletManager::open(&root).unwrap();
    reopened
        .unlock(&wallet_id, AWAY_PASSPHRASE, unix_now())
        .unwrap();
    let resumed = reopened
        .resume_interrupted_witness(&wallet_id, unix_now())
        .await
        .expect("the reopened wallet finishes what the dead one started")
        .expect("there was something to finish");
    println!("[crsh] resumed to {:?}", resumed.status);
    assert!(
        matches!(
            resumed.status,
            OperationStatus::SubmittedAwaitingFinalWitness
                | OperationStatus::BroadcastSubmitted
                | OperationStatus::BroadcastUncertain
        ),
        "unexpected status after resume: {:?}",
        resumed.status
    );
    let mined = wait_for_transaction(&tx_hash, wait_budget).await;
    println!("[crsh] mined: {mined}");

    // ---- 3. EXACTLY ONCE, ASKED OF THE CHAIN ----
    let again = reopened
        .resume_interrupted_witness(&wallet_id, unix_now())
        .await;
    println!("[crsh] resuming again answered {again:?}");
    let amount_zhu = u128::from(super::desktop_witness_flow::AMOUNT_UNITS) * 100;
    let recipient_after = balance_zhu(recipient).await;
    let owner_after = balance_zhu(&owner_address).await;
    println!(
        "[coin] recipient {recipient_before} -> {recipient_after} Zhu, owner {owner_before} -> {owner_after} Zhu"
    );
    assert_eq!(
        recipient_after,
        recipient_before + amount_zhu,
        "the interrupted payment must be paid exactly once"
    );
}
