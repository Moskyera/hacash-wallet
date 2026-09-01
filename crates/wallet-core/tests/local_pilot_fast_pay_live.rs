//! Live HPAY Local Pilot Chain (private chain 7) Fast Pay harness.
//!
//! Everything here is `#[ignore]`. A plain `cargo test` does not run it and
//! CI is unaffected: it needs a real fullnode listening, a real block chain
//! that pays a real mining reward, and minutes of wall clock waiting for six
//! confirmations. It is an instrument, not a gate.
//!
//! What it is for: proving that the code path a user actually walks - import
//! or unlock a vault, open a Fast Pay channel through the reviewed prepared
//! ceremony, then press Send - reaches a completed Fast Pay payment. Nothing
//! is mocked. The fullnode is the real `fullnode.exe` on private chain 7. The
//! Hub is the real `l2_fast_pay_hub::HubState` behind the real
//! `l2_fast_pay_hub::build_router`, served over real HTTP on a real TCP port,
//! exactly as `fast-pay-hub.exe` serves it. The wallet is the real
//! `WalletService`, and the payment is `WalletService::send_hac`, which is the
//! function both UIs call from the Send screen.
//!
//! NO REAL VALUE. Chain 7 is a private development network. `network_kind` is
//! `local_pilot_v1` and `chain.mainnet` is false; the harness refuses to run
//! against anything else, so it can never be pointed at Hacash mainnet.
//!
//! Environment:
//!
//! * `HPAY_PILOT_NODE_URL`  - required. The chain-7 fullnode API, e.g.
//!   `http://127.0.0.1:8217`.
//! * `HPAY_PILOT_SEED`      - required. Per-agent identity seed. Two agents
//!   running at the same time must use different seeds, so that they derive
//!   different payer, payee and Hub addresses and never share a channel.
//! * `HPAY_PILOT_WORKDIR`   - required. Per-agent directory holding the wallet
//!   vault and the Hub state file, so a re-run resumes instead of colliding.
//!   Keep it SHORT. The wallet applies a Windows ACL to every file it writes,
//!   and `SetFileSecurityW` fails with `0x8007007B` once the full path passes
//!   260 characters, which a scratchpad path does.
//! * `HPAY_PILOT_HUB_SEED`  - optional. Overrides only the Hub identity, which
//!   is what lets a second full open-and-pay cycle run against the same funded
//!   payer.
//! * `HPAY_PILOT_HUB_LISTEN` - optional, default `127.0.0.1:0` (ephemeral).
//! * `HPAY_PILOT_DEPOSIT`   - optional, default `1`. Channel deposit in HAC.
//! * `HPAY_PILOT_AMOUNT`    - optional, default `0.1`. Payment amount in HAC.
//! * `HPAY_PILOT_MAX_PAYMENT_ZHU`  - optional, default `100000000` (1 HAC).
//! * `HPAY_PILOT_MAX_CHANNEL_ZHU`  - optional, default `100000000` (1 HAC).
//! * `HPAY_PILOT_WAIT_SECS` - optional, default `1800`. Confirmation budget.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hacash_wallet_core::WalletService;
use hacash_wallet_core::account::WalletAccount;
use l2_fast_pay_hub::{HubState, build_router};

const VAULT_PASSPHRASE: &str = "local-pilot-harness-passphrase";

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| {
        panic!("{name} must be set; see the module docs at the top of this file")
    })
}

fn optional_env(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn seed() -> String {
    required_env("HPAY_PILOT_SEED")
}

fn payer_account() -> WalletAccount {
    WalletAccount::create(&format!("{}::payer", seed())).unwrap()
}

/// The Hub identity. Overridable on its own so a second full open-and-pay
/// cycle can run against the same funded payer: the channel id is derived
/// from (payer, hub, incarnation), so a different Hub is a different channel.
fn hub_account() -> WalletAccount {
    WalletAccount::create(&optional_env(
        "HPAY_PILOT_HUB_SEED",
        &format!("{}::hub", seed()),
    ))
    .unwrap()
}

/// A 32-byte key derived from the seed. These protect a throwaway Hub state
/// file on a private chain and are deliberately reproducible so a re-run can
/// reopen the same sealed state.
fn derived_key_hex(label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed().as_bytes());
    hasher.update(b"::");
    hasher.update(label.as_bytes());
    hex::encode(hasher.finalize())
}

fn workdir() -> PathBuf {
    let dir = PathBuf::from(required_env("HPAY_PILOT_WORKDIR"));
    std::fs::create_dir_all(&dir).expect("workdir");
    dir
}

/// Print the public addresses this seed produces, and nothing secret.
///
/// Run this first: the payer address is what the pilot fullnode has to be
/// configured to pay its mining reward to, and that has to happen before the
/// node starts.
#[test]
#[ignore = "live private pilot chain only"]
fn pilot_identities() {
    let payer = payer_account();
    let hub = hub_account();
    println!("HPAY_PILOT_SEED        = {}", seed());
    println!("payer address (fund me) = {}", payer.address());
    println!("hub address             = {}", hub.address());
}

/// One complete Fast Pay payment on private chain 7, through the real wallet.
#[test]
#[ignore = "live private pilot chain only"]
fn one_fast_pay_payment_completes_on_the_private_pilot_chain() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(drive_one_payment());
}

async fn drive_one_payment() {
    let node_url = required_env("HPAY_PILOT_NODE_URL");
    let work = workdir();
    let deposit_hac = optional_env("HPAY_PILOT_DEPOSIT", "1");
    let amount_hac: f64 = optional_env("HPAY_PILOT_AMOUNT", "0.1").parse().unwrap();
    let wait_budget = Duration::from_secs(
        optional_env("HPAY_PILOT_WAIT_SECS", "1800")
            .parse()
            .unwrap(),
    );

    let payer = payer_account();
    let hub_signer_account = hub_account();
    let payer_address = payer.address();
    let hub_address = hub_signer_account.address();

    // ---------------------------------------------------------------- node
    // Refuse anything that is not the private pilot chain. This is what makes
    // the harness safe to leave lying around: it cannot be aimed at mainnet.
    let capabilities: serde_json::Value = reqwest::get(format!("{node_url}/query/capabilities"))
        .await
        .expect("pilot fullnode is not reachable")
        .json()
        .await
        .expect("capability document");
    assert_eq!(
        capabilities["chain"]["id"].as_u64(),
        Some(7),
        "this harness only runs on private chain 7"
    );
    assert_eq!(
        capabilities["chain"]["mainnet"].as_bool(),
        Some(false),
        "this harness must never be pointed at a mainnet node"
    );
    assert_eq!(
        capabilities["network"]["kind"].as_str(),
        Some("local_pilot_v1")
    );
    println!(
        "[node] {node_url} chain id {} mainnet {} kind {} height {}",
        capabilities["chain"]["id"],
        capabilities["chain"]["mainnet"],
        capabilities["network"]["kind"],
        capabilities["chain"]["height"]
    );

    // ----------------------------------------------------------------- hub
    // The real Hub server, in this process, on a real TCP socket. Same
    // HubState and same router that `fast-pay-hub.exe` builds.
    let hub_state = Arc::new(
        HubState::new_secure_with_policy(
            "HPAY Local Pilot Harness Hub",
            hub_address.clone(),
            node_url.clone(),
            None,
            work.join("hub-state.sealed.json"),
            hub_signer_account.secret_hex().to_string(),
            &derived_key_hex("journal"),
            &derived_key_hex("state"),
            "local-pilot",
            // The Hub's exposure caps, in Zhu, and they are enforced on every
            // profile: leave them at zero and the Hub refuses to bind any
            // channel at all. Defaults here are the protocol hard maxima that
            // still admit a one-HAC channel and a sub-HAC payment.
            optional_env("HPAY_PILOT_MAX_PAYMENT_ZHU", "100000000")
                .parse()
                .unwrap(),
            optional_env("HPAY_PILOT_MAX_CHANNEL_ZHU", "100000000")
                .parse()
                .unwrap(),
        )
        .expect("hub state"),
    );
    let listen = optional_env("HPAY_PILOT_HUB_LISTEN", "127.0.0.1:0");
    let listener = tokio::net::TcpListener::bind(&listen).await.unwrap();
    let hub_url = format!("http://{}", listener.local_addr().unwrap());
    let hub_task = tokio::spawn(async move {
        axum::serve(listener, build_router(hub_state))
            .await
            .unwrap();
    });
    println!("[hub ] {hub_url} address {hub_address} profile local-pilot");

    // -------------------------------------------------------------- wallet
    // Real vault, real settings file, real key. `HACASH_WALLET_NETWORK` is the
    // supported runtime override and is what pins this wallet to testnet mode,
    // which is what chain 7 is: not mainnet, chain id not zero.
    // SAFETY: single-threaded setup before any wallet thread exists.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("wallet-data"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("wallet-data")).unwrap();

    let mut wallet = WalletService::new(Some(node_url.clone()), Some(hub_url.clone())).unwrap();
    match wallet.unlock(VAULT_PASSPHRASE) {
        Ok(address) => println!("[wall] unlocked existing vault {address}"),
        Err(_) => {
            let address = wallet
                .import_wallet(&payer.secret_hex(), VAULT_PASSPHRASE, &payer_address)
                .expect("import the pilot payer key");
            println!("[wall] imported vault {address}");
        }
    }
    assert_eq!(
        wallet.status().address.as_deref(),
        Some(payer_address.as_str())
    );

    let mut settings = wallet.get_settings();
    settings.node_url = node_url.clone();
    settings.l2_hub_url = Some(hub_url.clone());
    settings.hub_right_address = Some(hub_address.clone());
    // The mainnet bounded-pilot consent box, ticked. On chain 7 the wallet is
    // in testnet mode so this value is not what opens the gate here; it is set
    // because this is the settings shape a consenting user actually carries,
    // and because every Hub client on this path is now built from it.
    wallet.update_settings(settings).expect("wallet settings");
    // The consent box, ticked. Giving consent now needs the authenticated
    // command; `update_settings` refuses to turn it on.
    wallet
        .set_trusted_mainnet_fast_pay_pilot(VAULT_PASSPHRASE, true)
        .expect("authenticated mainnet pilot consent");

    let balance = wallet.balance_mei().await.expect("payer balance");
    println!("[wall] payer {payer_address} balance {balance} HAC");
    assert!(
        balance > 0.0,
        "the payer address has no pilot HAC. Point the chain-7 miner reward at {payer_address} and mine a few blocks."
    );

    // -------------------------------------------------------- channel open
    // The reviewed prepared ceremony, which is the only way this wallet will
    // open a funded channel. `open_channel` itself is disabled on purpose.
    let existing = wallet.get_settings().channel_id_hex;
    if existing.is_none() {
        let preview = wallet
            .preview_channel_open(&hub_address, &deposit_hac, "0")
            .await
            .expect("channel preview");
        println!(
            "[chan] preview id {} left {} {} right {} {}",
            preview.channel_id,
            preview.left_address,
            preview.left_deposit,
            preview.right_address,
            preview.right_deposit
        );
        let prepared = wallet
            .prepare_channel_open(&hub_address, &deposit_hac, "0")
            .await
            .expect("prepare channel open");
        println!("[chan] prepared {} digest {}", prepared.id, prepared.digest);
        let first = wallet
            .execute_prepared_channel_open(&prepared.id)
            .await
            .expect("execute prepared channel open");
        println!("[chan] {first}");

        let deadline = Instant::now() + wait_budget;
        loop {
            if wallet.get_settings().channel_id_hex.is_some() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "channel did not reach six confirmations within the wait budget"
            );
            tokio::time::sleep(Duration::from_secs(15)).await;
            match wallet.recover_channel_open().await {
                Ok(message) => println!("[chan] {message}"),
                Err(error) => println!("[chan] still waiting: {error}"),
            }
        }
    }
    let channel_id = wallet
        .get_settings()
        .channel_id_hex
        .expect("channel id after open");
    let channel_before = wallet
        .channel_info()
        .await
        .expect("channel info")
        .expect("channel present");
    println!(
        "[chan] id {channel_id} status {} reuse {} left {} = {} right {} = {}",
        channel_before.status,
        channel_before.reuse_version,
        channel_before.left.address,
        channel_before.left.hacash,
        channel_before.right.address,
        channel_before.right.hacash
    );

    // ------------------------------------------------------------- payment
    // Exactly the Send screen. `preview_send` picks the rail, `send_hac`
    // executes it. If the Fast Pay gate refused, the rail would come back
    // L1OnChain and this assertion is what catches the silent fallback.
    let preview = wallet
        .preview_send(&hub_address, amount_hac, &Default::default())
        .await
        .expect("send preview");
    println!(
        "[send] planned rail {:?} label {:?} fee {:?} channel {:?}",
        preview.plan.rail,
        preview.plan.rail_label,
        preview.plan.estimated_fee,
        preview.plan.channel_id
    );
    assert_eq!(
        preview.plan.rail,
        hacash_wallet_core::payment::PaymentRail::L2Fast,
        "the Send screen fell back to a paid L1 transaction instead of Fast Pay"
    );

    let result = wallet
        .send_hac(&hub_address, amount_hac, Default::default())
        .await
        .expect("Fast Pay payment");
    println!(
        "[send] rail {:?} id {} pending {} :: {}",
        result.rail, result.tx_hash, result.pending, result.summary
    );
    assert_eq!(
        result.rail,
        hacash_wallet_core::payment::PaymentRail::L2Fast
    );
    assert!(!result.pending, "the Hub did not settle the payment");

    // -------------------------------------------------------------- proof
    let summaries = wallet.list_bill_summaries().expect("bill summaries");
    let bill = summaries
        .iter()
        .find(|summary| summary.payment_id == result.tx_hash)
        .expect("the settlement bill for this payment");
    for prove in &bill.prove_bodies {
        println!(
            "[bill] channel {} serial {} amount {} {} -> left {} = {} right {} = {}",
            prove.channel_id_hex,
            prove.bill_auto_number,
            prove.pay_amount_mei,
            prove.pay_direction,
            prove.left_address,
            prove.left_balance_mei,
            prove.right_address,
            prove.right_balance_mei
        );
    }
    println!(
        "[bill] signatures filled {} verified {} dispute_ready {}",
        bill.all_signatures_filled, bill.all_signatures_verified, bill.dispute_ready
    );
    assert!(
        bill.all_signatures_verified,
        "the settlement bill is not fully signed by both parties"
    );
    assert!(
        bill.dispute_ready,
        "the settlement bill is not dispute-ready"
    );

    hub_task.abort();
}
