//! The mainnet bounded-pilot CONSENT gate, measured twice: consent off, consent on.
//!
//! Everything here is `#[ignore]`; `cargo test` and CI are unaffected. It is an
//! instrument, not a gate.
//!
//! WHY THIS FILE EXISTS SEPARATELY FROM `local_pilot_fast_pay_live.rs`.
//! That harness proves the Fast Pay mechanics on private chain 7. It cannot
//! prove anything about the consent flag, and its author said so. The reason is
//! structural, not incidental:
//!
//! * `L2HubClient::new_for_wallet_policy` returns `TrustedBoundedPilot` only
//!   when `network_mode == "mainnet"` AND the consent flag is set.
//! * `PaymentRouter::try_l2_plan` consults the mainnet gate only inside
//!   `if self.settings.network_mode == "mainnet"`.
//!
//! On chain 7 the wallet is in testnet mode, so on that chain the consent flag
//! is inert by construction and an off/on diff there is necessarily null.
//! `pilot_chain_consent_off_then_on` measures that null rather than assuming it.
//! The diff that discriminates has to be taken against a mainnet-pointed Hub,
//! which is what the other tests here do.
//!
//! NO VALUE MOVES. The mainnet tests only read, serve a Hub that reads, and let
//! the wallet BUILD a plan or PREPARE (not execute) a transaction. Nothing here
//! signs a broadcast or calls `execute_prepared_channel_open` or `send_hac`
//! against mainnet: `prepare_channel_open` builds and stores a prepared
//! operation, and broadcast lives only in `execute_prepared_channel_open`,
//! which this file never calls.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hacash_wallet_core::WalletService;
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::l2_hub::L2HubClient;
use hacash_wallet_core::payment::PaymentRail;
use l2_fast_pay_hub::{HubState, build_router};

const VAULT_PASSPHRASE: &str = "agent-d-consent-gate-passphrase";

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} must be set; see the module docs"))
}

fn optional_env(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn seed() -> String {
    required_env("HPAY_D_SEED")
}

fn payer_account() -> WalletAccount {
    WalletAccount::create(&format!("{}::payer", seed())).unwrap()
}

fn hub_account() -> WalletAccount {
    WalletAccount::create(&optional_env(
        "HPAY_D_HUB_SEED",
        &format!("{}::hub", seed()),
    ))
    .unwrap()
}

fn derived_key_hex(label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed().as_bytes());
    hasher.update(b"::");
    hasher.update(label.as_bytes());
    hex::encode(hasher.finalize())
}

fn workdir(sub: &str) -> PathBuf {
    let dir = PathBuf::from(required_env("HPAY_D_WORKDIR")).join(sub);
    std::fs::create_dir_all(&dir).expect("workdir");
    dir
}

async fn capabilities(node_url: &str) -> serde_json::Value {
    reqwest::get(format!("{node_url}/query/capabilities"))
        .await
        .expect("fullnode is not reachable")
        .json()
        .await
        .expect("capability document")
}

/// Stand up the real Hub server in this process, on a real TCP socket: the same
/// `HubState` and the same `build_router` that `fast-pay-hub.exe` serves.
async fn serve_hub(
    node_url: &str,
    profile: &str,
    state_dir: &std::path::Path,
    listen: &str,
) -> (String, String, tokio::task::JoinHandle<()>) {
    let hub_signer = hub_account();
    let hub_address = hub_signer.address();
    let max_payment: u64 = optional_env("HPAY_D_MAX_PAYMENT_ZHU", "100000000")
        .parse()
        .unwrap();
    let max_channel: u64 = optional_env("HPAY_D_MAX_CHANNEL_ZHU", "100000000")
        .parse()
        .unwrap();
    let state_path = state_dir.join(format!("hub-state-{profile}.sealed.json"));
    // A mainnet pilot profile is a real deployment and takes the real deployment
    // constructor: the operator's admission allowlist, exactly as
    // `fast-pay-hub.rs` builds it. Without it the Hub honestly publishes the
    // blocker `mainnet_pilot_user_allowlist_is_not_configured` and refuses, and
    // that refusal would mask the thing being measured here. Configuring the
    // allowlist is operator configuration; no check is removed by it.
    let state = Arc::new(if profile.starts_with("mainnet-") {
        let admission = l2_fast_pay_hub::readiness::MainnetPilotAdmissionPolicy::try_new(
            [payer_account().address()],
            optional_env("HPAY_D_MAX_TVL_ZHU", "10000000000")
                .parse()
                .unwrap(),
        )
        .expect("admission policy");
        assert!(admission.is_configured(), "allowlist must be configured");
        HubState::new_secure_with_mainnet_admission_signer(
            "HPAY Agent-D Consent Gate Hub",
            hub_address.clone(),
            node_url.to_owned(),
            None,
            state_path,
            l2_fast_pay_hub::HubSigner::from_secret_hex(&hub_signer.secret_hex()).expect("signer"),
            &derived_key_hex("journal"),
            &derived_key_hex("state"),
            profile,
            max_payment,
            max_channel,
            admission,
        )
        .expect("hub state")
    } else {
        HubState::new_secure_with_policy(
            "HPAY Agent-D Consent Gate Hub",
            hub_address.clone(),
            node_url.to_owned(),
            None,
            state_path,
            hub_signer.secret_hex().to_string(),
            &derived_key_hex("journal"),
            &derived_key_hex("state"),
            profile,
            max_payment,
            max_channel,
        )
        .expect("hub state")
    });
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
    let hub_url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });
    println!("[hub ] {hub_url} address {hub_address} profile {profile}");
    (hub_url, hub_address, task)
}

fn set_consent(wallet: &mut WalletService, consent: bool) {
    apply_mainnet_pilot_consent(wallet, consent);
}

/// Set the bounded mainnet pilot consent the way a user now has to.
///
/// Turning it on goes through the authenticated command; `update_settings`
/// refuses it. Turning it off is a tightening and stays on the generic path.
fn apply_mainnet_pilot_consent(wallet: &mut WalletService, consent: bool) {
    if consent {
        wallet
            .set_trusted_mainnet_fast_pay_pilot(VAULT_PASSPHRASE, true)
            .expect("authenticated mainnet pilot consent");
    } else {
        let mut settings = wallet.get_settings();
        settings.trusted_mainnet_fast_pay_pilot = false;
        wallet.update_settings(settings).expect("withdraw consent");
    }
    assert_eq!(
        wallet.get_settings().trusted_mainnet_fast_pay_pilot,
        consent,
        "the consent flag did not persist"
    );
}

/// Print the plan the Send screen would show, exactly as the router produced it.
async fn show_plan(
    wallet: &mut WalletService,
    to: &str,
    amount: f64,
    label: &str,
) -> Option<PaymentRail> {
    match wallet.preview_send(to, amount, &Default::default()).await {
        Ok(preview) => {
            println!(
                "[plan {label}] rail {:?} label {:?} fee {:?} channel {:?} summary {:?}",
                preview.plan.rail,
                preview.plan.rail_label,
                preview.plan.estimated_fee,
                preview.plan.channel_id,
                preview.plan.summary
            );
            Some(preview.plan.rail)
        }
        Err(error) => {
            println!("[plan {label}] REFUSED: {error}");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// 1. The pilot chain. Full user journey, consent off, then consent on.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "live private pilot chain only"]
fn pilot_chain_consent_off_then_on() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(drive_pilot_journey());
}

async fn drive_pilot_journey() {
    let node_url = required_env("HPAY_D_PILOT_NODE_URL");
    let work = workdir("pilot");
    let deposit_hac = optional_env("HPAY_D_DEPOSIT", "1");
    let amount_hac: f64 = optional_env("HPAY_D_AMOUNT", "0.1").parse().unwrap();
    let wait_budget =
        Duration::from_secs(optional_env("HPAY_D_WAIT_SECS", "1800").parse().unwrap());

    // Refuse anything that is not the private pilot chain.
    let caps = capabilities(&node_url).await;
    assert_eq!(caps["chain"]["id"].as_u64(), Some(7), "pilot chain 7 only");
    assert_eq!(caps["chain"]["mainnet"].as_bool(), Some(false));
    assert_eq!(caps["network"]["kind"].as_str(), Some("local_pilot_v1"));
    println!(
        "[node] {node_url} chain id {} mainnet {} kind {} height {}",
        caps["chain"]["id"],
        caps["chain"]["mainnet"],
        caps["network"]["kind"],
        caps["chain"]["height"]
    );

    let (hub_url, hub_address, hub_task) = serve_hub(
        &node_url,
        "local-pilot",
        &work,
        &optional_env("HPAY_D_PILOT_HUB_LISTEN", "127.0.0.1:0"),
    )
    .await;

    // SAFETY: single-threaded setup before any wallet thread exists.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("wallet-data"));
        std::env::set_var("HACASH_WALLET_NETWORK", "testnet");
    }
    std::fs::create_dir_all(work.join("wallet-data")).unwrap();

    let payer = payer_account();
    let payer_address = payer.address();
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

    let mut settings = wallet.get_settings();
    settings.node_url = node_url.clone();
    settings.l2_hub_url = Some(hub_url.clone());
    settings.hub_right_address = Some(hub_address.clone());
    // START WITH CONSENT OFF. This is the whole point of this test.
    settings.trusted_mainnet_fast_pay_pilot = false;
    wallet.update_settings(settings).expect("settings");
    println!(
        "[wall] network_mode {} consent {}",
        wallet.get_settings().network_mode,
        wallet.get_settings().trusted_mainnet_fast_pay_pilot
    );

    let balance = wallet.balance_mei().await.expect("payer balance");
    println!("[wall] payer {payer_address} balance {balance} HAC");
    assert!(
        balance > 0.0,
        "payer has no pilot HAC; point the miner reward at {payer_address}"
    );

    // ------------------------------------------------- channel open, consent OFF
    if wallet.get_settings().channel_id_hex.is_none() {
        let prepared = wallet
            .prepare_channel_open(&hub_address, &deposit_hac, "0")
            .await
            .expect("prepare channel open (consent off, pilot chain)");
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
                "channel did not confirm in budget"
            );
            tokio::time::sleep(Duration::from_secs(15)).await;
            match wallet.recover_channel_open().await {
                Ok(message) => println!("[chan] {message}"),
                Err(error) => println!("[chan] still waiting: {error}"),
            }
        }
    }
    let channel_id = wallet.get_settings().channel_id_hex.expect("channel id");
    let info = wallet.channel_info().await.unwrap().unwrap();
    println!(
        "[chan] id {channel_id} status {} reuse {} left {} = {} right {} = {}",
        info.status,
        info.reuse_version,
        info.left.address,
        info.left.hacash,
        info.right.address,
        info.right.hacash
    );

    // ------------------------------------------------------- send, consent OFF
    let rail_off = show_plan(&mut wallet, &hub_address, amount_hac, "consent OFF").await;
    let sent_off = wallet
        .send_hac(&hub_address, amount_hac, Default::default())
        .await;
    match &sent_off {
        Ok(result) => println!(
            "[send OFF] rail {:?} id {} pending {} :: {}",
            result.rail, result.tx_hash, result.pending, result.summary
        ),
        Err(error) => println!("[send OFF] REFUSED: {error}"),
    }

    // -------------------------------------------------------- send, consent ON
    set_consent(&mut wallet, true);
    println!(
        "[wall] consent flipped to {}",
        wallet.get_settings().trusted_mainnet_fast_pay_pilot
    );
    let rail_on = show_plan(&mut wallet, &hub_address, amount_hac, "consent ON ").await;
    let sent_on = wallet
        .send_hac(&hub_address, amount_hac, Default::default())
        .await
        .expect("Fast Pay payment with consent on");
    println!(
        "[send ON ] rail {:?} id {} pending {} :: {}",
        sent_on.rail, sent_on.tx_hash, sent_on.pending, sent_on.summary
    );
    assert_eq!(
        sent_on.rail,
        PaymentRail::L2Fast,
        "consented send fell back to paid L1"
    );
    assert!(!sent_on.pending, "the Hub did not settle the payment");

    for summary in wallet.list_bill_summaries().expect("bills") {
        for prove in &summary.prove_bodies {
            println!(
                "[bill] channel {} serial {} amount {} {} -> left {} = {} right {} = {} | verified {} dispute_ready {}",
                prove.channel_id_hex,
                prove.bill_auto_number,
                prove.pay_amount_mei,
                prove.pay_direction,
                prove.left_address,
                prove.left_balance_mei,
                prove.right_address,
                prove.right_balance_mei,
                summary.all_signatures_verified,
                summary.dispute_ready
            );
        }
    }

    println!(
        "[DIFF] pilot chain rail with consent OFF = {rail_off:?}, with consent ON = {rail_on:?}"
    );
    hub_task.abort();
}

// ---------------------------------------------------------------------------
// 2. The mainnet-pointed consent gate. READ ONLY. Nothing is broadcast.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "reads the real mainnet fullnode; builds plans only, never broadcasts"]
fn mainnet_bounded_pilot_consent_gate() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(drive_mainnet_gate());
}

async fn drive_mainnet_gate() {
    let mainnet_url = required_env("HPAY_D_MAINNET_NODE_URL");
    let work = workdir("mainnet");
    let amount_hac: f64 = optional_env("HPAY_D_AMOUNT", "0.1").parse().unwrap();

    // This test is only meaningful against the real mainnet chain, and it must
    // stay read-only there.
    let caps = capabilities(&mainnet_url).await;
    assert_eq!(
        caps["chain"]["id"].as_u64(),
        Some(0),
        "mainnet chain id is 0"
    );
    assert_eq!(caps["chain"]["mainnet"].as_bool(), Some(true));
    // The registry V2 flag first, because it is the one the Hub's gate reads.
    // The V1 per-channel number is kept beside it, labelled, so nobody reads
    // this line and concludes the wrong contract is being waited on.
    println!(
        "[node] {mainnet_url} chain id {} mainnet {} height {} tip_age {} \
         registry_unilateral_exit (v2, gated) {} unilateral_exit (v1, gates nothing) {}",
        caps["chain"]["id"],
        caps["chain"]["mainnet"],
        caps["chain"]["height"],
        caps["sync"]["tip_age_seconds"],
        caps["features"]["channel_registry_unilateral_exit"],
        caps["features"]["channel_unilateral_exit"]
    );

    let (hub_url, hub_address, hub_task) = serve_hub(
        &mainnet_url,
        "mainnet-bounded-pilot",
        &work,
        &optional_env("HPAY_D_MAINNET_HUB_LISTEN", "127.0.0.1:0"),
    )
    .await;

    // ------------------------------------------------- criterion 4: the wire
    // What the Hub actually serves, byte for byte, and what the wallet's own
    // deserializer makes of the same bytes.
    let wire: serde_json::Value = reqwest::get(format!("{hub_url}/v1/readiness/mainnet"))
        .await
        .expect("hub readiness")
        .json()
        .await
        .expect("readiness json");
    println!("[wire] {}", serde_json::to_string(&wire).unwrap());
    let parsed = L2HubClient::new_for_network(&hub_url, "mainnet")
        .mainnet_readiness()
        .await
        .expect("the wallet must be able to parse what the Hub serves");
    println!(
        "[read] profile {:?} payments_enabled {} mainnet_detected {:?} trusted_bounded_pilot {} trustless_finality {} unilateral_l1_enforceable {} blockers {:?}",
        parsed.profile,
        parsed.payments_enabled,
        parsed.mainnet_detected,
        parsed.trusted_bounded_pilot,
        parsed.trustless_finality,
        parsed.unilateral_l1_enforceable,
        parsed.blockers
    );
    // Wallet-parsed value must equal the served value, field by field, for the
    // fields the gate actually decides on.
    assert_eq!(Some(parsed.profile.as_str()), wire["profile"].as_str());
    assert_eq!(
        parsed.payments_enabled,
        wire["payments_enabled"].as_bool().unwrap()
    );
    assert_eq!(
        parsed.trusted_bounded_pilot,
        wire["trusted_bounded_pilot"].as_bool().unwrap()
    );
    assert_eq!(
        parsed.trustless_finality,
        wire["trustless_finality"].as_bool().unwrap()
    );
    assert_eq!(
        parsed.unilateral_l1_enforceable,
        wire["unilateral_l1_enforceable"].as_bool().unwrap()
    );
    assert_eq!(
        parsed.blockers.len(),
        wire["blockers"].as_array().unwrap().len()
    );

    // -------------------------------- the gate itself, off and on, same document
    // This is the exact call `prepare_channel_open` makes, one frame down.
    let deposit = optional_env("HPAY_D_DEPOSIT", "1");
    for consent in [false, true] {
        let client = L2HubClient::new_for_wallet_policy(&hub_url, "mainnet", consent);
        match client
            .require_channel_open_ready(&hub_address, &deposit)
            .await
        {
            Ok(health) => println!(
                "[gate consent={consent}] OPENED: hub ok {} profile {:?} bounded_ready {}",
                health.ok, health.deployment_profile, health.trusted_bounded_pilot_ready
            ),
            Err(error) => println!("[gate consent={consent}] REFUSED: {error}"),
        }
        let payment = L2HubClient::new_for_wallet_policy(&hub_url, "mainnet", consent);
        match payment.require_mainnet_payment_ready(Some("0.1")).await {
            Ok(readiness) => println!(
                "[paygate consent={consent}] OPENED against profile {:?}",
                readiness.profile
            ),
            Err(error) => println!("[paygate consent={consent}] REFUSED: {error}"),
        }
    }

    // ------------------------------- the Send screen, mainnet mode, off and on
    // SAFETY: single-threaded setup before any wallet thread exists.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("wallet-data"));
        std::env::set_var("HACASH_WALLET_NETWORK", "mainnet");
    }
    std::fs::create_dir_all(work.join("wallet-data")).unwrap();

    // The L1 node the wallet reads its channel from. Two configurations are
    // measured, and they are NOT the same claim:
    //
    //  * `HPAY_D_SEND_NODE_URL` unset  -> the real mainnet node. Faithful, but
    //    this payer owns no mainnet channel, so the L2 plan cannot complete for
    //    a reason that has nothing to do with consent. What it still shows is
    //    WHERE the plan dies: at the consent gate, or past it.
    //  * `HPAY_D_SEND_NODE_URL` set to the chain-7 node -> a composite. The
    //    consent gate is judged against the real mainnet Hub document while the
    //    channel is read from the pilot chain. This is the only way to watch a
    //    complete L2 plan be produced under the bounded-pilot policy without
    //    owning a funded mainnet channel. Reported as a composite, never as a
    //    mainnet payment.
    let send_node = optional_env("HPAY_D_SEND_NODE_URL", &mainnet_url);
    let composite = send_node != mainnet_url;
    println!("[send] L1 node {send_node} composite {composite}");

    let payer = payer_account();
    let payer_address = payer.address();
    let mut wallet = WalletService::new(Some(send_node.clone()), Some(hub_url.clone())).unwrap();
    match wallet.unlock(VAULT_PASSPHRASE) {
        Ok(address) => println!("[wall] unlocked existing vault {address}"),
        Err(_) => {
            let address = wallet
                .import_wallet(&payer.secret_hex(), VAULT_PASSPHRASE, &payer_address)
                .expect("import payer key");
            println!("[wall] imported vault {address}");
        }
    }
    let mut settings = wallet.get_settings();
    settings.node_url = send_node.clone();
    settings.l2_hub_url = Some(hub_url.clone());
    settings.hub_right_address = Some(hub_address.clone());
    settings.trusted_mainnet_fast_pay_pilot = false;
    wallet.update_settings(settings).expect("settings");

    // The wallet REFUSES to take a channel id through the generic settings
    // command - `channel_id_hex` is on the sensitive list and only the
    // channel-open ceremony may adopt one:
    //
    //   Policy("security and key settings require their dedicated authenticated command")
    //
    // That check is correct and is not touched here. What this does instead is
    // put the wallet into the state a user is in AFTER a successful open, by
    // writing the same settings file the wallet writes itself, and then letting
    // the real code read it back at construction. The alternative would be to
    // open a funded channel on mainnet, which is exactly what must not happen.
    drop(wallet);
    let settings_path = hacash_wallet_core::paths::settings_path();
    let mut on_disk: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&settings_path).expect("settings file"))
            .expect("settings json");
    on_disk["channel_id_hex"] = serde_json::Value::String(required_env("HPAY_D_CHANNEL_ID"));
    std::fs::write(&settings_path, serde_json::to_vec_pretty(&on_disk).unwrap()).unwrap();
    println!("[wall] seeded channel id into {}", settings_path.display());

    let mut wallet = WalletService::new(Some(send_node.clone()), Some(hub_url.clone())).unwrap();
    wallet.unlock(VAULT_PASSPHRASE).expect("unlock");
    println!(
        "[wall] network_mode {} channel {:?} consent {}",
        wallet.get_settings().network_mode,
        wallet.get_settings().channel_id_hex,
        wallet.get_settings().trusted_mainnet_fast_pay_pilot
    );
    assert_eq!(
        wallet.get_settings().network_mode,
        "mainnet",
        "this measurement is only meaningful with the wallet in mainnet mode"
    );

    let rail_off = show_plan(&mut wallet, &hub_address, amount_hac, "mainnet consent OFF").await;
    set_consent(&mut wallet, true);
    let rail_on = show_plan(&mut wallet, &hub_address, amount_hac, "mainnet consent ON ").await;
    println!("[DIFF] mainnet rail with consent OFF = {rail_off:?}, with consent ON = {rail_on:?}");

    // ------------------------- the channel-open half, at the wallet entry point
    // `prepare_channel_open` BUILDS and STORES. It does not broadcast; only
    // `execute_prepared_channel_open` does, and this test never calls it.
    for consent in [false, true] {
        set_consent(&mut wallet, consent);
        match wallet
            .prepare_channel_open(&hub_address, &deposit, "0")
            .await
        {
            Ok(prepared) => println!(
                "[open consent={consent}] PREPARED (not broadcast) {} digest {}",
                prepared.id, prepared.digest
            ),
            Err(error) => println!("[open consent={consent}] REFUSED: {error}"),
        }
    }

    hub_task.abort();
}
