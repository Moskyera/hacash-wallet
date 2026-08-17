//! READ-ONLY observation of the mainnet Fast Pay gate, against the real
//! Hacash mainnet fullnode.
//!
//! NOTHING HERE MOVES VALUE, AND NOTHING HERE CAN. Every function this
//! harness calls is a read, a capability query, or a gate evaluation:
//!
//! * `L2HubClient::health`, `::mainnet_readiness` - GET.
//! * `L2HubClient::require_mainnet_payment_ready`, `::require_channel_open_ready`,
//!   `::require_mainnet_hard_guarantees` - pure judgement over a fetched document.
//! * `WalletService::enable_fast_pay` - configures settings and *refuses* to
//!   open a channel; it returns `needs_channel` and stops.
//! * `WalletService::preview_send`, `::preview_channel_open` - build a plan.
//!
//! `send_hac`, `execute_prepared_channel_open` and `open_channel` are never
//! called, so no transaction is ever built, signed or broadcast. The Hub this
//! harness starts is never asked to open an L1 channel.
//!
//! The measurement is "does the gate open or refuse, and what exactly does it
//! say", which is answered entirely before any broadcast would happen.
//!
//! Every test is `#[ignore]`, so `cargo test` and CI are unaffected.
//!
//! Environment:
//!
//! * `HPAY_MAINNET_OBS_NODE_URL` - required. The real mainnet fullnode origin,
//!   e.g. `http://127.0.0.1:8080`. The harness asserts chain id 0 and
//!   `mainnet: true` before doing anything, which is the exact opposite guard
//!   from `local_pilot_fast_pay_live.rs`.
//! * `HPAY_MAINNET_OBS_SEED`     - required. Per-agent identity seed.
//! * `HPAY_MAINNET_OBS_WORKDIR`  - required. Keep it SHORT (Windows ACL,
//!   `SetFileSecurityW` fails past 260 characters).
//! * `HPAY_MAINNET_OBS_FULL_LISTEN`    - optional, default `127.0.0.1:8857`.
//! * `HPAY_MAINNET_OBS_BOUNDED_LISTEN` - optional, default `127.0.0.1:8858`.

use std::path::PathBuf;
use std::sync::Arc;

use hacash_wallet_core::WalletService;
use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::l2_hub::{HubMainnetReadiness, L2HubClient};
use l2_fast_pay_hub::readiness::MainnetPilotAdmissionPolicy;
use l2_fast_pay_hub::{HubState, build_router};

const VAULT_PASSPHRASE: &str = "mainnet-observation-harness-passphrase";
/// 1 HAC, the protocol hard maximum for a pilot payment cap.
const MAX_PAYMENT_ZHU: u64 = 100_000_000;
/// 1 HAC. Well under the 10 HAC hard maximum for channel funding.
const MAX_CHANNEL_ZHU: u64 = 100_000_000;
const MAX_AGGREGATE_TVL_ZHU: u64 = 100_000_000;

fn required_env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set; see this file's module docs"))
}

fn optional_env(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn seed() -> String {
    required_env("HPAY_MAINNET_OBS_SEED")
}

fn payer_account() -> WalletAccount {
    WalletAccount::create(&format!("{}::payer", seed())).unwrap()
}

fn full_pilot_hub_account() -> WalletAccount {
    WalletAccount::create(&format!("{}::hub-full", seed())).unwrap()
}

fn bounded_pilot_hub_account() -> WalletAccount {
    WalletAccount::create(&format!("{}::hub-bounded", seed())).unwrap()
}

fn derived_key_hex(label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed().as_bytes());
    hasher.update(b"::");
    hasher.update(label.as_bytes());
    hex::encode(hasher.finalize())
}

fn workdir() -> PathBuf {
    let dir = PathBuf::from(required_env("HPAY_MAINNET_OBS_WORKDIR"));
    std::fs::create_dir_all(&dir).expect("workdir");
    dir
}

/// Refuse to run against anything that is not the real Hacash mainnet.
///
/// This harness is the mirror image of the pilot one: that harness must never
/// see mainnet, this one must never see anything else, because the whole point
/// is what the gate does against the live network. It stays read-only by never
/// calling a function that broadcasts, not by being pointed somewhere harmless.
async fn assert_real_mainnet(node_url: &str) -> serde_json::Value {
    let capabilities: serde_json::Value = reqwest::get(format!("{node_url}/query/capabilities"))
        .await
        .expect("mainnet fullnode is not reachable")
        .json()
        .await
        .expect("capability document");
    assert_eq!(
        capabilities["chain"]["id"].as_u64(),
        Some(0),
        "this harness only observes the real Hacash mainnet (chain id 0)"
    );
    assert_eq!(
        capabilities["chain"]["mainnet"].as_bool(),
        Some(true),
        "this harness only observes the real Hacash mainnet"
    );
    println!(
        "[node] {node_url} chain id {} mainnet {} height {} channel_unilateral_exit {}",
        capabilities["chain"]["id"],
        capabilities["chain"]["mainnet"],
        capabilities["chain"]["height"],
        capabilities["features"]["channel_unilateral_exit"]
    );
    capabilities
}

struct RunningHub {
    url: String,
    address: String,
    task: tokio::task::JoinHandle<()>,
}

/// Start the real Hub, in this process, on a real TCP socket, pointed at the
/// real mainnet fullnode. Same `HubState` and same `build_router` that
/// `fast-pay-hub.exe` serves.
///
/// The Hub is started, not driven. It answers `/v1/health` and
/// `/v1/readiness/mainnet` and is never asked to open a channel or settle a
/// payment, so it never submits anything to the fullnode it is pointed at.
async fn start_hub(
    profile: &str,
    account: &WalletAccount,
    node_url: &str,
    state_file: PathBuf,
    listen: &str,
    allowlisted_user: &str,
    key_label: &str,
) -> RunningHub {
    let address = account.address();
    let admission =
        MainnetPilotAdmissionPolicy::try_new([allowlisted_user], MAX_AGGREGATE_TVL_ZHU).unwrap();
    let state = Arc::new(
        HubState::new_secure_with_mainnet_admission(
            format!("HPAY Mainnet Observation Hub ({profile})"),
            address.clone(),
            node_url.to_owned(),
            None,
            state_file,
            account.secret_hex().to_string(),
            &derived_key_hex(&format!("{key_label}-journal")),
            &derived_key_hex(&format!("{key_label}-state")),
            profile.to_owned(),
            MAX_PAYMENT_ZHU,
            MAX_CHANNEL_ZHU,
            admission,
        )
        .expect("hub state"),
    );
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });
    println!("[hub ] {url} profile {profile} address {address}");
    RunningHub { url, address, task }
}

async fn raw_get(url: &str) -> String {
    reqwest::get(url)
        .await
        .expect("hub request")
        .text()
        .await
        .expect("hub body")
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Print the addresses this seed derives. Nothing secret, no chain contact.
#[test]
#[ignore = "live mainnet observation only"]
fn observation_identities() {
    println!("payer          = {}", payer_account().address());
    println!("hub (full)     = {}", full_pilot_hub_account().address());
    println!("hub (bounded)  = {}", bounded_pilot_hub_account().address());
}

/// CRITERION 3 and CRITERION 4, and the mainnet half of CRITERION 2.
///
/// One process, both Hubs, one wallet, so the two profiles are compared under
/// identical conditions: same fullnode, same caps, same allowlist, same
/// consent. The only difference between them is the deployment profile.
#[test]
#[ignore = "live mainnet observation only"]
fn mainnet_pilot_gate_observation() {
    runtime().block_on(observe());
}

/// CRITERION 4, the other direction: a value the Hub publishes, that the
/// wallet does not keep, on a Hub configured so that the value matters.
///
/// The bounded pilot admits users from an allowlist. `/v1/readiness/mainnet`
/// publishes `allowlist_configured`, which says an allowlist EXISTS, and
/// never says who is on it. This Hub's allowlist deliberately does not
/// contain this wallet's user, and everything else is identical to the
/// bounded Hub that opened the gate above.
///
/// Read-only: it asks the wallet whether it would proceed. It never asks the
/// Hub to open anything, so no transaction is built, signed or submitted.
#[test]
#[ignore = "live mainnet observation only"]
fn bounded_pilot_gate_when_this_user_is_not_on_the_hub_allowlist() {
    runtime().block_on(observe_non_allowlisted());
}

async fn observe_non_allowlisted() {
    let node_url = required_env("HPAY_MAINNET_OBS_NODE_URL");
    let work = workdir();
    let payer = payer_account();
    let payer_address = payer.address();
    assert_real_mainnet(&node_url).await;

    // Somebody else entirely. Same seed family so it is reproducible, and
    // deliberately not the wallet's user.
    let stranger = WalletAccount::create(&format!("{}::stranger", seed()))
        .unwrap()
        .address();
    println!("[alw ] Hub allowlist contains only {stranger}");
    println!("[alw ] this wallet's user is        {payer_address}");
    assert_ne!(stranger, payer_address);

    let hub = start_hub(
        "mainnet-bounded-pilot",
        &WalletAccount::create(&format!("{}::hub-closed", seed())).unwrap(),
        &node_url,
        work.join("hub-closed.sealed.json"),
        &optional_env("HPAY_MAINNET_OBS_CLOSED_LISTEN", "127.0.0.1:8859"),
        &stranger,
        "closed",
    )
    .await;

    let served = raw_get(&format!("{}/v1/readiness/mainnet", hub.url)).await;
    let doc: HubMainnetReadiness = serde_json::from_str(&served).expect("parse readiness");
    let raw: serde_json::Value = serde_json::from_str(&served).expect("parse raw");
    println!(
        "[alw ] served: payments_enabled {} blockers {:?} allowlist_configured {}",
        doc.payments_enabled, doc.blockers, raw["allowlist_configured"]
    );

    let client = L2HubClient::new_for_wallet_policy(hub.url.clone(), "mainnet", true);
    report_gate(
        "require_mainnet_payment_ready(0.001)",
        client
            .require_mainnet_payment_ready(Some("0.001"))
            .await
            .map(|_| ()),
    );
    report_gate(
        "require_channel_open_ready(hub, 0.05)",
        client
            .require_channel_open_ready(&hub.address, "0.05")
            .await
            .map(|_| ()),
    );

    // SAFETY: single-threaded setup before any wallet thread exists.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("wallet-data-closed"));
        std::env::set_var("HACASH_WALLET_NETWORK", "mainnet");
    }
    std::fs::create_dir_all(work.join("wallet-data-closed")).unwrap();
    let mut wallet = WalletService::new(Some(node_url.clone()), Some(hub.url.clone())).unwrap();
    if wallet.unlock(VAULT_PASSPHRASE).is_err() {
        wallet
            .import_wallet(&payer.secret_hex(), VAULT_PASSPHRASE, &payer_address)
            .expect("import");
    }
    let mut settings = wallet.get_settings();
    settings.node_url = node_url.clone();
    settings.network_mode = "mainnet".into();
    settings.l2_hub_url = Some(hub.url.clone());
    settings.hub_right_address = Some(hub.address.clone());
    settings.channel_id_hex = None;
    wallet.update_settings(settings).expect("settings");
    // The consent box, ticked. Giving consent now needs the authenticated
    // command; `update_settings` refuses to turn it on.
    wallet
        .set_trusted_mainnet_fast_pay_pilot(VAULT_PASSPHRASE, true)
        .expect("authenticated mainnet pilot consent");

    match wallet.enable_fast_pay(Some(0.05)).await {
        Ok(status) => println!(
            "[user] enable_fast_pay  -> GATE OPENED: state {:?} can_enable {} message {:?}",
            status.state, status.can_enable, status.message
        ),
        Err(error) => println!("[user] enable_fast_pay  -> REFUSED: {error}"),
    }
    match wallet.prepare_channel_open(&hub.address, "0.05", "0").await {
        Ok(prepared) => println!(
            "[user] prepare_channel_open -> GATE OPENED, unsigned tx prepared id {} (NOT executed)",
            prepared.id
        ),
        Err(error) => println!("[user] prepare_channel_open -> REFUSED: {error}"),
    }
    println!("[stop] STOPPING BEFORE BROADCAST.");
    hub.task.abort();
}

async fn observe() {
    let node_url = required_env("HPAY_MAINNET_OBS_NODE_URL");
    let work = workdir();
    let payer = payer_account();
    let payer_address = payer.address();

    assert_real_mainnet(&node_url).await;
    println!("[wall] payer (unfunded, observation only) {payer_address}");

    let full = start_hub(
        "mainnet-pilot",
        &full_pilot_hub_account(),
        &node_url,
        work.join("hub-full.sealed.json"),
        &optional_env("HPAY_MAINNET_OBS_FULL_LISTEN", "127.0.0.1:8857"),
        &payer_address,
        "full",
    )
    .await;
    let bounded = start_hub(
        "mainnet-bounded-pilot",
        &bounded_pilot_hub_account(),
        &node_url,
        work.join("hub-bounded.sealed.json"),
        &optional_env("HPAY_MAINNET_OBS_BOUNDED_LISTEN", "127.0.0.1:8858"),
        &payer_address,
        "bounded",
    )
    .await;

    // ============================================================== SERVED
    println!("\n===== SERVED /v1/readiness/mainnet (FULL mainnet-pilot) =====");
    let full_served = raw_get(&format!("{}/v1/readiness/mainnet", full.url)).await;
    println!("{full_served}");
    println!("\n===== SERVED /v1/health (FULL mainnet-pilot) =====");
    println!("{}", raw_get(&format!("{}/v1/health", full.url)).await);

    println!("\n===== SERVED /v1/readiness/mainnet (BOUNDED mainnet-bounded-pilot) =====");
    let bounded_served = raw_get(&format!("{}/v1/readiness/mainnet", bounded.url)).await;
    println!("{bounded_served}");
    println!("\n===== SERVED /v1/health (BOUNDED) =====");
    println!("{}", raw_get(&format!("{}/v1/health", bounded.url)).await);

    // ====================================================== CRITERION 4
    println!("\n===== CRITERION 4: served JSON vs what the wallet parsed =====");
    compare_served_against_parsed("FULL mainnet-pilot", &full_served);
    compare_served_against_parsed("BOUNDED mainnet-bounded-pilot", &bounded_served);

    // The same type, over the real wire, through the client the wallet builds.
    let consented_full = L2HubClient::new_for_wallet_policy(full.url.clone(), "mainnet", true);
    let consented_bounded =
        L2HubClient::new_for_wallet_policy(bounded.url.clone(), "mainnet", true);
    let live_full = consented_full.mainnet_readiness().await;
    let live_bounded = consented_bounded.mainnet_readiness().await;
    println!(
        "[parse] live client fetch, FULL:    {}",
        match &live_full {
            Ok(doc) => format!(
                "ok, profile {} payments_enabled {} blockers {:?}",
                doc.profile, doc.payments_enabled, doc.blockers
            ),
            Err(error) => format!("ERROR {error}"),
        }
    );
    println!(
        "[parse] live client fetch, BOUNDED: {}",
        match &live_bounded {
            Ok(doc) => format!(
                "ok, profile {} payments_enabled {} blockers {:?}",
                doc.profile, doc.payments_enabled, doc.blockers
            ),
            Err(error) => format!("ERROR {error}"),
        }
    );

    // ====================================================== CRITERION 3
    println!("\n===== CRITERION 3: the refusal, at every gate the wallet has =====");
    for (label, client) in [
        (
            "FULL pilot Hub, consent ON  (policy TrustedBoundedPilot)",
            L2HubClient::new_for_wallet_policy(full.url.clone(), "mainnet", true),
        ),
        (
            "FULL pilot Hub, consent OFF (policy TrustlessOnly)",
            L2HubClient::new_for_wallet_policy(full.url.clone(), "mainnet", false),
        ),
    ] {
        println!("\n--- {label}");
        report_gate("require_mainnet_payment_ready(0.001)", {
            client
                .require_mainnet_payment_ready(Some("0.001"))
                .await
                .map(|_| ())
        });
        report_gate(
            "require_mainnet_hard_guarantees()",
            client.require_mainnet_hard_guarantees().await.map(|_| ()),
        );
        report_gate(
            "require_channel_open_ready(hub, 0.05)",
            client
                .require_channel_open_ready(&full.address, "0.05")
                .await
                .map(|_| ()),
        );
    }

    // ============================================== the real wallet service
    // Real vault, real settings file, real network mode. `HACASH_WALLET_NETWORK`
    // is the supported runtime override.
    // SAFETY: single-threaded setup before any wallet thread exists.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", work.join("wallet-data"));
        std::env::set_var("HACASH_WALLET_NETWORK", "mainnet");
    }
    std::fs::create_dir_all(work.join("wallet-data")).unwrap();

    let mut wallet = WalletService::new(Some(node_url.clone()), Some(full.url.clone())).unwrap();
    match wallet.unlock(VAULT_PASSPHRASE) {
        Ok(address) => println!("\n[wall] unlocked existing vault {address}"),
        Err(_) => {
            let address = wallet
                .import_wallet(&payer.secret_hex(), VAULT_PASSPHRASE, &payer_address)
                .expect("import the observation payer key");
            println!("\n[wall] imported vault {address}");
        }
    }
    let mut settings = wallet.get_settings();
    settings.node_url = node_url.clone();
    settings.network_mode = "mainnet".into();
    settings.l2_hub_url = Some(full.url.clone());
    settings.hub_right_address = Some(full.address.clone());
    settings.channel_id_hex = None;
    wallet.update_settings(settings).expect("wallet settings");
    // The consent box, ticked. Giving consent now needs the authenticated
    // command; `update_settings` refuses to turn it on.
    wallet
        .set_trusted_mainnet_fast_pay_pilot(VAULT_PASSPHRASE, true)
        .expect("authenticated mainnet pilot consent");
    println!(
        "[wall] network_mode {} consent {} hub {}",
        wallet.get_settings().network_mode,
        wallet.get_settings().trusted_mainnet_fast_pay_pilot,
        wallet.get_settings().l2_hub_url.clone().unwrap_or_default()
    );

    println!("\n--- what the USER sees, FULL mainnet-pilot Hub, consent ON");
    match wallet.fast_pay_status().await {
        Ok(status) => println!(
            "[user] fast_pay_status  -> state {:?} can_enable {} message {:?}",
            status.state, status.can_enable, status.message
        ),
        Err(error) => println!("[user] fast_pay_status  -> ERROR {error}"),
    }
    match wallet.enable_fast_pay(Some(0.05)).await {
        Ok(status) => println!(
            "[user] enable_fast_pay  -> OPENED GATE: state {:?} can_enable {} message {:?}",
            status.state, status.can_enable, status.message
        ),
        Err(error) => println!("[user] enable_fast_pay  -> REFUSED: {error}"),
    }
    match wallet
        .preview_channel_open(&full.address, "0.05", "0")
        .await
    {
        Ok(preview) => println!(
            "[user] preview_channel_open -> OK id {} left {} {}",
            preview.channel_id, preview.left_address, preview.left_deposit
        ),
        Err(error) => println!("[user] preview_channel_open -> REFUSED: {error}"),
    }
    match wallet
        .prepare_channel_open(&full.address, "0.05", "0")
        .await
    {
        Ok(prepared) => println!(
            "[user] prepare_channel_open -> GATE OPENED, unsigned tx prepared id {} (NOT executed)",
            prepared.id
        ),
        Err(error) => println!("[user] prepare_channel_open -> REFUSED: {error}"),
    }
    match wallet
        .preview_send(&full.address, 0.001, &Default::default())
        .await
    {
        Ok(preview) => println!(
            "[user] preview_send     -> rail {:?} label {:?} fee {:?} channel {:?}",
            preview.plan.rail,
            preview.plan.rail_label,
            preview.plan.estimated_fee,
            preview.plan.channel_id
        ),
        Err(error) => println!("[user] preview_send     -> ERROR {error}"),
    }

    // ====================================================== CRITERION 2
    println!("\n===== CRITERION 2: BOUNDED pilot Hub on REAL mainnet, consent ON =====");
    for (label, client) in [
        (
            "BOUNDED Hub, consent ON  (policy TrustedBoundedPilot)",
            L2HubClient::new_for_wallet_policy(bounded.url.clone(), "mainnet", true),
        ),
        (
            "BOUNDED Hub, consent OFF (policy TrustlessOnly)",
            L2HubClient::new_for_wallet_policy(bounded.url.clone(), "mainnet", false),
        ),
    ] {
        println!("\n--- {label}");
        report_gate(
            "require_mainnet_payment_ready(0.001)",
            client
                .require_mainnet_payment_ready(Some("0.001"))
                .await
                .map(|_| ()),
        );
        report_gate(
            "require_mainnet_hard_guarantees()",
            client.require_mainnet_hard_guarantees().await.map(|_| ()),
        );
        report_gate(
            "require_channel_open_ready(hub, 0.05)",
            client
                .require_channel_open_ready(&bounded.address, "0.05")
                .await
                .map(|_| ()),
        );
    }

    let mut settings = wallet.get_settings();
    settings.l2_hub_url = Some(bounded.url.clone());
    settings.hub_right_address = Some(bounded.address.clone());
    wallet.update_settings(settings).expect("wallet settings");
    // The consent box, ticked. Giving consent now needs the authenticated
    // command; `update_settings` refuses to turn it on.
    wallet
        .set_trusted_mainnet_fast_pay_pilot(VAULT_PASSPHRASE, true)
        .expect("authenticated mainnet pilot consent");

    println!("\n--- what the USER sees, BOUNDED Hub, consent ON");
    match wallet.fast_pay_status().await {
        Ok(status) => println!(
            "[user] fast_pay_status  -> state {:?} can_enable {} message {:?}",
            status.state, status.can_enable, status.message
        ),
        Err(error) => println!("[user] fast_pay_status  -> ERROR {error}"),
    }
    match wallet.enable_fast_pay(Some(0.05)).await {
        Ok(status) => println!(
            "[user] enable_fast_pay  -> GATE OPENED: state {:?} can_enable {} message {:?}",
            status.state, status.can_enable, status.message
        ),
        Err(error) => println!("[user] enable_fast_pay  -> REFUSED: {error}"),
    }
    match wallet
        .preview_channel_open(&bounded.address, "0.05", "0")
        .await
    {
        Ok(preview) => println!(
            "[user] preview_channel_open -> OK id {} left {} {} right {} {}",
            preview.channel_id,
            preview.left_address,
            preview.left_deposit,
            preview.right_address,
            preview.right_deposit
        ),
        Err(error) => println!("[user] preview_channel_open -> REFUSED: {error}"),
    }
    // Builds an UNSIGNED transaction body and stores it for review. It does not
    // sign and it does not broadcast; `execute_prepared_channel_open` would,
    // and is deliberately never called anywhere in this file.
    match wallet
        .prepare_channel_open(&bounded.address, "0.05", "0")
        .await
    {
        Ok(prepared) => println!(
            "[user] prepare_channel_open -> GATE OPENED, unsigned tx prepared id {} (NOT executed)",
            prepared.id
        ),
        Err(error) => println!("[user] prepare_channel_open -> REFUSED: {error}"),
    }

    // ============================ CRITERION 3, mechanically ============
    // Collect every string the wallet can put in front of a user when it
    // refuses the FULL mainnet-pilot Hub, and check each of the three blockers
    // the Hub actually published against all of them. This is the criterion
    // stated as a measurement instead of as a reading of the transcript.
    println!("\n===== CRITERION 3, MECHANICAL: does any published blocker reach the user? =====");
    let published: HubMainnetReadiness =
        serde_json::from_str(&full_served).expect("parse full pilot readiness");
    println!("[name] Hub published blockers: {:?}", published.blockers);

    let mut settings = wallet.get_settings();
    settings.l2_hub_url = Some(full.url.clone());
    settings.hub_right_address = Some(full.address.clone());
    wallet.update_settings(settings).expect("wallet settings");
    // The consent box, ticked. Giving consent now needs the authenticated
    // command; `update_settings` refuses to turn it on.
    wallet
        .set_trusted_mainnet_fast_pay_pilot(VAULT_PASSPHRASE, true)
        .expect("authenticated mainnet pilot consent");

    let mut surfaces: Vec<(String, String)> = Vec::new();
    surfaces.push((
        "fast_pay_status.message".into(),
        wallet
            .fast_pay_status()
            .await
            .map(|status| status.message)
            .unwrap_or_else(|error| error.to_string()),
    ));
    surfaces.push((
        "enable_fast_pay".into(),
        match wallet.enable_fast_pay(Some(0.05)).await {
            Ok(status) => format!("OPENED: {}", status.message),
            Err(error) => error.to_string(),
        },
    ));
    surfaces.push((
        "prepare_channel_open".into(),
        match wallet
            .prepare_channel_open(&full.address, "0.05", "0")
            .await
        {
            Ok(prepared) => format!("OPENED: {}", prepared.id),
            Err(error) => error.to_string(),
        },
    ));
    let consented_full = L2HubClient::new_for_wallet_policy(full.url.clone(), "mainnet", true);
    surfaces.push((
        "require_mainnet_payment_ready".into(),
        match consented_full
            .require_mainnet_payment_ready(Some("0.001"))
            .await
        {
            Ok(_) => "OPENED".into(),
            Err(error) => error.to_string(),
        },
    ));
    surfaces.push((
        "require_channel_open_ready".into(),
        match consented_full
            .require_channel_open_ready(&full.address, "0.05")
            .await
        {
            Ok(_) => "OPENED".into(),
            Err(error) => error.to_string(),
        },
    ));

    for (surface, message) in &surfaces {
        println!("[name] {surface:<30} = {message:?}");
    }
    let mut named = 0usize;
    for blocker in &published.blockers {
        let hits: Vec<&str> = surfaces
            .iter()
            .filter(|(_, message)| message.contains(blocker.as_str()))
            .map(|(surface, _)| surface.as_str())
            .collect();
        if hits.is_empty() {
            println!("[name] NOT NAMED anywhere: {blocker}");
        } else {
            named += 1;
            println!("[name] named by {hits:?}: {blocker}");
        }
    }
    println!(
        "[name] VERDICT: {named} of {} published blockers reach a user-visible string",
        published.blockers.len()
    );

    println!("\n[stop] STOPPING BEFORE BROADCAST. No transaction was signed or submitted.");
    full.task.abort();
    bounded.task.abort();
}

fn report_gate(label: &str, outcome: Result<(), hacash_wallet_core::error::WalletError>) {
    match outcome {
        Ok(()) => println!("[gate] {label:<40} -> OPENED"),
        Err(error) => println!("[gate] {label:<40} -> REFUSED: {error}"),
    }
}

/// The criterion-4 comparison, done on the wire and not between two Rust
/// structs: take the exact bytes the Hub served, deserialise them with the
/// wallet's own `HubMainnetReadiness`, re-serialise, and diff the two JSON
/// documents key by key.
///
/// A key served but absent after the round trip is a value the wallet threw
/// away. A key present after the round trip but not served is a value the
/// wallet invented (a `serde(default)` filling in for something the Hub never
/// said). Either one is the finding.
fn compare_served_against_parsed(label: &str, served_body: &str) {
    let served: serde_json::Value =
        serde_json::from_str(served_body).expect("the Hub served valid JSON");
    let parsed: HubMainnetReadiness = match serde_json::from_str(served_body) {
        Ok(parsed) => parsed,
        Err(error) => {
            println!("[diff] {label}: THE WALLET CANNOT PARSE WHAT THE HUB SERVES: {error}");
            return;
        }
    };
    let round_tripped = serde_json::to_value(&parsed).expect("re-serialise");

    let mut dropped = Vec::new();
    let mut invented = Vec::new();
    let mut differing = Vec::new();
    diff(
        "",
        &served,
        &round_tripped,
        &mut dropped,
        &mut invented,
        &mut differing,
    );

    println!("\n[diff] {label}");
    println!(
        "[diff]   served keys not kept by the wallet ({}):",
        dropped.len()
    );
    for key in &dropped {
        println!("[diff]     - {key}");
    }
    println!(
        "[diff]   keys the wallet holds that the Hub did not serve ({}):",
        invented.len()
    );
    for key in &invented {
        println!("[diff]     + {key}");
    }
    println!(
        "[diff]   keys present in both whose VALUE differs ({}):",
        differing.len()
    );
    for key in &differing {
        println!("[diff]     ! {key}");
    }
}

fn diff(
    path: &str,
    served: &serde_json::Value,
    parsed: &serde_json::Value,
    dropped: &mut Vec<String>,
    invented: &mut Vec<String>,
    differing: &mut Vec<String>,
) {
    match (served, parsed) {
        (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
            for (key, value) in left {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                match right.get(key) {
                    Some(other) => diff(&child, value, other, dropped, invented, differing),
                    None => dropped.push(format!("{child} = {value}")),
                }
            }
            for (key, value) in right {
                if !left.contains_key(key) {
                    let child = if path.is_empty() {
                        key.clone()
                    } else {
                        format!("{path}.{key}")
                    };
                    invented.push(format!("{child} = {value}"));
                }
            }
        }
        (left, right) if left != right => {
            differing.push(format!("{path}: served {left} vs wallet {right}"));
        }
        _ => {}
    }
}
