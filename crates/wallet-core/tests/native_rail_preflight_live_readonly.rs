//! Run the native-rail mainnet preflight against a LIVE node and a LIVE Hub,
//! and print exactly what it said.
//!
//! NOTHING HERE MOVES VALUE, AND NOTHING HERE CAN. The only functions it calls
//! are `observe` and `judge`. `observe` issues four GETs: `/query/capabilities`,
//! `/query/block/intro?height=1`, `/v1/health`, `/v1/readiness/mainnet`, plus
//! one GET against the POST-only `/v1/l1/channel/close-voucher`, which axum
//! answers 405 without invoking the handler. `judge` is pure. No transaction is
//! built, signed or submitted, no wallet is unlocked, and the Hub started here
//! is started, not driven.
//!
//! It is `#[ignore]`, so `cargo test` and CI are unaffected.
//!
//! Environment:
//!
//! * `HPAY_PREFLIGHT_NODE_URL`  - default `http://127.0.0.1:8197`, the chain 7
//!   pilot node. This is a MAINNET preflight, so pointed at chain 7 it refuses,
//!   which is the point: it refuses for the same reasons it would refuse a
//!   fake mainnet.
//! * `HPAY_PREFLIGHT_HUB_LISTEN` - default `127.0.0.1:8871`.
//! * `HPAY_PREFLIGHT_SEED`       - default a fixed local string. Derives the
//!   Hub's identity and the owner address only; no key here ever signs.

use std::path::PathBuf;
use std::sync::Arc;

use hacash_wallet_core::account::WalletAccount;
use hacash_wallet_core::hpay_native_rail_preflight::{
    CheckSeverity, CheckStatus, PreflightRequest, PreflightVerdict, judge, observe,
};
use l2_fast_pay_hub::readiness::MainnetPilotAdmissionPolicy;
use l2_fast_pay_hub::{HubState, build_router};

const MAX_PAYMENT_ZHU: u64 = 100_000_000;
const MAX_CHANNEL_ZHU: u64 = 1_000_000_000;
const MAX_AGGREGATE_TVL_ZHU: u64 = 10_000_000_000;

fn env_or(name: &str, fallback: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| fallback.to_owned())
}

fn seed() -> String {
    env_or("HPAY_PREFLIGHT_SEED", "hpay-native-rail-preflight-local")
}

fn derived_key_hex(label: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(seed().as_bytes());
    hasher.update(b"::");
    hasher.update(label.as_bytes());
    hex::encode(hasher.finalize())
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Start the real Hub, in this process, on a real socket, with the same
/// `HubState` and `build_router` that `fast-pay-hub.exe` serves. Started, not
/// driven: it answers GETs and is never asked to open or settle anything.
async fn start_bounded_pilot_hub(
    node_url: &str,
    listen: &str,
    owner: &str,
    state_file: PathBuf,
) -> (String, String) {
    let account = WalletAccount::create(&format!("{}::hub", seed())).unwrap();
    let address = account.address();
    let admission = MainnetPilotAdmissionPolicy::try_new([owner], MAX_AGGREGATE_TVL_ZHU).unwrap();
    let state = Arc::new(
        HubState::new_secure_with_mainnet_admission(
            "HPAY native-rail preflight Hub".to_owned(),
            address.clone(),
            node_url.to_owned(),
            None,
            state_file,
            account.secret_hex().to_string(),
            &derived_key_hex("journal"),
            &derived_key_hex("state"),
            "mainnet-bounded-pilot".to_owned(),
            MAX_PAYMENT_ZHU,
            MAX_CHANNEL_ZHU,
            admission,
        )
        .expect("hub state"),
    );
    let listener = tokio::net::TcpListener::bind(listen).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, build_router(state)).await.unwrap();
    });
    (url, address)
}

#[test]
#[ignore = "live read-only observation only"]
fn native_rail_preflight_against_the_live_pilot_node_and_a_live_hub() {
    runtime().block_on(async {
        let node_url = env_or("HPAY_PREFLIGHT_NODE_URL", "http://127.0.0.1:8197");
        let owner = WalletAccount::create(&format!("{}::owner", seed()))
            .unwrap()
            .address();
        let workdir = std::env::temp_dir().join("hpay-preflight-live");
        std::fs::create_dir_all(&workdir).unwrap();
        let (hub_url, hub_address) = start_bounded_pilot_hub(
            &node_url,
            &env_or("HPAY_PREFLIGHT_HUB_LISTEN", "127.0.0.1:8871"),
            &owner,
            workdir.join("hub.sealed.json"),
        )
        .await;

        let request = PreflightRequest {
            node_url: node_url.clone(),
            hub_url: hub_url.clone(),
            hub_address,
            owner_address: owner,
            channel_deposit_hac: env_or("HPAY_PREFLIGHT_DEPOSIT", "1"),
            payment_hac: env_or("HPAY_PREFLIGHT_PAYMENT", "0.1"),
        };
        println!("[node] {node_url}");
        println!("[hub ] {hub_url}");

        let observations = observe(&request).await;
        let report = judge(&request, &observations);

        for check in &report.checks {
            let mark = match (check.severity, check.status) {
                (_, CheckStatus::Pass) => "PASS",
                (CheckSeverity::Fatal, CheckStatus::Fail) => "FATAL FAIL",
                (CheckSeverity::Fatal, CheckStatus::Skip) => "FATAL SKIP",
                (CheckSeverity::Warning, CheckStatus::Fail) => "warn",
                (CheckSeverity::Warning, CheckStatus::Skip) => "warn skip",
            };
            println!("\n[{mark}] {} ({})", check.title, check.id);
            println!("   observed: {}", check.observed);
            if let Some(reason) = &check.reason {
                println!("   note:     {reason}");
            }
        }
        println!(
            "\n[VERDICT] {:?}  fatal failed {}  fatal skipped {}  warnings {}",
            report.verdict, report.fatal_failed, report.fatal_skipped, report.warnings
        );
        println!(
            "\n[JSON]\n{}",
            serde_json::to_string_pretty(&report).unwrap()
        );

        // The assertion depends on what the node actually is, because this
        // harness is pointed at a real mainnet node as readily as at the pilot.
        //
        // Against anything that is not mainnet, a mainnet preflight MUST
        // refuse, and the identity clause is what refuses it. That is the
        // safety property and it is the reason this test exists.
        //
        // Against real mainnet a pass is the correct answer, and asserting
        // NotPass unconditionally turned the right result into a failure. It
        // did exactly that the first time this was run against a synced
        // mainnet node: every one of the nineteen fatal checks passed and the
        // test reported FAILED.
        let is_mainnet = observations
            .capabilities
            .as_ref()
            .is_ok_and(|caps| caps.chain.mainnet && caps.chain.id == 0);
        if is_mainnet {
            assert_eq!(
                report.verdict,
                PreflightVerdict::Pass,
                "a synced mainnet node with a healthy Hub should pass; if this                  fires, read the failed item rather than the verdict"
            );
        } else {
            assert_eq!(
                report.verdict,
                PreflightVerdict::NotPass,
                "a mainnet preflight must never pass against a node that is not                  mainnet"
            );
        }
    });
}
