//! WHAT "ENABLE FAST PAY" DOES ON MAINNET, FROM THE COMMAND THE BUTTON CALLS.
//!
//! `wallet_prepare_channel_open` and `wallet_execute_prepared_channel_open` are
//! the two Tauri commands behind the one Enable control on both apps. This
//! harness calls the core functions they wrap and asserts the refusal, which is
//! the only test in this repo that exercises the gate the way a person does.
//!
//! THE ORDERING IS THE POINT, NOT JUST THE REFUSAL. The node URL below points
//! at a port with nothing on it. If the gate ran after the preview, the fee
//! quote, the network binding or the Hub reachability check, this test would
//! see a connection error instead of the sentence. Seeing the sentence proves
//! nothing was quoted, nothing was prompted for and nothing was signed: the
//! person meets the fact about their way out BEFORE the money moves, which is
//! the rule the whole decision rests on.
//!
//! It also covers the case a pure gate test cannot: a prepared channel open
//! stored by an EARLIER build, still sitting in the durable store when this one
//! starts. `prepare_channel_open` refusing does not help that operation. Only
//! the check at the signing boundary does.
//!
//! NO MAINNET CONTACT. Nothing is reachable, nothing is broadcast, and the only
//! chain-shaped thing in the file is the string "mainnet" in a settings field.
//! The vault lives in a scratch directory this test creates and deletes.

use hacash_wallet_core::WalletService;

const VAULT_PASSPHRASE: &str = "enable-fast-pay-refusal-harness-passphrase";
/// A port with nothing behind it. Any attempt at I/O fails loudly and quickly,
/// which is exactly what makes the ordering assertion below meaningful.
const DEAD_NODE_URL: &str = "http://127.0.0.1:1";

/// Everything in one test, because it sets process-wide environment variables
/// and Rust runs tests in the same binary on parallel threads.
#[test]
fn mainnet_enable_fast_pay_refuses_before_any_io_and_before_any_signature() {
    let work = std::env::temp_dir().join(format!("hpay-refusal-{}", std::process::id()));
    let data = work.join("wallet-data");
    std::fs::create_dir_all(&data).expect("scratch wallet data directory");

    // SAFETY: single-threaded setup, and this is the only test in this binary.
    unsafe {
        std::env::set_var("HACASH_WALLET_DATA", &data);
        std::env::set_var("HACASH_WALLET_NETWORK", "mainnet");
    }

    let mut wallet =
        WalletService::new(Some(DEAD_NODE_URL.to_owned()), None).expect("wallet service");
    wallet
        .create_wallet(VAULT_PASSPHRASE)
        .expect("create a vault in the scratch directory");

    let mut settings = wallet.get_settings();
    settings.network_mode = "mainnet".into();
    settings.node_url = DEAD_NODE_URL.to_owned();
    settings.l2_hub_url = Some("http://127.0.0.1:1".to_owned());
    wallet.update_settings(settings).expect("settings");
    assert_eq!(
        wallet.get_settings().network_mode,
        "mainnet",
        "this test is only meaningful on mainnet"
    );

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    // ---- the Enable button, first command -----------------------------------
    let prepare = runtime.block_on(async {
        wallet
            .prepare_channel_open("18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq", "0.2", "0")
            .await
    });
    let prepare_err = prepare
        .expect_err("a mainnet channel open must be refused")
        .to_string();
    println!("[prepare] {prepare_err}");
    assert!(
        prepare_err.contains("no way out of one"),
        "prepare must refuse with the no-way-out sentence, got {prepare_err}"
    );
    assert!(
        prepare_err.contains("Agent Wallet"),
        "the refusal must name where the exit does exist, got {prepare_err}"
    );
    // The ordering assertion. A dead node and a dead Hub are both configured;
    // if either had been contacted first, this is what we would be reading.
    for leaked in [
        "connect",
        "Connection refused",
        "os error",
        "not ready",
        "provider is not ready",
        "fee",
    ] {
        assert!(
            !prepare_err.contains(leaked),
            "the refusal reached the person only after {leaked:?} was attempted, \
             which means something was quoted or contacted before they were told \
             there is no way out: {prepare_err}"
        );
    }

    // ---- the Enable button, second command ----------------------------------
    //
    // No prepared operation exists, and that is the point: without the gate at
    // the signing boundary this returns "prepared operation not found" (or
    // executes, for an operation stored by an earlier build). With the gate it
    // returns the refusal, which proves the check runs before `take_prepared`
    // and therefore before any key is used.
    let execute = runtime.block_on(async {
        wallet
            .execute_prepared_channel_open("any-operation-id-at-all")
            .await
    });
    let execute_err = execute
        .expect_err("executing a prepared mainnet channel open must be refused")
        .to_string();
    println!("[execute] {execute_err}");
    assert!(
        execute_err.contains("no way out of one"),
        "execute must refuse at the signing boundary, ahead of taking the \
         prepared payload, got {execute_err}"
    );
    assert!(
        !execute_err.contains("not found"),
        "the gate must run before the prepared operation is looked up, or a \
         payload stored by an earlier build would still sign: {execute_err}"
    );

    // ---- and the closing routes are not touched -----------------------------
    //
    // The decision refuses opening a new channel, never leaving an old one.
    // `prepare_channel_close` has no such gate, so it fails on the dead node or
    // the missing channel and never on the words above.
    let close = runtime.block_on(async { wallet.prepare_channel_close().await });
    let close_err = close
        .expect_err("no channel is configured, so this fails for its own reasons")
        .to_string();
    println!("[close  ] {close_err}");
    assert!(
        !close_err.contains("no way out of one"),
        "closing an existing channel must not be refused by the open gate: {close_err}"
    );

    drop(wallet);
    let _ = std::fs::remove_dir_all(&work);
}
