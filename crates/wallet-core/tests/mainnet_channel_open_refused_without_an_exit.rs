//! THE GATE THAT REFUSES TO FUND A CHANNEL THIS WALLET CANNOT LEAVE.
//!
//! The main wallet can open a mainnet Fast Pay channel and has no way out of
//! one. Its three close paths (`prepare_channel_close`,
//! `execute_prepared_channel_close`, `recover_channel_close`) all end at
//! `L2HubClient::close_channel`, so the Hub countersigns and broadcasts or
//! nothing does. The close voucher, the only thing that produces bytes an
//! owner can broadcast alone, was built for the Agent Wallet and was never
//! wired here.
//!
//! The consent checkbox already said all of that, exactly and before the
//! money moved. What it never did was stop anyone. This gate does.
//!
//! WHAT THESE TESTS DO NOT TOUCH. Nothing here opens a socket, reads a chain,
//! unlocks a vault or signs anything. Every test is a pure judgement over a
//! network-mode string and the sentence that judgement returns.
//!
//! WHY THE SENTENCE IS TESTED AS HARD AS THE VERDICT. A refusal that only says
//! "no" reads as a broken build, and a person who believes the app is broken
//! goes looking for another way to do the thing. So the refusal has to name
//! where the exit does exist, and it has to describe that rail honestly: the
//! Hub countersigns once because it chose to, and nothing compels it. That is
//! not a trustless exit and this codebase must never call it one.

use hacash_wallet_core::error::WalletError;
use hacash_wallet_core::l1_channel_close_safety::{
    MAINNET_CHANNEL_OPEN_WITHOUT_EXIT_REFUSAL, refuse_mainnet_channel_open_without_an_exit,
};

fn refusal_text() -> String {
    match refuse_mainnet_channel_open_without_an_exit("mainnet") {
        Ok(()) => panic!("mainnet channel open was allowed; the gate is not shut"),
        Err(err) => err.to_string(),
    }
}

#[test]
fn mainnet_channel_open_is_refused() {
    let err = refuse_mainnet_channel_open_without_an_exit("mainnet")
        .expect_err("a mainnet channel open must be refused");
    // A policy refusal, not a transport or L2 error. This is a decision this
    // build made, not something a Hub or a node said.
    assert!(
        matches!(err, WalletError::Policy(_)),
        "expected a policy refusal, got {err:?}"
    );
    assert!(
        err.to_string()
            .contains(MAINNET_CHANNEL_OPEN_WITHOUT_EXIT_REFUSAL),
        "the refusal must carry the whole sentence, got {err}"
    );
}

#[test]
fn testnet_is_untouched() {
    // Scoped to mainnet, which is the same scope the consent checkbox is
    // scoped to. The pilot rail this mechanism was proven on is a test chain
    // and must keep working, or the next pass has nothing to develop against.
    refuse_mainnet_channel_open_without_an_exit("testnet")
        .expect("testnet channel open must not be refused by this gate");
}

#[test]
fn the_refusal_names_where_the_exit_does_exist() {
    let text = refusal_text();
    assert!(
        text.contains("Agent Wallet"),
        "the refusal must name the rail that has the voucher, got {text}"
    );
    // NOT "build flag", which this test used to demand. The reasoning behind
    // that demand was sound and its premise was false: it assumed a person
    // reading this does not have the voucher code, when every official desktop
    // release builds with agent-wallet-bounded-mainnet-pilot and ships the
    // commands. Naming the flag pointed at the only gate they had already
    // cleared. What must be named instead are the gates that really stop them,
    // because those are what decide whether the trip is worth starting.
    assert!(
        !text.contains("build flag"),
        "the build flag is already on in shipped desktop builds, so naming it \
         sends a person past the gates that actually stop them, got {text}"
    );
    assert!(
        text.contains("separate wallet"),
        "it must say the voucher belongs to a different wallet holding \
         different money, or a person will expect it to free the deposit this \
         refusal is about, got {text}"
    );
    assert!(
        text.contains("run both a Hacash full node and a Fast Pay Hub yourself"),
        "it must say the rail needs a node and a Hub of your own, which is the \
         real cost of getting there, got {text}"
    );
    assert!(
        text.contains("after your deposit has already confirmed"),
        "it must say the destination takes its voucher only after the money is \
         committed, because that is the one hole it does not close, got {text}"
    );
    assert!(
        text.contains("close voucher"),
        "it must name the thing that is missing, got {text}"
    );
}

#[test]
fn the_refusal_never_promises_a_guarantee() {
    let text = refusal_text().to_lowercase();
    // The Agent Wallet rail is a TRUSTED pilot. The Hub countersigns once
    // because it chose to and could refuse, in which case the deposit is
    // stuck. Nothing in this system is trustless and nothing may say so.
    assert!(
        !text.contains("trustless"),
        "the refusal must never describe any of this as trustless, got {text}"
    );
    assert!(
        !text.contains("guarantee"),
        "the refusal must not promise a guarantee it cannot make, got {text}"
    );
    assert!(
        refusal_text().contains("nothing compels it"),
        "it must say the Hub is not compelled to sign, got {}",
        refusal_text()
    );
}

#[test]
fn the_refusal_says_an_open_channel_still_closes() {
    let text = refusal_text();
    // The decision refuses OPENING a new channel, never leaving an old one.
    // Anyone already funded keeps every route they had, and a refusal that
    // does not say so would read as "your existing money is stuck too".
    assert!(
        text.contains("already have one open"),
        "it must say an existing channel is unaffected, got {text}"
    );
    assert!(
        text.contains("testnet is untouched"),
        "it must scope itself to mainnet out loud, got {text}"
    );
}

#[test]
fn the_refusal_states_the_fact_the_money_turns_on() {
    let text = refusal_text();
    // The hard rule: a person meets the plain fact of whether they will have a
    // way out. Not "unsupported", not "not available". The fact.
    assert!(
        text.contains("no way out"),
        "the refusal must state the fact plainly, got {text}"
    );
    assert!(
        text.contains("countersigned and broadcast by the Hub"),
        "it must say who has to act for the money to come back, got {text}"
    );
}

#[test]
fn an_unknown_network_mode_is_not_refused_by_this_gate() {
    // Settings normalise `network_mode` to "mainnet" or "testnet" before this
    // is ever reached, so anything else is a caller bug rather than a user
    // state. This gate is not the place to invent a third meaning: it answers
    // only the mainnet question, and every other mainnet check on the open
    // path (`require_channel_binding_ready`, the transport gate, the network
    // binding) still runs and still refuses whatever it refused before.
    refuse_mainnet_channel_open_without_an_exit("")
        .expect("this gate answers the mainnet question only");
    refuse_mainnet_channel_open_without_an_exit("Mainnet")
        .expect("this gate matches the normalised value settings actually store");
}
