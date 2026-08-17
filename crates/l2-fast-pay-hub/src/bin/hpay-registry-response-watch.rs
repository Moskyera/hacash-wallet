//! The registry response watch.
//!
//! A shared-registry channel is settled through an arbitration window
//! measured in blocks. If somebody challenges with a bill older than yours
//! and nobody answers before the window closes, the older split is what gets
//! paid. This program is the somebody.
//!
//! It is deliberately tiny and deliberately boring. It reads one file, polls
//! one fullnode, and can take exactly three actions, none of which it can
//! point anywhere but at the channel's own left party. It holds no key of the
//! user's — the only key it has is its own, and that key pays network fees
//! and nothing else.
//!
//! It also cannot open a close. There is no challenge subcommand and no
//! challenge step in the library it calls.
//!
//! Run it wherever you like: a VPS, a Raspberry Pi, a friend's machine, or on
//! your own desktop alongside the wallet. It protects nothing while it is not
//! running, and it prints exactly how large that gap is every time it starts.
//!
//! See `scripts/hpay-registry-response-watch/README.md`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};
use l2_fast_pay_hub::hvm_registry_response_watch::poll::{
    PollOutcomeV1, ResponseWatchV1, require_usable_poll_interval,
};
use l2_fast_pay_hub::hvm_registry_response_watch::{
    HvmRegistryExitKitV1, response_watch_coverage, response_watch_startup_notice,
};
use l2_fast_pay_hub::node::NodeClient;
use sys::Account;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "hpay-registry-response-watch",
    about = "Answers an HPAY registry arbitration challenge for somebody who is not awake"
)]
struct Args {
    /// The exit kit: one channel binding plus the latest bill both parties
    /// signed. Exported by the wallet. Not a private key, and it cannot be
    /// used to send the money anywhere but the channel's own owner.
    #[arg(long, env = "HPAY_RESPONSE_WATCH_KIT")]
    kit: PathBuf,

    /// The fullnode this trusts for chain facts. Never a Hub endpoint: if
    /// this program needed the Hub it would be useless in the exact case it
    /// exists for.
    #[arg(long, env = "HPAY_RESPONSE_WATCH_NODE_URL")]
    node_url: String,

    #[arg(long, env = "HPAY_RESPONSE_WATCH_NODE_API_TOKEN")]
    node_api_token: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Print what this would protect for a given kit, and stop. Reads no
    /// chain, needs no key, sends nothing.
    Explain {
        #[arg(long, default_value_t = 60)]
        poll_interval_seconds: u64,
    },
    /// Look at the chain once, decide, and report. With `--dry-run` it signs
    /// nothing and submits nothing while reaching the identical decision.
    Once {
        #[arg(long, env = "HPAY_RESPONSE_WATCH_SECRET_HEX")]
        secret_hex: String,
        #[arg(long, default_value_t = 10_000)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 250)]
        gas_max: u8,
        #[arg(long)]
        dry_run: bool,
    },
    /// Poll until stopped.
    Watch {
        #[arg(long, env = "HPAY_RESPONSE_WATCH_SECRET_HEX")]
        secret_hex: String,
        #[arg(long, env = "HPAY_RESPONSE_WATCH_POLL_SECONDS", default_value_t = 60)]
        poll_interval_seconds: u64,
        #[arg(long, default_value_t = 10_000)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 250)]
        gas_max: u8,
        #[arg(long)]
        dry_run: bool,
    },
}

fn die(message: impl std::fmt::Display) -> ! {
    eprintln!("{message}");
    std::process::exit(2);
}

fn load_kit(path: &PathBuf) -> HvmRegistryExitKitV1 {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|error| die(format!("cannot read the exit kit at {path:?}: {error}")));
    let kit: HvmRegistryExitKitV1 = serde_json::from_str(&raw)
        .unwrap_or_else(|error| die(format!("the exit kit is not a readable kit: {error}")));
    // Both signatures are checked against the binding before anything else
    // happens. A kit that does not verify here would produce a `respond` the
    // contract refuses, after the fee had been spent.
    kit.validate_crypto()
        .unwrap_or_else(|error| die(format!("the exit kit does not verify: {error}")));
    kit
}

fn account(secret_hex: &str) -> Account {
    let secret = Zeroizing::new(secret_hex.trim().to_owned());
    Account::create_by(secret.as_str())
        .unwrap_or_else(|error| die(format!("invalid responder key: {error}")))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

fn report(outcome: &PollOutcomeV1) {
    match outcome {
        PollOutcomeV1::Idle {
            status,
            chain_serial,
            observed_height,
            lease_live_blocks,
        } => {
            let name = match status {
                2 => "OPEN",
                3 => "CHALLENGING",
                4 => "FINAL",
                _ => "UNKNOWN",
            };
            println!(
                "  ok   height {observed_height}  channel {name}  chain serial {chain_serial}  \
                 storage lease {lease_live_blocks} blocks left"
            );
            // The lease is the one clock that destroys money outright rather
            // than misallocating it, so it is said out loud well before it
            // matters, in the one process guaranteed to be looking.
            if *lease_live_blocks < 2_000 {
                println!(
                    "  WARN this channel's storage lease has {lease_live_blocks} blocks left. \
                     When it lapses the deposit becomes unrecoverable by anyone, including you. \
                     THIS PROGRAM DOES NOT RENEW IT. Renew it from the wallet."
                );
            }
        }
        PollOutcomeV1::AlreadySubmitted { step } => {
            println!("  ok   {step:?} already submitted against this exact chain state; waiting");
        }
        PollOutcomeV1::Submitted {
            step,
            transaction_hash,
        } => {
            println!("  ACT  {step:?} submitted, tx {transaction_hash}");
        }
        PollOutcomeV1::WouldSubmit {
            step,
            transaction_hash,
        } => {
            println!("  DRY  {step:?} would be submitted, tx {transaction_hash} (nothing sent)");
        }
        PollOutcomeV1::WindowTooShort { blocks_left } => {
            println!(
                "  MISS a response is needed and only {blocks_left} blocks of the window remain, \
                 which is below the margin a response needs to be mined in. Nothing was signed: \
                 paying for a late response buys a transaction the contract refuses and leaves \
                 the stale split standing. If this appears, this watcher was not running when it \
                 needed to be."
            );
        }
        PollOutcomeV1::RecoveryRequired => {
            println!(
                "  STOP the chain is ahead of this kit. The kit is stale, and answering with a \
                 stale bill installs an older split, which on this rail pays the provider. \
                 Export a fresh kit from the wallet."
            );
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let kit = load_kit(&args.kit);
    let node_url = args.node_url.clone();
    let node_api_token = args.node_api_token.clone();
    let node_client = || {
        NodeClient::new(node_url.clone())
            .and_then(|client| client.with_api_token(node_api_token.as_deref()))
            .unwrap_or_else(|error| die(format!("cannot reach the fullnode: {error}")))
    };

    match args.command {
        Command::Explain {
            poll_interval_seconds,
        } => {
            let coverage = response_watch_coverage(&kit.binding, poll_interval_seconds)
                .unwrap_or_else(|error| die(error));
            // No key exists in this mode, so the notice is printed against a
            // placeholder that is obviously a placeholder.
            let placeholder = account("hpay-registry-response-watch-explain-placeholder");
            println!(
                "{}",
                response_watch_startup_notice(&kit, &coverage, &args.node_url, &placeholder)
            );
            println!(
                "  This was `explain`. Nothing is being watched. The fee-payer address above \
                 is a placeholder, not a real responder.\n"
            );
            if let Err(error) =
                require_usable_poll_interval(kit.binding.challenge_blocks, poll_interval_seconds)
            {
                println!("  THIS INTERVAL WOULD NOT PROTECT ANYONE: {error}\n");
            }
        }
        Command::Once {
            secret_hex,
            network_fee_zhu,
            gas_max,
            dry_run,
        } => {
            let signer = account(&secret_hex);
            let coverage =
                response_watch_coverage(&kit.binding, 60).unwrap_or_else(|error| die(error));
            println!(
                "{}",
                response_watch_startup_notice(&kit, &coverage, &args.node_url, &signer)
            );
            let node = node_client();
            let mut watch = ResponseWatchV1::new(kit, network_fee_zhu, gas_max, dry_run)
                .unwrap_or_else(|error| die(error));
            match watch.poll_once(&node, &signer, now_unix()).await {
                Ok(outcome) => report(&outcome),
                Err(error) => {
                    eprintln!("  ERR  {error}");
                    std::process::exit(1);
                }
            }
        }
        Command::Watch {
            secret_hex,
            poll_interval_seconds,
            network_fee_zhu,
            gas_max,
            dry_run,
        } => {
            let signer = account(&secret_hex);
            // Refused before the banner, because a configuration that cannot
            // answer in time should never get as far as looking like it is
            // protecting something.
            require_usable_poll_interval(kit.binding.challenge_blocks, poll_interval_seconds)
                .unwrap_or_else(|error| die(error));
            let coverage = response_watch_coverage(&kit.binding, poll_interval_seconds)
                .unwrap_or_else(|error| die(error));
            println!(
                "{}",
                response_watch_startup_notice(&kit, &coverage, &args.node_url, &signer)
            );
            println!(
                "  Polling every {poll_interval_seconds}s. That is {} looks inside the usable \
                 part of the window.{}\n",
                coverage.polls_inside_the_usable_window,
                if dry_run {
                    " DRY RUN: nothing will be submitted."
                } else {
                    ""
                }
            );
            let node = node_client();
            let mut watch = ResponseWatchV1::new(kit, network_fee_zhu, gas_max, dry_run)
                .unwrap_or_else(|error| die(error));
            let interval = std::time::Duration::from_secs(poll_interval_seconds);
            loop {
                match watch.poll_once(&node, &signer, now_unix()).await {
                    Ok(PollOutcomeV1::RecoveryRequired) => {
                        report(&PollOutcomeV1::RecoveryRequired);
                        // Not a retry loop. A stale kit does not get better
                        // by being tried again, and every further attempt is
                        // an attempt to install a split that favours the
                        // other party.
                        std::process::exit(1);
                    }
                    Ok(outcome) => report(&outcome),
                    // A node that is down, stale or unreachable is a reason
                    // to say so on every tick and keep looking, not a reason
                    // to stop: the window is still running, and this process
                    // going away is the failure it exists to prevent.
                    Err(error) => println!("  ERR  {error}"),
                }
                tokio::time::sleep(interval).await;
            }
        }
    }
}
