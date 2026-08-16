//! The external monotonic rollback anchor witness.
//!
//! A small server holding one durable, append-only counter per Hub identity
//! and one high-water serial per channel. It records a commitment before the
//! Hub uses its signing key and returns a signed receipt; it refuses, in
//! writing and under signature, a position it has already passed.
//!
//! This binary is the anchor. Run it somewhere the Hub's backups and restores
//! cannot reach - that separation is the whole guarantee, and no check in the
//! protocol can prove it for you. See
//! `docs/l2/ADR-001-EXTERNAL-ROLLBACK-ANCHOR.md`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use l2_fast_pay_hub::rollback_anchor::WitnessPosture;
use l2_fast_pay_hub::rollback_anchor::witness::{WitnessService, WitnessServiceConfig, router};
use sys::Account;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "hpay-rollback-witness",
    about = "External monotonic rollback anchor witness for the HPAY Fast Pay Hub"
)]
struct Args {
    /// Pinned witness identity. The Hub refuses any other.
    #[arg(long, env = "HPAY_WITNESS_ID")]
    witness_id: String,

    /// Receipt key generation. Bumped only when the online key is rotated.
    #[arg(long, env = "HPAY_WITNESS_EPOCH", default_value_t = 1)]
    witness_epoch: u64,

    /// The durable append-only counter store.
    #[arg(long, env = "HPAY_WITNESS_STORE")]
    store: PathBuf,

    /// Online receipt key, hex. Signs receipts, refusals and status probes.
    #[arg(long, env = "HPAY_WITNESS_RECEIPT_SECRET_HEX")]
    receipt_secret_hex: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Serve the witness.
    Serve {
        #[arg(long, default_value = "127.0.0.1:8791")]
        listen: SocketAddr,
    },
    /// Print the durable store identity. This is what the Hub pins on first
    /// contact; a change means the store was re-created.
    Instance,
    /// Issue a deployment attestation for one Hub, signed by the **offline**
    /// authorisation key. Run this off the serving host.
    Attest {
        #[arg(long)]
        hub_identity: String,
        /// Offline authorisation key, hex. Never the receipt key.
        #[arg(long, env = "HPAY_WITNESS_AUTHORISATION_SECRET_HEX")]
        authorisation_secret_hex: String,
        /// counterparty, neutral-third-party, or same-operator-separate-infrastructure.
        #[arg(long)]
        posture: String,
        #[arg(long)]
        witness_operator: String,
        /// What separates this witness's failure domain from the Hub's:
        /// backup sets, hosting, key custody. Free text, and it is read by a
        /// human during an incident.
        #[arg(long)]
        separation_statement: String,
        /// Weeks, not years. Long enough not to be a nuisance, short enough
        /// that nobody sets it and forgets.
        #[arg(long, default_value_t = 30)]
        validity_days: u64,
    },
}

fn account(secret_hex: &str, label: &str) -> Account {
    let secret = Zeroizing::new(secret_hex.trim().to_owned());
    Account::create_by(secret.as_str()).unwrap_or_else(|error| {
        eprintln!("invalid {label} key: {error}");
        std::process::exit(2);
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let args = Args::parse();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default();
    let service = WitnessService::open(
        WitnessServiceConfig {
            witness_id: args.witness_id.clone(),
            witness_epoch: args.witness_epoch,
            store_path: args.store.clone(),
            receipt_account: account(&args.receipt_secret_hex, "witness receipt"),
        },
        now,
    )
    .unwrap_or_else(|error| {
        eprintln!("witness store refused to open: {error}");
        std::process::exit(2);
    });

    match args.command {
        Command::Instance => {
            println!("witness_id={}", service.witness_id());
            println!("witness_epoch={}", service.witness_epoch());
            println!("witness_receipt_address={}", service.receipt_address());
            match service.instance_id() {
                Ok(instance) => println!("witness_instance_id={instance}"),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(2);
                }
            }
        }
        Command::Attest {
            hub_identity,
            authorisation_secret_hex,
            posture,
            witness_operator,
            separation_statement,
            validity_days,
        } => {
            let posture = match posture.as_str() {
                "counterparty" => WitnessPosture::Counterparty,
                "neutral-third-party" => WitnessPosture::NeutralThirdParty,
                "same-operator-separate-infrastructure" => {
                    WitnessPosture::SameOperatorSeparateInfrastructure
                }
                _ => {
                    eprintln!(
                        "posture must be counterparty, neutral-third-party, or \
                         same-operator-separate-infrastructure. There is deliberately no \
                         same-host posture: a configuration that wants it cannot express it"
                    );
                    std::process::exit(2);
                }
            };
            let authorisation = account(&authorisation_secret_hex, "witness authorisation");
            if authorisation.readable() == service.receipt_address() {
                eprintln!(
                    "the offline authorisation key must not be the online receipt key: \
                     collapsing them makes the recovery authorisation decorative"
                );
                std::process::exit(2);
            }
            let attestation = service
                .issue_attestation(
                    &authorisation,
                    &hub_identity,
                    posture,
                    &witness_operator,
                    &separation_statement,
                    now,
                    validity_days.saturating_mul(86_400),
                )
                .unwrap_or_else(|error| {
                    eprintln!("attestation could not be issued: {error}");
                    std::process::exit(2);
                });
            println!(
                "{}",
                serde_json::to_string_pretty(&attestation).unwrap_or_default()
            );
            eprintln!("witness_authorisation_address={}", authorisation.readable());
        }
        Command::Serve { listen } => {
            let service = Arc::new(service);
            let instance = service.instance_id().unwrap_or_default();
            tracing::info!(
                witness_id = %service.witness_id(),
                witness_epoch = service.witness_epoch(),
                witness_instance_id = %instance,
                store = %args.store.display(),
                "rollback anchor witness serving"
            );
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .unwrap_or_else(|error| {
                    eprintln!("cannot bind {listen}: {error}");
                    std::process::exit(2);
                });
            if let Err(error) = axum::serve(listener, router(service)).await {
                eprintln!("witness stopped: {error}");
                std::process::exit(1);
            }
        }
    }
}
