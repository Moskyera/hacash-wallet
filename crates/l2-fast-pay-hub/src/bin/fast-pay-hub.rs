use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use l2_fast_pay_hub::HubState;

#[derive(Parser, Debug)]
#[command(
    name = "fast-pay-hub",
    about = "Hacash CSP / Fast Pay hub (Wallet Hub API v4)"
)]
struct Args {
    /// Listen address (host:port)
    #[arg(long, default_value = "127.0.0.1:8790")]
    listen: SocketAddr,

    /// Fullnode API URL for channel queries
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    node_url: String,

    /// Optional API token required by the configured full node.
    #[arg(long, env = "HACASH_NODE_API_TOKEN")]
    node_api_token: Option<String>,

    /// On-chain address of this hub (either channel side)
    #[arg(long, env = "HACASH_HUB_ADDRESS")]
    hub_address: String,

    /// Hub private key hex (64 chars) for auto-signing channel bills
    #[arg(long, env = "HACASH_HUB_SECRET_HEX")]
    hub_secret_hex: Option<String>,

    /// Hub display name returned in /v1/health
    #[arg(long, default_value = "HPAY Fast Pay Hub")]
    name: String,

    /// Fast Pay is fee-free. This must remain 0.
    #[arg(long, default_value_t = 0)]
    hub_fee_mei: u64,

    /// Durable JSON state file. Required before settlement signing is enabled.
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// Independent 32-byte journal storage master key, hex encoded.
    #[arg(long, env = "HACASH_HUB_JOURNAL_KEY_HEX")]
    journal_key_hex: Option<String>,

    /// development, testnet, or mainnet-pilot.
    #[arg(
        long,
        env = "HACASH_HUB_DEPLOYMENT_PROFILE",
        default_value = "development"
    )]
    deployment_profile: String,

    /// Per-payment mainnet-pilot cap in Zhu. Hard maximum is 1 HAC.
    #[arg(
        long,
        env = "HACASH_HUB_MAINNET_MAX_PAYMENT_HAC_ZHU",
        default_value_t = 0
    )]
    mainnet_max_payment_hac_zhu: u64,

    /// Maximum channel funding the wallet may propose to this pilot, in Zhu.
    #[arg(
        long,
        env = "HACASH_HUB_MAINNET_MAX_CHANNEL_FUNDING_HAC_ZHU",
        default_value_t = 0
    )]
    mainnet_max_channel_funding_hac_zhu: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let hub = Arc::new(
        if args.deployment_profile == l2_fast_pay_hub::readiness::MAINNET_PILOT_PROFILE {
            let state_file = args
                .state_file
                .ok_or("mainnet-pilot requires --state-file")?;
            let journal_key = args
                .journal_key_hex
                .as_deref()
                .ok_or("mainnet-pilot requires --journal-key-hex")?;
            let hub_secret = args
                .hub_secret_hex
                .ok_or("mainnet-pilot requires --hub-secret-hex")?;
            HubState::new_secure_with_policy(
                args.name,
                args.hub_address,
                args.node_url.clone(),
                args.node_api_token.as_deref(),
                state_file,
                hub_secret,
                journal_key,
                args.deployment_profile,
                args.mainnet_max_payment_hac_zhu,
                args.mainnet_max_channel_funding_hac_zhu,
            )?
        } else {
            match (args.state_file, args.journal_key_hex.as_deref()) {
                (Some(state_file), Some(journal_key)) => HubState::new_secure(
                    args.name,
                    args.hub_address,
                    args.node_url.clone(),
                    state_file,
                    args.hub_fee_mei,
                    args.hub_secret_hex,
                    journal_key,
                )?,
                (None, Some(_)) => {
                    return Err("--state-file is required with --journal-key-hex".into());
                }
                (state_file, None) => HubState::new(
                    args.name,
                    args.hub_address,
                    args.node_url.clone(),
                    state_file,
                    args.hub_fee_mei,
                    args.hub_secret_hex,
                )?,
            }
        },
    );

    eprintln!(
        "Fast Pay hub: {}",
        hub.health().name.as_deref().unwrap_or("hub")
    );
    eprintln!(
        "Hub address:  {}",
        hub.health().hub_address.as_deref().unwrap_or("?")
    );
    eprintln!("Node API:     {}", args.node_url);
    eprintln!("Listen:       {}", args.listen);

    l2_fast_pay_hub::serve(args.listen, hub).await?;
    Ok(())
}
