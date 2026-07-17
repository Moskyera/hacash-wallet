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

    /// On-chain address of this hub (either channel side)
    #[arg(long, env = "HACASH_HUB_ADDRESS")]
    hub_address: String,

    /// Hub private key hex (64 chars) for auto-signing channel bills
    #[arg(long, env = "HACASH_HUB_SECRET_HEX")]
    hub_secret_hex: Option<String>,

    /// Hub display name returned in /v1/health
    #[arg(long, default_value = "Moskyera dev CSP")]
    name: String,

    /// Fast Pay is fee-free. This must remain 0.
    #[arg(long, default_value_t = 0.0)]
    hub_fee_mei: f64,

    /// Optional JSON file to persist channel ledgers and payment receipts
    #[arg(long)]
    state_file: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let hub = Arc::new(HubState::new(
        args.name,
        args.hub_address,
        args.node_url.clone(),
        args.state_file,
        args.hub_fee_mei,
        args.hub_secret_hex,
    )?);

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
