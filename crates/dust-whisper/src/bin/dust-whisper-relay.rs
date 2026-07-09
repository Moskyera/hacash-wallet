use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use dust_whisper::crypto::generate_relay_keypair;
use dust_whisper::relay::{parse_secret_hex, relay_state_from_secret, serve};

#[derive(Parser, Debug)]
#[command(name = "dust-whisper-relay", about = "DUST Whisper relay server")]
struct Args {
    /// Listen address (host:port)
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: SocketAddr,

    /// Default fullnode API URL to forward decrypted transactions
    #[arg(long, default_value = "https://nodeapi.hacash.org")]
    node_url: String,

    /// Relay X25519 secret key (64 hex chars). Generated on first run if omitted.
    #[arg(long, env = "DUST_WHISPER_SECRET_HEX")]
    secret_hex: Option<String>,

    /// Path to persist generated relay secret key
    #[arg(long, default_value = "relay.key")]
    key_file: PathBuf,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let secret = load_or_create_secret(&args)?;
    let state = relay_state_from_secret(secret, args.node_url.clone());

    eprintln!("DUST Whisper relay pubkey: {}", state.public_key_b64);
    eprintln!("Forwarding to: {}", state.default_node_url);
    eprintln!("Listening on: {}", args.listen);

    serve(args.listen, state).await?;
    Ok(())
}

fn load_or_create_secret(args: &Args) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    if let Some(hex_str) = &args.secret_hex {
        return Ok(parse_secret_hex(hex_str)?);
    }
    if args.key_file.exists() {
        let raw = std::fs::read_to_string(&args.key_file)?;
        return Ok(parse_secret_hex(raw.trim())?);
    }
    let (sk, _pk) = generate_relay_keypair();
    let hex_str = hex::encode(sk);
    write_secret_key(&args.key_file, &hex_str)?;
    eprintln!("Generated new relay key at {}", args.key_file.display());
    Ok(sk)
}

fn write_secret_key(path: &PathBuf, hex_str: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut opts = OpenOptions::new();
    opts.create(true).write(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts.open(path)?;
    writeln!(file, "{hex_str}")?;
    Ok(())
}