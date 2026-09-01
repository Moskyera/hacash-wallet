use std::fs::OpenOptions;
use std::io::Write;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use dust_whisper::crypto::generate_relay_keypair;
use dust_whisper::messenger_relay::InboxAllowlist;
use dust_whisper::relay::{
    RelayAccess, SUBMIT_TOKEN_HEADER, SubmitAccess, parse_secret_hex, relay_state_from_secret,
    serve_with,
};

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

    /// Carry mail only for these Hacash addresses. Repeat the flag per address.
    ///
    /// This is the default shape of a relay: it serves the addresses its
    /// operator named and nobody else. Naming none, and not passing
    /// `--serve-everybody`, is a relay that serves nobody, which is what a
    /// relay started by mistake should do.
    #[arg(long = "allow", value_name = "ADDRESS")]
    allow: Vec<String>,

    /// Run a public relay: carry mail for whoever can reach the socket.
    ///
    /// The open relay this crate used to build by default, now something an
    /// operator says out loud. Everything in section 6 of
    /// docs/RUNNING-A-RELAY.md is yours to keep when you pass this, and anybody
    /// who can reach the port can fill the store and stop your own mail.
    #[arg(long = "serve-everybody", default_value_t = false)]
    serve_everybody: bool,

    /// Also accept transactions submitted from other machines.
    ///
    /// Off by default and separate from the address list on purpose: forwarding
    /// a transaction to your fullnode is a different thing from carrying
    /// somebody's mail, and nothing about wanting the second is a request for
    /// the first. With this off, a submitter has to be on this machine AND hold
    /// the submit token printed at startup, because a reverse proxy makes every
    /// caller in the world look like it is on this machine.
    ///
    /// This is the flag that makes a relay a public transaction submitter, and
    /// it is what a deliberately public relay is for. Read section 8 of
    /// docs/RUNNING-A-RELAY.md before passing it.
    #[arg(long = "submit-from-anywhere", default_value_t = false)]
    submit_from_anywhere: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    let secret = load_or_create_secret(&args)?;
    let state = relay_state_from_secret(secret, args.node_url.clone());

    let access = RelayAccess {
        inbox: if args.serve_everybody {
            InboxAllowlist::serving_everybody()
        } else {
            InboxAllowlist::from_addresses(&args.allow)
        },
        submit: if args.submit_from_anywhere {
            SubmitAccess::Everybody
        } else {
            SubmitAccess::ThisMachineOnly
        },
    };

    eprintln!("DUST Whisper relay pubkey: {}", state.public_key_b64);
    eprintln!("Forwarding to: {}", state.default_node_url);
    eprintln!("Listening on: {}", args.listen);
    if args.serve_everybody {
        eprintln!(
            "Mail: carried for ANYBODY who can reach this socket. Whoever reaches it can also fill it."
        );
    } else if access.inbox.is_empty() {
        eprintln!(
            "Mail: carried for NOBODY. No address was listed, so every send and every collection is refused. Pass --allow <address> for each person this relay is for."
        );
    } else {
        eprintln!(
            "Mail: carried only for the {} listed address(es). Everybody else is refused.",
            access.inbox.len()
        );
    }
    if args.submit_from_anywhere {
        eprintln!("Transactions: forwarded for ANY machine that can reach this socket.");
    } else {
        eprintln!(
            "Transactions: forwarded only for a submitter on this machine that presents the token below."
        );
        eprintln!(
            "  Submit token ({SUBMIT_TOKEN_HEADER}): {}",
            state.submit_token
        );
        eprintln!(
            "  Loopback alone is not the credential. Behind a reverse proxy every caller arrives as 127.0.0.1, so the token is what a proxy cannot launder. Anything that can read the key file can derive it."
        );
    }

    serve_with(args.listen, state, access).await?;
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
