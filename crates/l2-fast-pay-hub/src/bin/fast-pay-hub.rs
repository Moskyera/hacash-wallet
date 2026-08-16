use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use l2_fast_pay_hub::{HubSigner, HubState};
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[command(
    name = "fast-pay-hub",
    about = "Hacash CSP / Fast Pay hub (Wallet Hub API v7)"
)]
struct Args {
    /// Listen address (host:port)
    #[arg(long, default_value = "127.0.0.1:8790")]
    listen: SocketAddr,

    /// Exact reverse-proxy socket IP allowed to supply an overwritten X-Real-IP header.
    #[arg(long, env = "HACASH_HUB_TRUSTED_PROXY_IP")]
    trusted_proxy_ip: Option<IpAddr>,

    /// Fullnode API URL for channel queries
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    node_url: String,

    /// Optional API token required by the configured full node.
    #[arg(long, env = "HACASH_NODE_API_TOKEN")]
    node_api_token: Option<String>,

    /// On-chain address of this hub (either channel side)
    #[arg(long, env = "HACASH_HUB_ADDRESS")]
    hub_address: Option<String>,

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

    /// Independent 32-byte key for AEAD-sealed Hub state, hex encoded.
    #[arg(long, env = "HACASH_HUB_STATE_KEY_HEX")]
    state_encryption_key_hex: Option<String>,

    /// Offline one-time authenticated migration of an existing plaintext state file.
    #[arg(long)]
    migrate_plaintext_state: bool,

    /// Windows-only DPAPI identity file. Replaces plaintext Hub identity inputs.
    #[arg(long)]
    identity_dpapi_file: Option<PathBuf>,

    /// Create a new user-bound DPAPI identity at --identity-dpapi-file, print
    /// only its public Hub address, and exit. Existing files are never replaced.
    #[arg(long, default_value_t = false)]
    create_dpapi_identity: bool,

    /// Offline Windows-only migration from one legacy DPAPI v2 blob to split
    /// DPAPI v3 components. The original v2 file is retained as a backup.
    #[arg(long, default_value_t = false)]
    migrate_dpapi_identity_v3: bool,

    /// development, testnet, mainnet-pilot, or mainnet-bounded-pilot.
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

    /// Comma-separated Hacash user addresses admitted to the initial mainnet pilot.
    #[arg(long, env = "HACASH_HUB_MAINNET_ALLOWED_USERS", value_delimiter = ',')]
    mainnet_allowed_users: Vec<String>,

    /// Aggregate active and reserved channel TVL cap in Zhu. Hard maximum is 100 HAC.
    #[arg(
        long,
        env = "HACASH_HUB_MAINNET_MAX_AGGREGATE_TVL_HAC_ZHU",
        default_value_t = 100_000_000
    )]
    mainnet_max_aggregate_tvl_hac_zhu: u64,

    /// Enable automatic maintenance of all 18 HVM storage leases.
    #[arg(long, default_value_t = false)]
    hvm_lease_scheduler: bool,

    /// Seconds between HVM lease maintenance checks. Minimum 60.
    #[arg(long, default_value_t = 300)]
    hvm_lease_interval_seconds: u64,

    /// Renew when the shortest HVM lease has at most this many live blocks.
    #[arg(long, default_value_t = 10_000)]
    hvm_lease_threshold_blocks: u64,

    /// Lease periods added atomically to every one of the 18 storage keys.
    #[arg(long, default_value_t = 100)]
    hvm_lease_periods: u64,

    /// Exact Type 3 network fee in Zhu for one renew-all transaction.
    #[arg(long, default_value_t = 0)]
    hvm_lease_network_fee_zhu: u64,

    /// Type 3 gas limit byte for HVM renew-all calls.
    #[arg(long, default_value_t = 255)]
    hvm_lease_gas_max: u8,

    /// External monotonic rollback anchor: the witness base URL.
    ///
    /// The anchor is a counter that lives outside this Hub's state, beyond the
    /// reach of whoever can restore that state, and only ever goes up. Set it
    /// and every Hub signature first reserves its exact ledger position with
    /// the witness; an unreachable witness then refuses rather than signs.
    ///
    /// All five anchor settings are required together. A partial configuration
    /// is a startup failure, never a Hub that quietly runs without an anchor.
    #[arg(long, env = "HACASH_HUB_ROLLBACK_WITNESS_URL")]
    rollback_witness_url: Option<String>,

    /// Pinned witness identity.
    #[arg(long, env = "HACASH_HUB_ROLLBACK_WITNESS_ID")]
    rollback_witness_id: Option<String>,

    /// Pinned witness receipt key generation.
    #[arg(long, env = "HACASH_HUB_ROLLBACK_WITNESS_EPOCH", default_value_t = 1)]
    rollback_witness_epoch: u64,

    /// Pinned online witness receipt address. Verifies receipts and refusals.
    #[arg(long, env = "HACASH_HUB_ROLLBACK_WITNESS_RECEIPT_ADDRESS")]
    rollback_witness_receipt_address: Option<String>,

    /// Pinned offline witness authorisation address. Verifies the deployment
    /// attestation, and nothing that signs unattended.
    #[arg(long, env = "HACASH_HUB_ROLLBACK_WITNESS_AUTHORISATION_ADDRESS")]
    rollback_witness_authorisation_address: Option<String>,

    /// The signed `WitnessDeploymentAttestationV1`, as produced by
    /// `hpay-rollback-witness attest`.
    #[arg(long, env = "HACASH_HUB_ROLLBACK_WITNESS_ATTESTATION_FILE")]
    rollback_witness_attestation_file: Option<PathBuf>,

    /// Witness request timeout. There is no "proceed on timeout".
    #[arg(long, default_value_t = 5)]
    rollback_witness_timeout_seconds: u64,
}

/// Assemble the anchor configuration, or say plainly that there is none.
///
/// Absent configuration reads as *no witness*, which reads as
/// `external_rollback_anchor_ready = false`. It never reads as "anchor not
/// required". Partial configuration is refused outright: a Hub that was meant
/// to have an anchor and silently does not is the worst outcome available.
fn rollback_anchor_config(
    args: &Args,
) -> Result<
    Option<l2_fast_pay_hub::rollback_anchor::RollbackAnchorConfig>,
    Box<dyn std::error::Error>,
> {
    let supplied = [
        args.rollback_witness_url.is_some(),
        args.rollback_witness_id.is_some(),
        args.rollback_witness_receipt_address.is_some(),
        args.rollback_witness_authorisation_address.is_some(),
        args.rollback_witness_attestation_file.is_some(),
    ];
    if supplied.iter().all(|present| !present) {
        return Ok(None);
    }
    if !supplied.iter().all(|present| *present) {
        return Err(
            "the external rollback anchor needs --rollback-witness-url, --rollback-witness-id, \
             --rollback-witness-receipt-address, --rollback-witness-authorisation-address and \
             --rollback-witness-attestation-file together. A partial anchor configuration is \
             refused rather than run without an anchor"
                .into(),
        );
    }
    let attestation_path = args
        .rollback_witness_attestation_file
        .as_ref()
        .expect("checked above");
    let attestation = serde_json::from_slice(&std::fs::read(attestation_path)?)?;
    Ok(Some(
        l2_fast_pay_hub::rollback_anchor::RollbackAnchorConfig {
            witness_url: args.rollback_witness_url.clone().expect("checked above"),
            witness_id: args.rollback_witness_id.clone().expect("checked above"),
            witness_epoch: args.rollback_witness_epoch,
            witness_receipt_address: args
                .rollback_witness_receipt_address
                .clone()
                .expect("checked above"),
            witness_authorisation_address: args
                .rollback_witness_authorisation_address
                .clone()
                .expect("checked above"),
            attestation,
            request_timeout: std::time::Duration::from_secs(
                args.rollback_witness_timeout_seconds.max(1),
            ),
        },
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Read before anything consumes `args`, and before any key material is
    // touched: a partial anchor configuration must fail the process here.
    let anchor_config = rollback_anchor_config(&args)?;

    if args.create_dpapi_identity && args.migrate_dpapi_identity_v3 {
        return Err(
            "--create-dpapi-identity and --migrate-dpapi-identity-v3 are mutually exclusive".into(),
        );
    }

    if args.migrate_dpapi_identity_v3 {
        let identity_path = args
            .identity_dpapi_file
            .as_deref()
            .ok_or("--migrate-dpapi-identity-v3 requires --identity-dpapi-file")?;
        if args.hub_address.is_some()
            || args.hub_secret_hex.is_some()
            || args.journal_key_hex.is_some()
            || args.state_encryption_key_hex.is_some()
        {
            return Err(
                "--migrate-dpapi-identity-v3 cannot be combined with identity secrets".into(),
            );
        }
        #[cfg(windows)]
        {
            let directory =
                l2_fast_pay_hub::windows_identity::migrate_dpapi_hub_identity_to_v3(identity_path)?;
            eprintln!(
                "DPAPI identity migrated to split v3 storage: {}",
                directory.display()
            );
            eprintln!("The original v2 DPAPI file was retained unchanged as a backup.");
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            let _ = identity_path;
            return Err("--migrate-dpapi-identity-v3 is available only on Windows".into());
        }
    }

    if args.create_dpapi_identity {
        let identity_path = args
            .identity_dpapi_file
            .as_deref()
            .ok_or("--create-dpapi-identity requires --identity-dpapi-file")?;
        if args.hub_address.is_some()
            || args.hub_secret_hex.is_some()
            || args.journal_key_hex.is_some()
            || args.state_encryption_key_hex.is_some()
        {
            return Err("--create-dpapi-identity cannot be combined with identity secrets".into());
        }
        #[cfg(windows)]
        {
            let address =
                l2_fast_pay_hub::windows_identity::create_dpapi_hub_identity(identity_path)?;
            eprintln!("DPAPI Hub identity created. Public Hub address: {address}");
            return Ok(());
        }
        #[cfg(not(windows))]
        {
            let _ = identity_path;
            return Err("--create-dpapi-identity is available only on Windows".into());
        }
    }

    let (hub_address, hub_secret_hex, journal_key_hex, state_key_hex) = if let Some(identity_path) =
        args.identity_dpapi_file.as_deref()
    {
        if args.hub_address.is_some()
            || args.hub_secret_hex.is_some()
            || args.journal_key_hex.is_some()
            || args.state_encryption_key_hex.is_some()
        {
            return Err(
                    "--identity-dpapi-file cannot be combined with Hub identity arguments or environment variables"
                        .into(),
                );
        }
        #[cfg(windows)]
        {
            l2_fast_pay_hub::windows_identity::load_dpapi_hub_identity(identity_path)?.into_parts()
        }
        #[cfg(not(windows))]
        {
            let _ = identity_path;
            return Err("--identity-dpapi-file is available only on Windows".into());
        }
    } else {
        (
            args.hub_address.ok_or("--hub-address is required")?,
            args.hub_secret_hex.map(Zeroizing::new).unwrap_or_default(),
            args.journal_key_hex.map(Zeroizing::new).unwrap_or_default(),
            args.state_encryption_key_hex
                .map(Zeroizing::new)
                .unwrap_or_default(),
        )
    };

    if args.migrate_plaintext_state {
        let state_file = args
            .state_file
            .as_deref()
            .ok_or("--migrate-plaintext-state requires --state-file")?;
        let journal_key = (!journal_key_hex.is_empty())
            .then_some(journal_key_hex.as_str())
            .ok_or("--migrate-plaintext-state requires --journal-key-hex")?;
        let state_key = (!state_key_hex.is_empty())
            .then_some(state_key_hex.as_str())
            .ok_or("--migrate-plaintext-state requires --state-encryption-key-hex")?;
        if !hub_secret_hex.is_empty()
            && (hub_secret_hex.eq_ignore_ascii_case(journal_key)
                || hub_secret_hex.eq_ignore_ascii_case(state_key))
        {
            return Err("Hub signer, journal and state keys must all be independent".into());
        }
        let backup = l2_fast_pay_hub::migrate_plaintext_state_to_sealed(
            state_file,
            &hub_address,
            journal_key,
            state_key,
        )?;
        eprintln!(
            "Hub state migration verified. Original plaintext backup: {}",
            backup.display()
        );
        return Ok(());
    }
    let mut hub_signer = (!hub_secret_hex.is_empty())
        .then(|| HubSigner::from_secret_hex(hub_secret_hex.as_str()))
        .transpose()?;
    let hub_state = {
        if l2_fast_pay_hub::readiness::is_mainnet_pilot_profile(&args.deployment_profile) {
            let state_file = args
                .state_file
                .ok_or("a mainnet profile requires --state-file")?;
            let journal_key = (!journal_key_hex.is_empty())
                .then_some(journal_key_hex.as_str())
                .ok_or("a mainnet profile requires --journal-key-hex")?;
            let hub_signer = hub_signer
                .take()
                .ok_or("a mainnet profile requires --hub-secret-hex")?;
            let state_key = (!state_key_hex.is_empty())
                .then_some(state_key_hex.as_str())
                .ok_or("a mainnet profile requires --state-encryption-key-hex")?;
            let admission = l2_fast_pay_hub::readiness::MainnetPilotAdmissionPolicy::try_new(
                &args.mainnet_allowed_users,
                args.mainnet_max_aggregate_tvl_hac_zhu,
            )?;
            if !admission.is_configured() {
                return Err(
                    "a mainnet profile requires --mainnet-allowed-users with at least one Hacash address"
                        .into(),
                );
            }
            HubState::new_secure_with_mainnet_admission_signer(
                args.name,
                hub_address.clone(),
                args.node_url.clone(),
                args.node_api_token.as_deref(),
                state_file,
                hub_signer,
                journal_key,
                state_key,
                args.deployment_profile,
                args.mainnet_max_payment_hac_zhu,
                args.mainnet_max_channel_funding_hac_zhu,
                admission,
            )?
        } else {
            let journal_key = (!journal_key_hex.is_empty()).then_some(journal_key_hex.as_str());
            let state_key = (!state_key_hex.is_empty()).then_some(state_key_hex.as_str());
            match (args.state_file, journal_key, state_key) {
                (Some(state_file), Some(journal_key), Some(state_key)) => {
                    let signer = hub_signer
                        .take()
                        .ok_or("authenticated Hub storage requires --hub-secret-hex")?;
                    HubState::new_secure_with_signer_policy(
                        args.name,
                        hub_address.clone(),
                        args.node_url.clone(),
                        args.node_api_token.as_deref(),
                        state_file,
                        signer,
                        journal_key,
                        state_key,
                        args.deployment_profile,
                        args.mainnet_max_payment_hac_zhu,
                        args.mainnet_max_channel_funding_hac_zhu,
                    )?
                }
                (Some(state_file), Some(journal_key), None) => HubState::new_secure_with_signer(
                    args.name,
                    hub_address.clone(),
                    args.node_url.clone(),
                    state_file,
                    args.hub_fee_mei,
                    hub_signer.take(),
                    journal_key,
                )?,
                (Some(_), None, Some(_)) => {
                    return Err(
                        "--journal-key-hex is required with --state-encryption-key-hex".into(),
                    );
                }
                (None, Some(_), _) | (None, _, Some(_)) => {
                    return Err("--state-file is required with Hub storage keys".into());
                }
                (state_file, None, None) => HubState::new_with_signer(
                    args.name,
                    hub_address.clone(),
                    args.node_url.clone(),
                    state_file,
                    args.hub_fee_mei,
                    hub_signer.take(),
                )?,
            }
        }
    };
    let anchored = anchor_config.is_some();
    let hub_state = match anchor_config {
        Some(config) => hub_state.with_rollback_anchor(config)?,
        None => hub_state,
    };
    let hub = Arc::new(hub_state);
    if anchored {
        // The anti-rollback check proper, before the money path serves
        // anything. A Hub that cannot agree with its witness on every channel
        // it holds does not start.
        hub.run_rollback_anchor_startup_probe().await?;
        eprintln!("Rollback anchor: witness agreed on every channel this Hub holds");
    } else {
        eprintln!(
            "Rollback anchor: NONE configured. external_rollback_anchor_ready will read false \
             and full mainnet stays blocked"
        );
    }

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

    if args.hvm_lease_scheduler {
        let config = l2_fast_pay_hub::hvm_scheduler::HvmLeaseSchedulerConfig {
            interval_seconds: args.hvm_lease_interval_seconds,
            renew_when_live_blocks_at_or_below: args.hvm_lease_threshold_blocks,
            periods: args.hvm_lease_periods,
            network_fee_zhu: args.hvm_lease_network_fee_zhu,
            gas_max: args.hvm_lease_gas_max,
        };
        config.validate()?;
        if !hub.health().settlement_ready {
            return Err("HVM lease scheduler requires authenticated durable Hub storage".into());
        }
        eprintln!(
            "HVM leases:    automatic, {}s interval, {}-block threshold",
            config.interval_seconds, config.renew_when_live_blocks_at_or_below
        );
        tokio::spawn(l2_fast_pay_hub::hvm_scheduler::run_hvm_lease_scheduler(
            hub.clone(),
            config,
        ));
    }

    l2_fast_pay_hub::server::serve_with_trusted_proxy(args.listen, hub, args.trusted_proxy_ip)
        .await?;
    Ok(())
}
