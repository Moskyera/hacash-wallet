use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use l2_fast_pay_hub::hvm_pilot::{
    HvmLocalPilotNetwork, HvmPilotTransactionPhase, validate_hvm_pilot_node_url,
};
use l2_fast_pay_hub::hvm_registry_pilot::{
    HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU, HvmRegistryPilotChannelParameters,
    build_hvm_registry_pilot_payment_request, preview_hvm_registry_pilot_deployment,
    preview_hvm_registry_pilot_funding, preview_hvm_registry_pilot_initialization,
    preview_hvm_registry_pilot_prefund,
};
use l2_fast_pay_hub::hvm_registry_pilot_state::{
    HvmRegistryLifecycleReview, HvmRegistryLifecycleStage, HvmRegistryObservationOutcome,
    HvmRegistryPilotStateStore, HvmRegistryPrepareProvenance,
};
use l2_fast_pay_hub::hvm_registry_watchtower::{
    HVM_REGISTRY_LEASE_REQUEST_SCHEMA, HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA,
    HvmRegistryLeaseRenewalRequestV2, HvmRegistryWatchtowerModeV2, HvmRegistryWatchtowerRequestV2,
};
use l2_fast_pay_hub::node::NodeClient;
use l2_fast_pay_hub::{HubError, HubSigner, HubState};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sys::Account;

#[derive(Parser, Debug)]
#[command(
    name = "hpay-hvm-registry-local-pilot",
    about = "Fail-closed shared HVM registry lifecycle tool for private chain 7 only"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8197")]
    node_url: String,
    #[arg(long)]
    left_identity_dpapi_file: PathBuf,
    #[arg(long)]
    hub_identity_dpapi_file: PathBuf,
    #[arg(long)]
    state_file: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum WatchAction {
    BeginChallenge,
    InjectStaleChallenge,
    Monitor,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum LifecycleStage {
    HubPrefunding,
    Deployment,
    Initialization,
    Funding,
}

impl LifecycleStage {
    fn durable(self) -> HvmRegistryLifecycleStage {
        match self {
            Self::HubPrefunding => HvmRegistryLifecycleStage::HubPrefunding,
            Self::Deployment => HvmRegistryLifecycleStage::Deployment,
            Self::Initialization => HvmRegistryLifecycleStage::Initialization,
            Self::Funding => HvmRegistryLifecycleStage::Funding,
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    Status,
    Inspect,
    /// Reconcile one already-durable lifecycle transaction by observation
    /// only. This command never loads a signer and never submits/resubmits.
    ReconcileLifecycle {
        #[arg(long, value_enum)]
        stage: LifecycleStage,
        #[arg(long, default_value_t = 6)]
        confirmations: u64,
        #[arg(long, default_value_t = 0)]
        wait_seconds: u64,
    },
    /// Shows the deterministic contract address and exact costs without
    /// constructing a transaction, signing, submitting or changing the journal.
    PreviewDeploy {
        #[arg(long)]
        hub_address: String,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
    },
    /// Shows the exact channel, contract call, fee and gas commitment without
    /// opening a node, DPAPI identity or durable journal.
    PreviewInitialize {
        #[arg(long)]
        left_address: String,
        #[arg(long)]
        hub_address: String,
        #[arg(long)]
        contract_address: String,
        /// Optional exact channel id. A fresh random id is printed when omitted.
        #[arg(long)]
        channel_id: Option<String>,
        #[arg(long)]
        left_deposit_zhu: u64,
        #[arg(long, default_value_t = 12)]
        challenge_blocks: u64,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
    },
    /// Shows the exact left-only channel funding transfer without opening a
    /// node, DPAPI identity or durable journal.
    PreviewFund {
        #[arg(long)]
        left_address: String,
        #[arg(long)]
        hub_address: String,
        #[arg(long)]
        contract_address: String,
        #[arg(long)]
        left_deposit_zhu: u64,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
    },
    /// Shows the exact 2000 HAC source-to-Hub transfer, fee, gas and short
    /// signing-validity window without opening a signer, node or journal.
    /// The figure is `HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU`, 200_000_000_000
    /// Zhu. It is ten times the V1 channel cost, which is the 200 HAC quoted
    /// in the canary runbook; do not confuse the two.
    PreviewPrefund {
        #[arg(long)]
        left_address: String,
        #[arg(long)]
        hub_address: String,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long)]
        timestamp: u64,
        #[arg(long)]
        valid_until_unix: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
    },
    /// Durably transfers exactly the 2000 HAC deployment protocol cost
    /// (`HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU`, 200_000_000_000 Zhu) from
    /// the isolated pilot-left identity to the exact DPAPI Hub identity.
    PrefundHub {
        /// Exact unsigned commitment printed by PreviewPrefund.
        #[arg(long)]
        expected_preview_commitment: Option<String>,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long)]
        timestamp: Option<u64>,
        #[arg(long)]
        valid_until_unix: Option<u64>,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 6)]
        confirmations: u64,
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
        #[arg(long, requires = "exact_resubmit_commitment")]
        exact_resubmit_tx_hash: Option<String>,
        #[arg(long, requires = "exact_resubmit_tx_hash")]
        exact_resubmit_commitment: Option<String>,
    },
    Deploy {
        /// Exact unsigned commitment printed by PreviewDeploy.
        #[arg(long)]
        expected_preview_commitment: String,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 6)]
        confirmations: u64,
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
        #[arg(long, requires = "exact_resubmit_commitment")]
        exact_resubmit_tx_hash: Option<String>,
        #[arg(long, requires = "exact_resubmit_tx_hash")]
        exact_resubmit_commitment: Option<String>,
    },
    Initialize {
        /// The Hub that must countersign the serial-1 full refund before any
        /// `init` bytes leave this process. There is no local fallback: this
        /// tool cannot produce a Hub refund signature by itself.
        #[arg(long)]
        hub_url: String,
        /// Exact unsigned commitment printed by PreviewInitialize.
        #[arg(long)]
        expected_preview_commitment: String,
        /// Exact channel id printed by PreviewInitialize.
        #[arg(long)]
        channel_id: String,
        #[arg(long)]
        left_deposit_zhu: u64,
        #[arg(long, default_value_t = 12)]
        challenge_blocks: u64,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 6)]
        confirmations: u64,
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
        #[arg(long, requires = "exact_resubmit_commitment")]
        exact_resubmit_tx_hash: Option<String>,
        #[arg(long, requires = "exact_resubmit_tx_hash")]
        exact_resubmit_commitment: Option<String>,
    },
    Fund {
        /// Exact unsigned commitment printed by PreviewFund.
        #[arg(long)]
        expected_preview_commitment: String,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 6)]
        confirmations: u64,
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
        #[arg(long, requires = "exact_resubmit_commitment")]
        exact_resubmit_tx_hash: Option<String>,
        #[arg(long, requires = "exact_resubmit_tx_hash")]
        exact_resubmit_commitment: Option<String>,
    },
    Activate {
        #[arg(long)]
        hub_state_file: PathBuf,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 100)]
        lease_periods: u64,
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
    },
    Pay {
        #[arg(long)]
        hub_state_file: PathBuf,
        #[arg(long)]
        payment_label: String,
        #[arg(long, default_value = "hpay-registry-local-pilot-service")]
        recipient: String,
        #[arg(long)]
        amount_zhu: u64,
        #[arg(long, default_value_t = 300)]
        expires_seconds: u64,
    },
    Watch {
        #[arg(long)]
        hub_state_file: PathBuf,
        #[arg(long, value_enum)]
        action: WatchAction,
        #[arg(long)]
        operation_label: String,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
    },
    Reconcile {
        #[arg(long)]
        hub_state_file: PathBuf,
        #[arg(long)]
        operation_id: String,
        #[arg(long, default_value_t = false)]
        allow_exact_resubmit: bool,
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
    },
    /// Retire a Recovery Required operation whose signed transaction provably
    /// cannot have executed, so a correct replacement can be signed.
    ///
    /// This takes no flag that would let it skip its proof, because there is
    /// no such flag. The Hub refuses unless a consensus rule that block
    /// verification itself applies shows the exact stored bytes can be in no
    /// valid block, and unless one last read of the chain finds them absent.
    /// If either fails, nothing changes and the reason is printed.
    AbandonInadmissible {
        #[arg(long)]
        hub_state_file: PathBuf,
        #[arg(long)]
        operation_id: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    validate_hvm_pilot_node_url(&args.node_url)?;
    let network = HvmLocalPilotNetwork::canonical();
    match &args.command {
        Command::PreviewDeploy {
            hub_address,
            network_fee_zhu,
            gas_max,
        } => {
            let preview = preview_hvm_registry_pilot_deployment(
                hub_address,
                &network,
                *network_fee_zhu,
                *gas_max,
            )?;
            println!("HPAY HVM CANONICAL DEPLOYMENT PREVIEW");
            println!("Network: private Local Pilot chain 7 (never mainnet)");
            println!("Deployer: {hub_address}");
            println!("Settlement profile: {}", preview.settlement_profile);
            println!("Contract: {}", preview.contract_address);
            println!("Protocol cost (Zhu): {}", preview.protocol_cost_zhu);
            println!("Requested network fee (Zhu): {}", preview.network_fee_zhu);
            println!("Requested total debit (Zhu): {}", preview.total_debit_zhu);
            println!("Requested gas max: {}", preview.gas_max);
            println!("Source SHA-256: {}", preview.source_sha256);
            println!("Bytecode SHA3: {}", preview.bytecode_sha3);
            println!("Action kinds: ChainAllow(1041), ContractDeploy(40)");
            println!("Constructor argv: {}", preview.constructor_argv_hex);
            println!("Unsigned commitment: {}", preview.unsigned_commitment);
        }
        Command::PreviewInitialize {
            left_address,
            hub_address,
            contract_address,
            channel_id,
            left_deposit_zhu,
            challenge_blocks,
            network_fee_zhu,
            gas_max,
        } => {
            let parameters = HvmRegistryPilotChannelParameters {
                channel_id: channel_id.clone().unwrap_or_else(random_channel_id),
                reuse_version: 0,
                left_deposit_zhu: *left_deposit_zhu,
                right_hub_deposit_zhu: 0,
                challenge_blocks: *challenge_blocks,
            };
            let preview = preview_hvm_registry_pilot_initialization(
                left_address,
                hub_address,
                contract_address,
                &network,
                &parameters,
                *network_fee_zhu,
                *gas_max,
            )?;
            println!("HPAY HVM CANONICAL INITIALIZATION PREVIEW");
            println!("Network: private Local Pilot chain 7 (never mainnet)");
            println!("Left: {}", preview.left_address);
            println!("Hub: {}", preview.hub_address);
            println!("Contract: {}", preview.contract_address);
            println!("Channel id: {}", preview.parameters.channel_id);
            println!("Reuse version: {}", preview.parameters.reuse_version);
            println!(
                "Left deposit (Zhu): {}",
                preview.parameters.left_deposit_zhu
            );
            println!(
                "Hub deposit (Zhu): {}",
                preview.parameters.right_hub_deposit_zhu
            );
            println!("Challenge blocks: {}", preview.parameters.challenge_blocks);
            println!("Requested network fee (Zhu): {}", preview.network_fee_zhu);
            println!("Requested gas max: {}", preview.gas_max);
            println!("Action kinds: ChainAllow(1041), ContractMainCall(44), ReqSignList(1044)");
            println!("Call source SHA-256: {}", preview.call_source_sha256);
            println!("Call action SHA-256: {}", preview.call_action_sha256);
            println!("Unsigned commitment: {}", preview.unsigned_commitment);
        }
        Command::PreviewFund {
            left_address,
            hub_address,
            contract_address,
            left_deposit_zhu,
            network_fee_zhu,
            gas_max,
        } => {
            let preview = preview_hvm_registry_pilot_funding(
                left_address,
                hub_address,
                contract_address,
                &network,
                *left_deposit_zhu,
                *network_fee_zhu,
                *gas_max,
            )?;
            println!("HPAY HVM CANONICAL FUNDING PREVIEW");
            println!("Network: private Local Pilot chain 7 (never mainnet)");
            println!("Left: {}", preview.left_address);
            println!("Hub: {}", preview.hub_address);
            println!("Contract: {}", preview.contract_address);
            println!("Exact funding (Zhu): {}", preview.amount_zhu);
            println!("Requested network fee (Zhu): {}", preview.network_fee_zhu);
            println!("Requested total debit (Zhu): {}", preview.total_debit_zhu);
            println!("Requested gas max: {}", preview.gas_max);
            println!("Action kinds: ChainAllow(1041), HacToTrs(1)");
            println!(
                "Transfer action SHA-256: {}",
                preview.transfer_action_sha256
            );
            println!("Unsigned commitment: {}", preview.unsigned_commitment);
        }
        Command::PreviewPrefund {
            left_address,
            hub_address,
            network_fee_zhu,
            timestamp,
            valid_until_unix,
            gas_max,
        } => {
            let preview = preview_hvm_registry_pilot_prefund(
                left_address,
                hub_address,
                &network,
                *network_fee_zhu,
                *timestamp,
                *valid_until_unix,
                *gas_max,
            )?;
            println!("HPAY HVM CANONICAL HUB PREFUND PREVIEW");
            println!("Network: private Local Pilot chain 7 (never mainnet)");
            println!("Source: {}", preview.source_address);
            println!("Destination: {}", preview.destination_address);
            println!("Exact transfer (Zhu): {}", preview.amount_zhu);
            println!("Requested network fee (Zhu): {}", preview.network_fee_zhu);
            println!("Requested total debit (Zhu): {}", preview.total_debit_zhu);
            println!("Transaction timestamp: {}", preview.timestamp);
            println!(
                "CLI authorization valid until: {}",
                preview.valid_until_unix
            );
            println!("Validity policy: {}", preview.validity_policy);
            println!("Requested gas max: {}", preview.gas_max);
            println!("Address topology: source, destination");
            println!("Action kinds: ChainAllow(1041), HacToTrs(1)");
            println!(
                "Transfer action SHA-256: {}",
                preview.transfer_action_sha256
            );
            println!("Unsigned commitment: {}", preview.unsigned_commitment);
        }
        _ => {
            let node = NodeClient::new(&args.node_url)?;
            let capabilities = node.capabilities().await?;
            network.validate_capabilities(&capabilities)?;
            return run_online(args, network, node, capabilities).await;
        }
    }
    println!("No node connection, DPAPI identity or durable state was opened.");
    println!("No transaction was constructed, signed or submitted.");
    Ok(())
}

async fn run_online(
    args: Args,
    network: HvmLocalPilotNetwork,
    node: NodeClient,
    capabilities: l2_fast_pay_hub::node::FullnodeCapabilitiesV1,
) -> Result<(), Box<dyn std::error::Error>> {
    match &args.command {
        Command::Status => {
            let left_address = load_dpapi_public_identity(&args.left_identity_dpapi_file)?;
            let hub_address = load_dpapi_public_identity(&args.hub_identity_dpapi_file)?;
            require_distinct_public_identities(&left_address, &hub_address)?;
            println!("HPAY SHARED HVM REGISTRY LOCAL PILOT");
            println!("Network: private chain 7 (never mainnet)");
            println!("Node height: {}", capabilities.height);
            println!("Left address: {left_address}");
            println!("Hub address: {hub_address}");
            println!(
                "Left balance (Zhu): {}",
                node.query_balance_zhu(&left_address).await?
            );
            println!(
                "Hub balance (Zhu): {}",
                node.query_balance_zhu(&hub_address).await?
            );
            println!(
                "Minimum deployment protocol cost (Zhu): {HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU}"
            );
            println!("No signer key was decrypted.");
            println!("No transaction was signed or submitted.");
            return Ok(());
        }
        Command::Inspect => {
            let (left_address, left_state_key) =
                load_dpapi_state_key_identity(&args.left_identity_dpapi_file)?;
            let hub_address = load_dpapi_public_identity(&args.hub_identity_dpapi_file)?;
            require_distinct_public_identities(&left_address, &hub_address)?;
            let store = HvmRegistryPilotStateStore::open(
                &args.state_file,
                left_state_key.as_str(),
                network,
                &left_address,
                &hub_address,
            )?;
            print_store(&store)?;
            println!("No signer key was decrypted.");
            return Ok(());
        }
        Command::ReconcileLifecycle {
            stage,
            confirmations,
            wait_seconds,
        } => {
            if *confirmations == 0 {
                return Err("lifecycle reconciliation confirmations must be positive".into());
            }
            let (left_address, left_state_key) =
                load_dpapi_state_key_identity(&args.left_identity_dpapi_file)?;
            let hub_address = load_dpapi_public_identity(&args.hub_identity_dpapi_file)?;
            require_distinct_public_identities(&left_address, &hub_address)?;
            let mut store = HvmRegistryPilotStateStore::open(
                &args.state_file,
                left_state_key.as_str(),
                network.clone(),
                &left_address,
                &hub_address,
            )?;
            reconcile_lifecycle_observation_only(
                &node,
                &network,
                &mut store,
                *stage,
                *confirmations,
                *wait_seconds,
            )
            .await?;
            println!("No signer key was decrypted.");
            println!("No transaction was submitted or resubmitted.");
            return Ok(());
        }
        _ => {}
    }

    let (public_left_address, public_left_state_key) =
        load_dpapi_state_key_identity(&args.left_identity_dpapi_file)?;
    let public_hub_address = load_dpapi_public_identity(&args.hub_identity_dpapi_file)?;
    require_distinct_public_identities(&public_left_address, &public_hub_address)?;

    let mut store = HvmRegistryPilotStateStore::open(
        &args.state_file,
        public_left_state_key.as_str(),
        network.clone(),
        &public_left_address,
        &public_hub_address,
    )?;

    if let Some(execution) = lifecycle_execution(&args.command)? {
        if store.lifecycle_snapshot(execution.stage).is_some() {
            run_lifecycle_record(
                &node,
                &network,
                &mut store,
                execution.stage,
                execution.required_action,
                execution.confirmations,
                execution.wait_seconds,
                execution.exact_resubmit,
            )
            .await?;
            verify_completed_lifecycle_stage(&node, &store, execution.stage).await?;
            println!("No signer key was decrypted.");
            return Ok(());
        }
        if execution.exact_resubmit.is_some() {
            return Err("exact resubmit was supplied but no durable transaction exists".into());
        }
        if execution.stage == HvmRegistryLifecycleStage::HubPrefunding {
            let Command::PrefundHub {
                expected_preview_commitment,
                network_fee_zhu,
                timestamp,
                valid_until_unix,
                gas_max,
                ..
            } = &args.command
            else {
                unreachable!("Prefund execution must originate from PrefundHub");
            };
            let expected_preview_commitment = expected_preview_commitment
                .as_deref()
                .ok_or("new PrefundHub requires --expected-preview-commitment")?;
            let timestamp = timestamp.ok_or("new PrefundHub requires --timestamp")?;
            let valid_until_unix =
                valid_until_unix.ok_or("new PrefundHub requires --valid-until-unix")?;
            let preview = preview_hvm_registry_pilot_prefund(
                &public_left_address,
                &public_hub_address,
                &network,
                *network_fee_zhu,
                timestamp,
                valid_until_unix,
                *gas_max,
            )?;
            preview.validate_for_signing(unix_timestamp()?)?;
            if preview.unsigned_commitment != expected_preview_commitment {
                return Err(
                    "new PrefundHub does not match the explicitly reviewed preview commitment"
                        .into(),
                );
            }
        }
        if let Some(predecessor) = predecessor_for(execution.stage) {
            if execution.stage == HvmRegistryLifecycleStage::Deployment {
                if store.lifecycle_snapshot(predecessor).is_some() {
                    require_reobserved_confirmed(&node, &mut store, predecessor, 6).await?;
                }
            } else {
                require_reobserved_confirmed(&node, &mut store, predecessor, 6).await?;
            }
        }
    } else if matches!(args.command, Command::Activate { .. }) {
        require_reobserved_confirmed(&node, &mut store, HvmRegistryLifecycleStage::Funding, 6)
            .await?;
    }

    let identities = load_identities(&args)?;
    if identities.left_address != public_left_address
        || identities.hub_address != public_hub_address
        || identities.left_state_key.as_str() != public_left_state_key.as_str()
    {
        return Err("registry signer identities changed after public-state reconciliation".into());
    }
    let node_url = args.node_url.clone();

    match args.command {
        Command::Status | Command::Inspect | Command::ReconcileLifecycle { .. } => {
            unreachable!("read-only commands return before signer loading")
        }
        Command::PreviewDeploy { .. }
        | Command::PreviewInitialize { .. }
        | Command::PreviewFund { .. }
        | Command::PreviewPrefund { .. } => {
            unreachable!("offline preview returns before DPAPI identity loading")
        }
        Command::PrefundHub {
            expected_preview_commitment,
            network_fee_zhu,
            timestamp,
            valid_until_unix,
            gas_max,
            confirmations,
            wait_seconds,
            exact_resubmit_tx_hash: _,
            exact_resubmit_commitment: _,
        } => {
            require_execution_args(network_fee_zhu, gas_max, confirmations, wait_seconds)?;
            let required_hub_balance = u128::from(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU)
                .checked_add(u128::from(network_fee_zhu))
                .ok_or("Hub deployment balance requirement overflow")?;
            let existing = store.hub_prefunding().is_some();
            let hub_balance = node.query_balance_zhu(&identities.hub_address).await?;
            if !existing && hub_balance >= required_hub_balance {
                println!("Hub already has the exact deployment cost and fee reserve.");
                println!("No transaction was signed or submitted.");
            } else {
                if !existing {
                    if hub_balance < u128::from(network_fee_zhu) {
                        return Err(
                            "Hub must retain at least the deployment network fee before exact prefunding"
                                .into(),
                        );
                    }
                    let required_left_balance = u128::from(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU)
                        .checked_add(u128::from(network_fee_zhu))
                        .ok_or("left prefunding balance requirement overflow")?;
                    if node.query_balance_zhu(&identities.left_address).await?
                        < required_left_balance
                    {
                        return Err(format!(
                            "pilot-left balance is insufficient: mine at least {required_left_balance} Local Pilot Zhu"
                        )
                        .into());
                    }
                }
                let left = Account::create_by(identities.left_secret.as_str())?;
                let expected_preview_commitment = expected_preview_commitment
                    .as_deref()
                    .ok_or("new PrefundHub lost its reviewed preview commitment")?;
                let timestamp = timestamp.ok_or("new PrefundHub lost its exact timestamp")?;
                let valid_until_unix =
                    valid_until_unix.ok_or("new PrefundHub lost its validity window")?;
                let prepared = store.prepare_hub_prefunding(
                    &left,
                    network_fee_zhu,
                    timestamp,
                    valid_until_unix,
                    gas_max,
                    expected_preview_commitment,
                    unix_timestamp()?,
                )?;
                require_created_provenance(prepared.provenance)?;
                run_lifecycle_record(
                    &node,
                    &network,
                    &mut store,
                    HvmRegistryLifecycleStage::HubPrefunding,
                    1,
                    confirmations,
                    wait_seconds,
                    None,
                )
                .await?;
                if node.query_balance_zhu(&identities.hub_address).await? < required_hub_balance {
                    return Err(
                        "confirmed exact prefunding did not produce the required Hub deployment balance"
                            .into(),
                    );
                }
                println!("Exact durable Hub prefunding confirmed.");
            }
        }
        Command::Deploy {
            expected_preview_commitment,
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
            exact_resubmit_tx_hash: _,
            exact_resubmit_commitment: _,
        } => {
            require_execution_args(network_fee_zhu, gas_max, confirmations, wait_seconds)?;
            let required = u128::from(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU)
                .checked_add(u128::from(network_fee_zhu))
                .ok_or("deployment balance requirement overflow")?;
            if node.query_balance_zhu(&identities.hub_address).await? < required {
                return Err(format!(
                    "Hub balance is insufficient: send at least {required} Local Pilot Zhu to {}",
                    identities.hub_address
                )
                .into());
            }
            let hub = Account::create_by(identities.hub_secret.as_str())?;
            let deployment = store.prepare_deployment(
                &hub,
                network_fee_zhu,
                unix_timestamp()?,
                gas_max,
                &expected_preview_commitment,
            )?;
            require_created_provenance(deployment.provenance)?;
            let contract_address = deployment.transaction.contract_address.clone();
            run_lifecycle_record(
                &node,
                &network,
                &mut store,
                HvmRegistryLifecycleStage::Deployment,
                40,
                confirmations,
                wait_seconds,
                None,
            )
            .await?;
            println!("Registry deployment confirmed: {contract_address}");
        }
        Command::Initialize {
            hub_url,
            expected_preview_commitment,
            channel_id,
            left_deposit_zhu,
            challenge_blocks,
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
            exact_resubmit_tx_hash: _,
            exact_resubmit_commitment: _,
        } => {
            require_execution_args(network_fee_zhu, gas_max, confirmations, wait_seconds)?;
            if left_deposit_zhu == 0 || challenge_blocks == 0 {
                return Err("deposit and challenge blocks must be positive".into());
            }
            let left = Account::create_by(identities.left_secret.as_str())?;
            let hub = Account::create_by(identities.hub_secret.as_str())?;
            let parameters = if let Some((_, _, _, stored, _)) = store.initialization() {
                if stored.channel_id != channel_id
                    || stored.left_deposit_zhu != left_deposit_zhu
                    || stored.challenge_blocks != challenge_blocks
                {
                    return Err(
                        "initialization retry changed the durable deposit or challenge window"
                            .into(),
                    );
                }
                stored.clone()
            } else {
                HvmRegistryPilotChannelParameters {
                    channel_id,
                    reuse_version: 0,
                    left_deposit_zhu,
                    right_hub_deposit_zhu: 0,
                    challenge_blocks,
                }
            };
            let prepared = store.prepare_initialization(
                &left,
                &hub,
                parameters,
                network_fee_zhu,
                unix_timestamp()?,
                gas_max,
                &expected_preview_commitment,
                unix_timestamp()?,
            )?;
            require_created_provenance(prepared.provenance)?;
            // Ask BEFORE broadcasting `init`. A Hub that refuses here costs the
            // user a deploy that was already sunk; a Hub that refuses after
            // `init` confirms burns this (contract, left) slot forever, because
            // re-`init` is only reachable from FINAL-and-claimed and a channel
            // stranded in FUNDING is neither.
            let ask = store
                .refund_countersign_request()
                .ok_or("initialization lost its refund countersign ask")?
                .clone();
            let answer = request_hub_refund_countersignature(&hub_url, &ask).await?;
            store.record_hub_countersignature(&answer, &hub_url, unix_timestamp()?)?;
            println!("Hub countersigned the serial-1 full refund; the user can now leave unaided.");
            run_lifecycle_record(
                &node,
                &network,
                &mut store,
                HvmRegistryLifecycleStage::Initialization,
                44,
                confirmations,
                wait_seconds,
                None,
            )
            .await?;
            println!("Shared registry channel initialization confirmed.");
        }
        Command::Fund {
            expected_preview_commitment,
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
            exact_resubmit_tx_hash: _,
            exact_resubmit_commitment: _,
        } => {
            require_execution_args(network_fee_zhu, gas_max, confirmations, wait_seconds)?;
            let left = Account::create_by(identities.left_secret.as_str())?;
            // The on-chain re-check, and it is not decoration. The refund bill
            // binds the challenge window; `PayableHAC` does not check it. So a
            // channel that was `init`ed with a different challenge window would
            // take the deposit and then refuse the perfectly-signed refund.
            let bundle = store
                .recovery_bundle()
                .cloned()
                .ok_or("funding requires a Hub-countersigned refund bundle")?;
            node.verify_hvm_registry_prefunding_bundle(&bundle, 1, 0)
                .await?;
            println!(
                "Pre-funding chain re-check passed: the channel on chain is the one the refund bill names."
            );
            let prepared = store.prepare_funding(
                &left,
                network_fee_zhu,
                unix_timestamp()?,
                gas_max,
                &expected_preview_commitment,
            )?;
            require_created_provenance(prepared.provenance)?;
            run_lifecycle_record(
                &node,
                &network,
                &mut store,
                HvmRegistryLifecycleStage::Funding,
                1,
                confirmations,
                wait_seconds,
                None,
            )
            .await?;
            let bundle = store
                .recovery_bundle()
                .ok_or("funding journal lost its recovery bundle")?;
            // Open, not "initial": the reviewed contract now seeds a recovery
            // buffer on every channel key when it takes custody, and
            // `verify_hvm_registry_initial_bundle` requires zero recovery
            // credit. Asserting the old shape here would report a failure on a
            // funding that had in fact just succeeded.
            node.verify_hvm_registry_open_bundle(bundle, 1, 1).await?;
            println!("Exact left-only channel funding confirmed.");
        }
        Command::Activate {
            hub_state_file,
            network_fee_zhu,
            gas_max,
            lease_periods,
            wait_seconds,
        } => {
            if network_fee_zhu == 0 || gas_max == 0 || lease_periods == 0 || wait_seconds == 0 {
                return Err("activation parameters are invalid".into());
            }
            require_funding_confirmed(&store)?;
            let bundle = store
                .recovery_bundle()
                .cloned()
                .ok_or("activation journal lost its recovery bundle")?;
            node.verify_hvm_registry_initial_bundle(&bundle, 1).await?;
            drop(store);
            let hub = open_hub(&node_url, &identities, hub_state_file)?;
            let commitment = hub
                .activate_hvm_registry_recovery(bundle.clone(), 1, 0)
                .await?;
            let operation_id = stable_id("lease", &commitment, "bootstrap")?;
            let (stable_time, stable_created) = registry_request_time(&hub, &operation_id)?;
            let request = HvmRegistryLeaseRenewalRequestV2 {
                schema: HVM_REGISTRY_LEASE_REQUEST_SCHEMA.into(),
                operation_id: operation_id.clone(),
                idempotency_key: operation_id,
                binding_commitment: commitment.clone(),
                renew_when_blocks_at_or_below: u64::MAX,
                periods: lease_periods,
                network_fee_zhu,
                timestamp: stable_time,
                gas_max,
                created_unix: stable_created,
            };
            let response = wait_registry_chain(
                || hub.run_hvm_registry_lease_renewal(request.clone()),
                wait_seconds,
            )
            .await?;
            node.verify_hvm_registry_open_bundle(&bundle, 1, 1).await?;
            println!("Registry activated and all 18 leases are operational.");
            println!("Binding commitment: {commitment}");
            print_chain_response(&response);
        }
        Command::Pay {
            hub_state_file,
            payment_label,
            recipient,
            amount_zhu,
            expires_seconds,
        } => {
            if amount_zhu == 0 || !(30..=900).contains(&expires_seconds) {
                return Err("payment amount or expiry is invalid".into());
            }
            require_funding_confirmed(&store)?;
            let bundle = store
                .recovery_bundle()
                .cloned()
                .ok_or("payment journal lost its recovery bundle")?;
            node.verify_hvm_registry_open_bundle(&bundle, 1, 1).await?;
            drop(store);
            let left = Account::create_by(identities.left_secret.as_str())?;
            let hub = open_hub(&node_url, &identities, hub_state_file)?;
            let commitment = bundle.binding.commitment()?;
            let operation_id = stable_id("payment", &commitment, &payment_label)?;
            let request = match hub.hvm_registry_payment_status(&operation_id) {
                Ok(status) => status.request,
                Err(HubError::NotFound(_)) => {
                    let previous = hub
                        .hvm_registry_channel_status(&commitment)?
                        .latest_fully_signed_bill;
                    let now = unix_timestamp()?;
                    // Read from the node rather than assumed: the request is
                    // bound to the network it was built on, and the Hub refuses
                    // one whose binding disagrees with the channel's.
                    let network_binding =
                        node.capabilities().await?.l1_channel_network_binding()?;
                    build_hvm_registry_pilot_payment_request(
                        &left,
                        &network_binding,
                        &bundle.binding,
                        &previous,
                        &operation_id,
                        &operation_id,
                        &recipient,
                        amount_zhu,
                        now,
                        now.checked_add(expires_seconds)
                            .ok_or("payment expiry overflow")?,
                    )?
                }
                Err(error) => return Err(error.into()),
            };
            if request.recipient != recipient || request.amount_zhu != amount_zhu {
                return Err("payment label is already bound to different terms".into());
            }
            let cosigned = hub
                .cosign_hvm_registry_payment(request, unix_timestamp()?)
                .await?;
            cosigned.bill.validate_fully_signed(&bundle.binding)?;
            println!("Fee-free registry payment is fully signed and durable.");
            println!("Operation: {operation_id}");
            println!("Serial: {}", cosigned.bill.serial);
            println!("Amount (Zhu): {amount_zhu}");
            println!("Hub fee (Zhu): 0");
            println!("Anchor receipts: {}", cosigned.anchor_receipts.len());
        }
        Command::Watch {
            hub_state_file,
            action,
            operation_label,
            network_fee_zhu,
            gas_max,
            wait_seconds,
        } => {
            if network_fee_zhu == 0 || gas_max == 0 || wait_seconds == 0 {
                return Err("watchtower parameters are invalid".into());
            }
            require_funding_confirmed(&store)?;
            let bundle = store
                .recovery_bundle()
                .cloned()
                .ok_or("watchtower journal lost its recovery bundle")?;
            node.verify_hvm_registry_runtime_bundle(&bundle, 1, 1)
                .await?;
            drop(store);
            let hub = open_hub(&node_url, &identities, hub_state_file)?;
            let commitment = bundle.binding.commitment()?;
            let mode = match action {
                WatchAction::BeginChallenge | WatchAction::InjectStaleChallenge => {
                    HvmRegistryWatchtowerModeV2::BeginChallenge
                }
                WatchAction::Monitor => HvmRegistryWatchtowerModeV2::Monitor,
            };
            let operation_id = stable_id(
                "watch",
                &commitment,
                &format!("{action:?}-{operation_label}"),
            )?;
            let (stable_time, stable_created) = registry_request_time(&hub, &operation_id)?;
            let request = HvmRegistryWatchtowerRequestV2 {
                schema: HVM_REGISTRY_WATCHTOWER_REQUEST_SCHEMA.into(),
                operation_id: operation_id.clone(),
                idempotency_key: operation_id,
                binding_commitment: commitment,
                mode,
                network_fee_zhu,
                timestamp: stable_time,
                gas_max,
                created_unix: stable_created,
            };
            let response = wait_registry_chain(
                || run_registry_watch_action(&hub, action, request.clone()),
                wait_seconds,
            )
            .await?;
            print_chain_response(&response);
        }
        Command::Reconcile {
            hub_state_file,
            operation_id,
            allow_exact_resubmit,
            wait_seconds,
        } => {
            if operation_id.trim().is_empty() || wait_seconds == 0 {
                return Err("reconciliation parameters are invalid".into());
            }
            drop(store);
            let hub = open_hub(&node_url, &identities, hub_state_file)?;
            let deadline = tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(wait_seconds))
                .ok_or("reconciliation deadline overflow")?;
            loop {
                let response = hub
                    .reconcile_hvm_registry_chain_operation(&operation_id, allow_exact_resubmit)
                    .await?;
                if response.status == "confirmed" || response.status == "no_action" {
                    print_chain_response(&response);
                    break;
                }
                if response.status == "recovery_required" && !allow_exact_resubmit {
                    return Err(
                        "operation remains Recovery Required; exact resubmit is disabled".into(),
                    );
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "operation remains {} after reconciliation timeout",
                        response.status
                    )
                    .into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
        }
        Command::AbandonInadmissible {
            hub_state_file,
            operation_id,
        } => {
            if operation_id.trim().is_empty() {
                return Err("abandonment parameters are invalid".into());
            }
            drop(store);
            let hub = open_hub(&node_url, &identities, hub_state_file)?;
            let response = hub
                .abandon_inadmissible_hvm_registry_chain_operation(&operation_id)
                .await?;
            print_chain_response(&response);
            println!(
                "The signed transaction was proven inadmissible and observed absent. It is now terminal and will never be resubmitted; a replacement may be signed."
            );
        }
    }
    Ok(())
}

async fn run_registry_watch_action(
    hub: &HubState,
    action: WatchAction,
    request: HvmRegistryWatchtowerRequestV2,
) -> l2_fast_pay_hub::HubResult<l2_fast_pay_hub::hvm_registry_watchtower::HvmRegistryChainResponseV2>
{
    match action {
        WatchAction::InjectStaleChallenge => {
            hub.run_hvm_registry_local_pilot_stale_challenge(request)
                .await
        }
        WatchAction::BeginChallenge | WatchAction::Monitor => {
            hub.run_hvm_registry_watchtower(request).await
        }
    }
}

/// The registry Local Pilot signs real value, so its identities exist only
/// inside a Windows DPAPI v3 identity directory. Every non-Windows build
/// refuses here instead of reaching for a weaker key source; there is
/// deliberately no file, environment or plaintext fallback.
#[cfg(not(windows))]
const DPAPI_REQUIRED: &str = "the registry Local Pilot requires Windows DPAPI";

struct Identities {
    left_address: String,
    left_secret: zeroize::Zeroizing<String>,
    left_state_key: zeroize::Zeroizing<String>,
    hub_address: String,
    hub_secret: zeroize::Zeroizing<String>,
    hub_journal_key: zeroize::Zeroizing<String>,
    hub_state_key: zeroize::Zeroizing<String>,
}

#[cfg(windows)]
fn load_identities(args: &Args) -> Result<Identities, Box<dyn std::error::Error>> {
    let (left_address, left_secret, _, left_state_key) =
        l2_fast_pay_hub::windows_identity::load_dpapi_hub_identity(&args.left_identity_dpapi_file)?
            .into_parts();
    let (hub_address, hub_secret, hub_journal_key, hub_state_key) =
        l2_fast_pay_hub::windows_identity::load_dpapi_hub_identity(&args.hub_identity_dpapi_file)?
            .into_parts();
    let left = Account::create_by(left_secret.as_str())?;
    let hub = Account::create_by(hub_secret.as_str())?;
    if left.readable() != left_address
        || hub.readable() != hub_address
        || left_address == hub_address
        || left_secret.as_str() == hub_secret.as_str()
    {
        return Err("registry pilot identities are corrupt, mismatched or reused".into());
    }
    Ok(Identities {
        left_address,
        left_secret,
        left_state_key,
        hub_address,
        hub_secret,
        hub_journal_key,
        hub_state_key,
    })
}

#[cfg(not(windows))]
fn load_identities(_args: &Args) -> Result<Identities, Box<dyn std::error::Error>> {
    Err(DPAPI_REQUIRED.into())
}

#[cfg(windows)]
fn load_dpapi_public_identity(
    path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    Ok(l2_fast_pay_hub::windows_identity::load_dpapi_hub_public(
        path,
    )?)
}

#[cfg(not(windows))]
fn load_dpapi_public_identity(
    _path: &std::path::Path,
) -> Result<String, Box<dyn std::error::Error>> {
    Err(DPAPI_REQUIRED.into())
}

#[cfg(windows)]
fn load_dpapi_state_key_identity(
    path: &std::path::Path,
) -> Result<(String, zeroize::Zeroizing<String>), Box<dyn std::error::Error>> {
    Ok(l2_fast_pay_hub::windows_identity::load_dpapi_hub_state_key(
        path,
    )?)
}

#[cfg(not(windows))]
fn load_dpapi_state_key_identity(
    _path: &std::path::Path,
) -> Result<(String, zeroize::Zeroizing<String>), Box<dyn std::error::Error>> {
    Err(DPAPI_REQUIRED.into())
}

fn require_distinct_public_identities(
    left_address: &str,
    hub_address: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let left = field::Address::from_readable(left_address)?;
    let hub = field::Address::from_readable(hub_address)?;
    if left.to_readable() != left_address
        || hub.to_readable() != hub_address
        || left_address == hub_address
    {
        return Err("registry pilot identities are invalid or reused".into());
    }
    Ok(())
}

fn open_hub(
    node_url: &str,
    identities: &Identities,
    state_file: PathBuf,
) -> Result<HubState, Box<dyn std::error::Error>> {
    let signer = HubSigner::from_secret_hex(identities.hub_secret.as_str())?;
    Ok(HubState::new_secure_with_signer_policy(
        "HPAY Shared HVM Registry Local Pilot",
        identities.hub_address.clone(),
        node_url.to_owned(),
        None,
        state_file,
        signer,
        identities.hub_journal_key.as_str(),
        identities.hub_state_key.as_str(),
        "local-pilot",
        0,
        0,
    )?)
}

struct LifecycleExecution<'a> {
    stage: HvmRegistryLifecycleStage,
    required_action: u16,
    confirmations: u64,
    wait_seconds: u64,
    exact_resubmit: Option<(&'a str, &'a str)>,
}

fn lifecycle_execution(
    command: &Command,
) -> Result<Option<LifecycleExecution<'_>>, Box<dyn std::error::Error>> {
    let execution = match command {
        Command::PrefundHub {
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
            exact_resubmit_tx_hash,
            exact_resubmit_commitment,
            ..
        } => {
            require_execution_args(*network_fee_zhu, *gas_max, *confirmations, *wait_seconds)?;
            Some(LifecycleExecution {
                stage: HvmRegistryLifecycleStage::HubPrefunding,
                required_action: 1,
                confirmations: *confirmations,
                wait_seconds: *wait_seconds,
                exact_resubmit: exact_resubmit_pair(
                    exact_resubmit_tx_hash,
                    exact_resubmit_commitment,
                )?,
            })
        }
        Command::Deploy {
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
            exact_resubmit_tx_hash,
            exact_resubmit_commitment,
            ..
        } => {
            require_execution_args(*network_fee_zhu, *gas_max, *confirmations, *wait_seconds)?;
            Some(LifecycleExecution {
                stage: HvmRegistryLifecycleStage::Deployment,
                required_action: 40,
                confirmations: *confirmations,
                wait_seconds: *wait_seconds,
                exact_resubmit: exact_resubmit_pair(
                    exact_resubmit_tx_hash,
                    exact_resubmit_commitment,
                )?,
            })
        }
        Command::Initialize {
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
            exact_resubmit_tx_hash,
            exact_resubmit_commitment,
            ..
        } => {
            require_execution_args(*network_fee_zhu, *gas_max, *confirmations, *wait_seconds)?;
            Some(LifecycleExecution {
                stage: HvmRegistryLifecycleStage::Initialization,
                required_action: 44,
                confirmations: *confirmations,
                wait_seconds: *wait_seconds,
                exact_resubmit: exact_resubmit_pair(
                    exact_resubmit_tx_hash,
                    exact_resubmit_commitment,
                )?,
            })
        }
        Command::Fund {
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
            exact_resubmit_tx_hash,
            exact_resubmit_commitment,
            ..
        } => {
            require_execution_args(*network_fee_zhu, *gas_max, *confirmations, *wait_seconds)?;
            Some(LifecycleExecution {
                stage: HvmRegistryLifecycleStage::Funding,
                required_action: 1,
                confirmations: *confirmations,
                wait_seconds: *wait_seconds,
                exact_resubmit: exact_resubmit_pair(
                    exact_resubmit_tx_hash,
                    exact_resubmit_commitment,
                )?,
            })
        }
        _ => None,
    };
    Ok(execution)
}

fn exact_resubmit_pair<'a>(
    hash: &'a Option<String>,
    commitment: &'a Option<String>,
) -> Result<Option<(&'a str, &'a str)>, Box<dyn std::error::Error>> {
    match (hash.as_deref(), commitment.as_deref()) {
        (None, None) => Ok(None),
        (Some(hash), Some(commitment)) => Ok(Some((hash, commitment))),
        _ => Err(
            "exact resubmit requires both --exact-resubmit-tx-hash and --exact-resubmit-commitment"
                .into(),
        ),
    }
}

fn predecessor_for(stage: HvmRegistryLifecycleStage) -> Option<HvmRegistryLifecycleStage> {
    match stage {
        HvmRegistryLifecycleStage::HubPrefunding => None,
        HvmRegistryLifecycleStage::Deployment => Some(HvmRegistryLifecycleStage::HubPrefunding),
        HvmRegistryLifecycleStage::Initialization => Some(HvmRegistryLifecycleStage::Deployment),
        HvmRegistryLifecycleStage::Funding => Some(HvmRegistryLifecycleStage::Initialization),
    }
}

fn required_action(stage: HvmRegistryLifecycleStage) -> u16 {
    match stage {
        HvmRegistryLifecycleStage::HubPrefunding | HvmRegistryLifecycleStage::Funding => 1,
        HvmRegistryLifecycleStage::Deployment => 40,
        HvmRegistryLifecycleStage::Initialization => 44,
    }
}

/// One request, one answer, and the wallet keeps 97 bytes of what comes back.
///
/// The response type carries no binding and no bill, so there is nothing here
/// for a hostile Hub to substitute: `record_hub_countersignature` splices the
/// signature into the bill this process already built and made durable.
async fn request_hub_refund_countersignature(
    hub_url: &str,
    request: &l2_fast_pay_hub::hvm_registry::HvmRegistryRefundCountersignRequestV2,
) -> Result<
    l2_fast_pay_hub::hvm_registry_ledger::HvmRegistryRefundCountersignResponseV2,
    Box<dyn std::error::Error>,
> {
    let url = format!(
        "{}/v2/hvm-registry/channel/open-countersign",
        hub_url.trim_end_matches('/')
    );
    let response = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?
        .post(url)
        .json(request)
        .send()
        .await?;
    if !response.status().is_success() {
        return Err(format!(
            "the Hub refused to countersign the refund: HTTP {} {}",
            response.status(),
            response.text().await.unwrap_or_default()
        )
        .into());
    }
    Ok(response.json().await?)
}

fn require_created_provenance(
    provenance: HvmRegistryPrepareProvenance,
) -> Result<(), Box<dyn std::error::Error>> {
    if provenance != HvmRegistryPrepareProvenance::CreatedThisInvocation {
        return Err("preexisting lifecycle bytes must be reconciled before signer loading".into());
    }
    Ok(())
}

// One argument per lifecycle constraint being recorded. Grouping them would
// hide which of them a given call actually pins.
#[allow(clippy::too_many_arguments)]
async fn run_lifecycle_record(
    node: &NodeClient,
    network: &HvmLocalPilotNetwork,
    store: &mut HvmRegistryPilotStateStore,
    stage: HvmRegistryLifecycleStage,
    required_action: u16,
    confirmations: u64,
    wait_seconds: u64,
    exact_resubmit: Option<(&str, &str)>,
) -> Result<(), Box<dyn std::error::Error>> {
    network.validate_capabilities(&node.capabilities().await?)?;
    let snapshot = store
        .lifecycle_snapshot(stage)
        .ok_or("registry lifecycle stage has no durable transaction")?;
    let observation = node
        .query_hvm_pilot_transaction(&snapshot.transaction.transaction_hash, required_action)
        .await;
    let outcome = store.reconcile_observation_result(stage, observation, confirmations)?;
    let transaction = match outcome {
        HvmRegistryObservationOutcome::Confirmed => {
            print_confirmed_stage(store, stage);
            return Ok(());
        }
        HvmRegistryObservationOutcome::Pending
        | HvmRegistryObservationOutcome::AwaitingConfirmations => {
            return wait_for_lifecycle_confirmation(
                node,
                network,
                store,
                stage,
                required_action,
                confirmations,
                wait_seconds,
            )
            .await;
        }
        HvmRegistryObservationOutcome::NeverAttempted => {
            if exact_resubmit.is_some() {
                return Err("exact resubmit was supplied for a fresh transaction".into());
            }
            store.begin_initial_submission(
                stage,
                &snapshot.transaction.transaction_hash,
                &snapshot.request_commitment,
                unix_timestamp()?,
            )?
        }
        HvmRegistryObservationOutcome::RecoveryRequired => {
            let Some((expected_hash, expected_commitment)) = exact_resubmit else {
                return Err(format!(
                    "{stage:?} requires explicit exact resubmit; review transaction {} and request commitment {}, then supply both exact values",
                    snapshot.transaction.transaction_hash, snapshot.request_commitment
                )
                .into());
            };
            store.begin_exact_resubmit(stage, expected_hash, expected_commitment)?
        }
    };
    if let Err(error) = node
        .submit_hvm_local_pilot_transaction_bound(
            &transaction.signed_transaction_hex,
            &transaction.transaction_hash,
            network,
        )
        .await
    {
        store.mark_submission_uncertain(stage, &transaction.transaction_hash)?;
        return Err(error.into());
    }
    store.mark_submission_acknowledged(stage, &transaction.transaction_hash)?;
    wait_for_lifecycle_confirmation(
        node,
        network,
        store,
        stage,
        required_action,
        confirmations,
        wait_seconds,
    )
    .await
}

async fn wait_for_lifecycle_confirmation(
    node: &NodeClient,
    network: &HvmLocalPilotNetwork,
    store: &mut HvmRegistryPilotStateStore,
    stage: HvmRegistryLifecycleStage,
    required_action: u16,
    confirmations: u64,
    wait_seconds: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(wait_seconds))
        .ok_or("confirmation deadline overflow")?;
    loop {
        network.validate_capabilities(&node.capabilities().await?)?;
        let snapshot = store
            .lifecycle_snapshot(stage)
            .ok_or("registry lifecycle stage disappeared while waiting")?;
        let observation = node
            .query_hvm_pilot_transaction(&snapshot.transaction.transaction_hash, required_action)
            .await;
        match store.reconcile_observation_result(stage, observation, confirmations)? {
            HvmRegistryObservationOutcome::Confirmed => {
                print_confirmed_stage(store, stage);
                return Ok(());
            }
            HvmRegistryObservationOutcome::RecoveryRequired
            | HvmRegistryObservationOutcome::NeverAttempted => {
                return Err(format!(
                    "{stage:?} entered fail-closed recovery while awaiting confirmation"
                )
                .into());
            }
            HvmRegistryObservationOutcome::Pending
            | HvmRegistryObservationOutcome::AwaitingConfirmations => {}
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "{} remains durable but has not reached {confirmations} confirmations",
                snapshot.transaction.transaction_hash
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

async fn require_reobserved_confirmed(
    node: &NodeClient,
    store: &mut HvmRegistryPilotStateStore,
    stage: HvmRegistryLifecycleStage,
    confirmations: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let network = HvmLocalPilotNetwork::canonical();
    network.validate_capabilities(&node.capabilities().await?)?;
    let snapshot = store
        .lifecycle_snapshot(stage)
        .ok_or_else(|| format!("{stage:?} predecessor is missing"))?;
    let observation = node
        .query_hvm_pilot_transaction(
            &snapshot.transaction.transaction_hash,
            required_action(stage),
        )
        .await;
    if store.reconcile_observation_result(stage, observation, confirmations)?
        != HvmRegistryObservationOutcome::Confirmed
    {
        return Err(format!(
            "{stage:?} predecessor is not currently anchored with {confirmations} confirmations"
        )
        .into());
    }
    Ok(())
}

async fn verify_completed_lifecycle_stage(
    node: &NodeClient,
    store: &HvmRegistryPilotStateStore,
    stage: HvmRegistryLifecycleStage,
) -> Result<(), Box<dyn std::error::Error>> {
    if stage == HvmRegistryLifecycleStage::Funding {
        let bundle = store
            .recovery_bundle()
            .ok_or("funding journal lost its recovery bundle")?;
        node.verify_hvm_registry_initial_bundle(bundle, 1).await?;
    }
    print_confirmed_stage(store, stage);
    Ok(())
}

fn print_confirmed_stage(store: &HvmRegistryPilotStateStore, stage: HvmRegistryLifecycleStage) {
    if let Some(snapshot) = store.lifecycle_snapshot(stage) {
        println!("Lifecycle stage confirmed: {stage:?}");
        println!("Transaction: {}", snapshot.transaction.transaction_hash);
        println!("Request commitment: {}", snapshot.request_commitment);
        if let Some(evidence) = snapshot.active_confirmation {
            println!("Block height: {}", evidence.block_height);
            println!(
                "Block hash: {}",
                evidence
                    .block_hash
                    .as_deref()
                    .unwrap_or("legacy-unanchored")
            );
            println!("Confirmations: {}", evidence.observed_confirmations);
        }
    }
}

async fn wait_registry_chain<F, Fut>(
    mut execute: F,
    wait_seconds: u64,
) -> Result<
    l2_fast_pay_hub::hvm_registry_watchtower::HvmRegistryChainResponseV2,
    Box<dyn std::error::Error>,
>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<
            Output = l2_fast_pay_hub::HubResult<
                l2_fast_pay_hub::hvm_registry_watchtower::HvmRegistryChainResponseV2,
            >,
        >,
{
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(wait_seconds))
        .ok_or("registry chain deadline overflow")?;
    loop {
        let response = execute().await?;
        if matches!(response.status.as_str(), "confirmed" | "no_action") {
            return Ok(response);
        }
        if response.status == "recovery_required" {
            return Err(format!(
                "operation {} requires explicit reconciliation",
                response.operation_id
            )
            .into());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "operation {} remains {}",
                response.operation_id, response.status
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn require_funding_confirmed(
    store: &HvmRegistryPilotStateStore,
) -> Result<(), Box<dyn std::error::Error>> {
    if !matches!(
        store.funding().map(|entry| entry.0),
        Some(HvmPilotTransactionPhase::Confirmed)
    ) {
        return Err("registry channel requires exact confirmed funding".into());
    }
    Ok(())
}

fn require_execution_args(
    fee: u64,
    gas: u8,
    confirmations: u64,
    wait: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if fee == 0 || gas == 0 || confirmations == 0 || wait == 0 {
        return Err("fee, gas, confirmations and wait must be positive".into());
    }
    Ok(())
}

fn random_channel_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

fn stable_id(
    domain: &str,
    binding: &str,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let label = label.trim();
    if label.is_empty()
        || label.len() > 96
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b' '))
    {
        return Err("operation label contains unsupported characters".into());
    }
    let mut digest = Sha256::new();
    digest.update(b"HPAY/HVM-REGISTRY/LOCAL-PILOT/OP/V1");
    digest.update(domain.as_bytes());
    digest.update(binding.as_bytes());
    digest.update(label.as_bytes());
    Ok(format!(
        "registry-{domain}-{}",
        hex::encode(digest.finalize())
    ))
}

/// The exact transaction timestamp to commit for this chain operation.
///
/// Every invocation of `activate` and `watch` rebuilds its request from
/// scratch, and the Hub refuses a retry whose request commitment changed, so
/// the timestamp has to be identical across invocations. That used to be met
/// by hashing the operation into a fixed `1_700_000_000 + n % 100_000_000`
/// window — a window whose upper half is in the future. `chain::check` on the
/// fullnode rejects any transaction whose timestamp exceeds the node's clock
/// ("tx timestamp {} cannot exceed now {}"), so roughly one operation in
/// eight drew a future timestamp and could never be submitted at all: it was
/// refused at the node and latched `RecoveryRequired` a second after being
/// signed.
///
/// Stability now comes from the durable record rather than from a hash: the
/// first attempt reads the real clock, and every later attempt reads back the
/// timestamp already committed for that operation. The rebuilt request is
/// therefore byte-identical to the persisted one, and the value can never be
/// in the future.
/// Both committed clock fields are read back, never one inferred from the
/// other: the commitment covers `timestamp` and `created_unix` separately, so
/// deriving the second from the first would rebuild a lookalike rather than
/// the original request the moment the two were ever written apart.
fn registry_request_time(
    hub: &HubState,
    operation_id: &str,
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    match hub.hvm_registry_chain_operation_request_clock(operation_id)? {
        Some(committed) => Ok(committed),
        None => {
            let now = unix_timestamp()?;
            Ok((now, now))
        }
    }
}

fn unix_timestamp() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn print_store(store: &HvmRegistryPilotStateStore) -> Result<(), Box<dyn std::error::Error>> {
    println!("HPAY SHARED HVM REGISTRY LOCAL PILOT JOURNAL");
    if let Some((phase, transaction, height)) = store.hub_prefunding() {
        println!("Hub prefunding: {phase:?}");
        println!(
            "Hub prefunding transaction: {}",
            transaction.transaction_hash
        );
        println!("Hub prefunding confirmed height: {height:?}");
    } else {
        println!("Hub prefunding: Not prepared");
    }
    if let Some((phase, deployment, height)) = store.deployment() {
        println!("Deployment: {phase:?}");
        println!(
            "Deployment transaction: {}",
            deployment.transaction.transaction_hash
        );
        println!("Deployment contract: {}", deployment.contract_address);
        println!("Deployment source SHA-256: {}", deployment.source_sha256);
        println!("Deployment bytecode SHA3: {}", deployment.bytecode_sha3);
        println!("Deployment confirmed height: {height:?}");
    } else {
        println!("Deployment: Not prepared");
    }
    if let Some((phase, transaction, height, _, _)) = store.initialization() {
        println!("Initialization: {phase:?}");
        println!(
            "Initialization transaction: {}",
            transaction.transaction_hash
        );
        println!("Initialization confirmed height: {height:?}");
    } else {
        println!("Initialization: Not prepared");
    }
    if let Some((phase, transaction, height)) = store.funding() {
        println!("Funding: {phase:?}");
        println!("Funding transaction: {}", transaction.transaction_hash);
        println!("Funding confirmed height: {height:?}");
    } else {
        println!("Funding: Not prepared");
    }
    if let Some(bundle) = store.recovery_bundle() {
        println!(
            "Binding commitment: {}",
            bundle
                .binding
                .commitment()
                .unwrap_or_else(|_| "invalid".into())
        );
        println!("Contract: {}", bundle.binding.contract_address);
    }
    for stage in [
        HvmRegistryLifecycleStage::HubPrefunding,
        HvmRegistryLifecycleStage::Deployment,
        HvmRegistryLifecycleStage::Initialization,
        HvmRegistryLifecycleStage::Funding,
    ] {
        if let Some(snapshot) = store.lifecycle_snapshot(stage) {
            println!("{stage:?} attempt state: {:?}", snapshot.attempt_state);
            println!(
                "{stage:?} exact request commitment: {}",
                snapshot.request_commitment
            );
            if let Some(evidence) = snapshot.active_confirmation {
                println!(
                    "{stage:?} active block: {} @ {} ({} confirmations)",
                    evidence
                        .block_hash
                        .as_deref()
                        .unwrap_or("legacy-unanchored"),
                    evidence.block_height,
                    evidence.observed_confirmations
                );
            }
            println!(
                "{stage:?} archived confirmations: {}",
                snapshot.confirmation_history.len()
            );
            for evidence in snapshot.confirmation_history {
                println!(
                    "{stage:?} archived block: {} @ {} ({} confirmations)",
                    evidence
                        .block_hash
                        .as_deref()
                        .unwrap_or("legacy-unanchored"),
                    evidence.block_height,
                    evidence.observed_confirmations
                );
            }
        }
        if let Some(review) = store.lifecycle_review(stage)? {
            print!("{}", format_lifecycle_review(&review));
        }
    }
    Ok(())
}

fn format_lifecycle_review(review: &HvmRegistryLifecycleReview) -> String {
    use std::fmt::Write as _;

    let mut output = String::new();
    let _ = writeln!(output, "{:?} exact review:", review.stage);
    let _ = writeln!(output, "  Network kind: {}", review.network.network_kind);
    let _ = writeln!(output, "  Node profile: {}", review.network.node_profile_id);
    let _ = writeln!(output, "  Chain id: {}", review.network.chain_id);
    let _ = writeln!(output, "  Block 1 hash: {}", review.network.block_1_hash);
    let _ = writeln!(
        output,
        "  Network instance: {}",
        review.network.network_instance_id
    );
    let _ = writeln!(
        output,
        "  Transaction format: {}",
        review.network.transaction_format_version
    );
    let _ = writeln!(output, "  Source/main: {}", review.source_address);
    let _ = writeln!(
        output,
        "  Destination/contract: {}",
        review.destination_or_contract.as_deref().unwrap_or("none")
    );
    let _ = writeln!(
        output,
        "  Amount/protocol cost (Zhu): {}",
        review
            .amount_or_protocol_cost_zhu
            .map(|value| value.to_string())
            .unwrap_or_else(|| "none".into())
    );
    let _ = writeln!(output, "  Network fee (Zhu): {}", review.network_fee_zhu);
    let _ = writeln!(output, "  Gas max: {}", review.gas_max);
    let _ = writeln!(output, "  Timestamp: {}", review.timestamp);
    let _ = writeln!(output, "  Action kinds: {:?}", review.action_kinds);
    let _ = writeln!(output, "  Address topology: {:?}", review.address_topology);
    let _ = writeln!(output, "  Required signers: {:?}", review.required_signers);
    let _ = writeln!(
        output,
        "  Reviewed preview commitment: {}",
        review
            .reviewed_preview_commitment
            .as_deref()
            .unwrap_or("legacy-not-recorded")
    );
    let _ = writeln!(output, "  Transaction hash: {}", review.transaction_hash);
    let _ = writeln!(
        output,
        "  Signed transaction SHA-256: {}",
        review.signed_transaction_sha256
    );
    let _ = writeln!(
        output,
        "  Exact request commitment: {}",
        review.request_commitment
    );
    output
}

async fn reconcile_lifecycle_observation_only(
    node: &NodeClient,
    network: &HvmLocalPilotNetwork,
    store: &mut HvmRegistryPilotStateStore,
    stage: LifecycleStage,
    required_confirmations: u64,
    wait_seconds: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let durable_stage = stage.durable();
    let snapshot = store
        .lifecycle_snapshot(durable_stage)
        .ok_or("lifecycle stage has no durable transaction")?;
    let previous_phase = snapshot.phase;
    let transaction_hash = snapshot.transaction.transaction_hash;
    let action = required_action(durable_stage);
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(wait_seconds))
        .ok_or("lifecycle reconciliation deadline overflow")?;
    loop {
        network.validate_capabilities(&node.capabilities().await?)?;
        let observation = node
            .query_hvm_pilot_transaction(&transaction_hash, action)
            .await;
        match store.reconcile_observation_result(
            durable_stage,
            observation,
            required_confirmations,
        )? {
            HvmRegistryObservationOutcome::Confirmed => {
                println!("Lifecycle stage: {stage:?}");
                println!("Previous durable phase: {previous_phase:?}");
                print_confirmed_stage(store, durable_stage);
                return Ok(());
            }
            HvmRegistryObservationOutcome::RecoveryRequired
            | HvmRegistryObservationOutcome::NeverAttempted => {
                return Err(format!(
                    "{stage:?} transaction {transaction_hash} requires explicit recovery; no submit or resubmit was attempted"
                )
                .into());
            }
            HvmRegistryObservationOutcome::Pending
            | HvmRegistryObservationOutcome::AwaitingConfirmations => {}
        }
        if wait_seconds == 0 || tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "{stage:?} transaction {transaction_hash} is not deeply confirmed; no submit or resubmit was attempted"
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
}

fn print_chain_response(
    response: &l2_fast_pay_hub::hvm_registry_watchtower::HvmRegistryChainResponseV2,
) {
    println!("Operation: {}", response.operation_id);
    println!("Status: {}", response.status);
    println!("Action: {}", response.action);
    if let Some(hash) = response.transaction_hash.as_deref() {
        println!("Transaction: {hash}");
    }
    println!("Confirmations: {}", response.observed_confirmations);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_identity_and_timestamp_are_stable_and_scoped() {
        let binding = "11".repeat(32);
        let first = stable_id("payment", &binding, "demo-1").unwrap();
        assert_eq!(first, stable_id("payment", &binding, "demo-1").unwrap());
        assert_ne!(first, stable_id("watch", &binding, "demo-1").unwrap());
        assert!(stable_id("payment", &binding, "../bad").is_err());
    }

    #[test]
    fn lifecycle_review_output_is_complete_and_contains_no_secret_material() {
        let review = HvmRegistryLifecycleReview {
            stage: HvmRegistryLifecycleStage::HubPrefunding,
            network: HvmLocalPilotNetwork::canonical(),
            source_address: "1Source".into(),
            destination_or_contract: Some("1Destination".into()),
            amount_or_protocol_cost_zhu: Some(HVM_REGISTRY_DEPLOY_PROTOCOL_COST_ZHU),
            network_fee_zhu: 1_000_000,
            gas_max: 255,
            timestamp: 1_700_000_000,
            action_kinds: vec![0x0411, 1],
            address_topology: vec!["1Source".into(), "1Destination".into()],
            required_signers: vec!["1Source".into()],
            reviewed_preview_commitment: Some("11".repeat(32)),
            transaction_hash: "22".repeat(32),
            signed_transaction_sha256: "33".repeat(32),
            request_commitment: "44".repeat(32),
        };
        let output = format_lifecycle_review(&review);
        for required in [
            "Network kind:",
            "Node profile:",
            "Chain id:",
            "Block 1 hash:",
            "Network instance:",
            "Transaction format:",
            "Source/main: 1Source",
            "Destination/contract: 1Destination",
            "Amount/protocol cost (Zhu):",
            "Network fee (Zhu): 1000000",
            "Gas max: 255",
            "Timestamp: 1700000000",
            "Action kinds: [1041, 1]",
            "Address topology:",
            "Required signers:",
            "Reviewed preview commitment:",
            "Transaction hash:",
            "Signed transaction SHA-256:",
            "Exact request commitment:",
        ] {
            assert!(output.contains(required), "missing {required}");
        }
        for forbidden in [
            "signed_transaction_hex",
            "private_key",
            "private key",
            "secret",
            "dpapi",
        ] {
            assert!(!output.to_ascii_lowercase().contains(forbidden));
        }
    }

    #[test]
    fn prefunding_exact_resubmit_is_explicit_and_off_by_default() {
        let base = [
            "hpay-hvm-registry-local-pilot",
            "--left-identity-dpapi-file",
            "left.dpapi",
            "--hub-identity-dpapi-file",
            "hub.dpapi",
            "--state-file",
            "registry.sealed.json",
            "prefund-hub",
            "--network-fee-zhu",
            "1000000",
        ];
        let parsed = Args::try_parse_from(base).unwrap();
        assert!(matches!(
            parsed.command,
            Command::PrefundHub {
                exact_resubmit_tx_hash: None,
                exact_resubmit_commitment: None,
                ..
            }
        ));

        assert!(
            Args::try_parse_from(
                base.into_iter()
                    .chain(["--allow-exact-resubmit"])
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
        assert!(
            Args::try_parse_from(
                base.into_iter()
                    .chain(["--exact-resubmit-tx-hash", "11"])
                    .collect::<Vec<_>>()
            )
            .is_err()
        );
        let hash = "11".repeat(32);
        let commitment = "22".repeat(32);
        let parsed = Args::try_parse_from(
            base.into_iter()
                .chain([
                    "--exact-resubmit-tx-hash",
                    hash.as_str(),
                    "--exact-resubmit-commitment",
                    commitment.as_str(),
                ])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::PrefundHub {
                exact_resubmit_tx_hash: Some(parsed_hash),
                exact_resubmit_commitment: Some(parsed_commitment),
                ..
            } if parsed_hash == hash && parsed_commitment == commitment
        ));
    }

    #[test]
    fn deployment_preview_requires_public_address_and_never_enables_resubmit() {
        let parsed = Args::try_parse_from([
            "hpay-hvm-registry-local-pilot",
            "--left-identity-dpapi-file",
            "missing-left.dpapi",
            "--hub-identity-dpapi-file",
            "missing-hub.dpapi",
            "--state-file",
            "missing-registry.sealed.json",
            "preview-deploy",
            "--hub-address",
            "12ZCnDaGiZW9cZhYombd4mhUNLYnXcBjq7",
            "--network-fee-zhu",
            "1000000",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::PreviewDeploy {
                hub_address,
                network_fee_zhu: 1_000_000,
                gas_max: 255,
            } if hub_address == "12ZCnDaGiZW9cZhYombd4mhUNLYnXcBjq7"
        ));
    }

    #[test]
    fn deployment_requires_the_exact_reviewed_preview_commitment() {
        let base = [
            "hpay-hvm-registry-local-pilot",
            "--left-identity-dpapi-file",
            "left.dpapi",
            "--hub-identity-dpapi-file",
            "hub.dpapi",
            "--state-file",
            "registry.sealed.json",
            "deploy",
            "--network-fee-zhu",
            "1000000",
        ];
        assert!(Args::try_parse_from(base).is_err());

        let commitment = "44".repeat(32);
        let parsed = Args::try_parse_from(
            base.into_iter()
                .chain(["--expected-preview-commitment", commitment.as_str()])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Deploy {
                expected_preview_commitment,
                network_fee_zhu: 1_000_000,
                gas_max: 255,
                confirmations: 6,
                wait_seconds: 180,
                exact_resubmit_tx_hash: None,
                exact_resubmit_commitment: None,
            } if expected_preview_commitment == commitment
        ));
    }

    #[test]
    fn initialization_preview_is_public_and_signed_path_requires_exact_inputs() {
        let preview = Args::try_parse_from([
            "hpay-hvm-registry-local-pilot",
            "--left-identity-dpapi-file",
            "missing-left.dpapi",
            "--hub-identity-dpapi-file",
            "missing-hub.dpapi",
            "--state-file",
            "missing-registry.sealed.json",
            "preview-initialize",
            "--left-address",
            "1ExampleLeft",
            "--hub-address",
            "1ExampleHub",
            "--contract-address",
            "1ExampleContract",
            "--left-deposit-zhu",
            "1000000",
            "--network-fee-zhu",
            "500000",
        ])
        .unwrap();
        assert!(matches!(
            preview.command,
            Command::PreviewInitialize {
                channel_id: None,
                left_deposit_zhu: 1_000_000,
                challenge_blocks: 12,
                network_fee_zhu: 500_000,
                gas_max: 255,
                ..
            }
        ));

        let base = [
            "hpay-hvm-registry-local-pilot",
            "--left-identity-dpapi-file",
            "left.dpapi",
            "--hub-identity-dpapi-file",
            "hub.dpapi",
            "--state-file",
            "registry.sealed.json",
            "initialize",
            "--left-deposit-zhu",
            "1000000",
            "--network-fee-zhu",
            "500000",
        ];
        assert!(Args::try_parse_from(base).is_err());
        let commitment = "11".repeat(32);
        let channel_id = "22".repeat(16);
        // `--hub-url` is required, not optional. Initialization now has to ask
        // a Hub for the serial-1 refund countersignature before it broadcasts
        // anything, and there is no local fallback that could produce one.
        assert!(
            Args::try_parse_from(
                base.into_iter()
                    .chain([
                        "--expected-preview-commitment",
                        commitment.as_str(),
                        "--channel-id",
                        channel_id.as_str(),
                    ])
                    .collect::<Vec<_>>(),
            )
            .is_err(),
            "initialize must refuse to run without a Hub to countersign the refund"
        );
        let parsed = Args::try_parse_from(
            base.into_iter()
                .chain([
                    "--expected-preview-commitment",
                    commitment.as_str(),
                    "--channel-id",
                    channel_id.as_str(),
                    "--hub-url",
                    "http://127.0.0.1:8197",
                ])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Initialize {
                expected_preview_commitment,
                channel_id: parsed_channel_id,
                exact_resubmit_tx_hash: None,
                exact_resubmit_commitment: None,
                ..
            } if expected_preview_commitment == commitment && parsed_channel_id == channel_id
        ));
    }

    #[test]
    fn funding_preview_is_public_and_signed_path_requires_commitment() {
        let preview = Args::try_parse_from([
            "hpay-hvm-registry-local-pilot",
            "--left-identity-dpapi-file",
            "missing-left.dpapi",
            "--hub-identity-dpapi-file",
            "missing-hub.dpapi",
            "--state-file",
            "missing-registry.sealed.json",
            "preview-fund",
            "--left-address",
            "1ExampleLeft",
            "--hub-address",
            "1ExampleHub",
            "--contract-address",
            "1ExampleContract",
            "--left-deposit-zhu",
            "1000000",
            "--network-fee-zhu",
            "500000",
        ])
        .unwrap();
        assert!(matches!(
            preview.command,
            Command::PreviewFund {
                left_deposit_zhu: 1_000_000,
                network_fee_zhu: 500_000,
                gas_max: 255,
                ..
            }
        ));

        let base = [
            "hpay-hvm-registry-local-pilot",
            "--left-identity-dpapi-file",
            "left.dpapi",
            "--hub-identity-dpapi-file",
            "hub.dpapi",
            "--state-file",
            "registry.sealed.json",
            "fund",
            "--network-fee-zhu",
            "500000",
        ];
        assert!(Args::try_parse_from(base).is_err());
        let commitment = "33".repeat(32);
        let parsed = Args::try_parse_from(
            base.into_iter()
                .chain(["--expected-preview-commitment", commitment.as_str()])
                .collect::<Vec<_>>(),
        )
        .unwrap();
        assert!(matches!(
            parsed.command,
            Command::Fund {
                expected_preview_commitment,
                exact_resubmit_tx_hash: None,
                exact_resubmit_commitment: None,
                ..
            } if expected_preview_commitment == commitment
        ));
    }

    #[test]
    fn lifecycle_reconciliation_has_no_submit_or_resubmit_switch() {
        let base = [
            "hpay-hvm-registry-local-pilot",
            "--left-identity-dpapi-file",
            "left.dpapi",
            "--hub-identity-dpapi-file",
            "hub.dpapi",
            "--state-file",
            "registry.sealed.json",
            "reconcile-lifecycle",
            "--stage",
            "deployment",
            "--confirmations",
            "6",
        ];
        let parsed = Args::try_parse_from(base).unwrap();
        assert!(matches!(
            parsed.command,
            Command::ReconcileLifecycle {
                stage: LifecycleStage::Deployment,
                confirmations: 6,
                wait_seconds: 0,
            }
        ));
        let mut forbidden = base.to_vec();
        forbidden.extend(["--allow-exact-resubmit", "true"]);
        assert!(Args::try_parse_from(forbidden).is_err());
    }
}
