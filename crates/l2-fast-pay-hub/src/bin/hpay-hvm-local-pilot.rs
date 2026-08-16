use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};
use l2_fast_pay_hub::hvm_channel::HvmChannelRecoveryBundleV1;
use l2_fast_pay_hub::hvm_pilot::{
    HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID, HVM_PILOT_DEPLOY_PROTOCOL_COST_ZHU, HvmLocalPilotNetwork,
    HvmPilotChannelParameters, HvmPilotSignedTransaction, HvmPilotStateStore,
    HvmPilotTransactionPhase, build_hvm_pilot_payment_request, validate_hvm_pilot_node_url,
};
use l2_fast_pay_hub::hvm_watchtower::{
    HVM_LEASE_RENEWAL_REQUEST_SCHEMA, HVM_WATCHTOWER_REQUEST_SCHEMA, HvmLeaseRenewalRequestV1,
    HvmWatchtowerMode, HvmWatchtowerRequestV1,
};
use l2_fast_pay_hub::node::{NodeClient, TransactionObservation};
use l2_fast_pay_hub::{HubSigner, HubState};
use rand::{RngCore, rngs::OsRng};
use sha2::{Digest, Sha256};
use sys::Account;

#[derive(Parser, Debug)]
#[command(
    name = "hpay-hvm-local-pilot",
    about = "Fail-closed HPAY HVM lifecycle tool for the private chain-7 Local Pilot only"
)]
struct Args {
    #[arg(long, default_value = "http://127.0.0.1:8197")]
    node_url: String,

    #[arg(long)]
    left_identity_dpapi_file: PathBuf,

    #[arg(long)]
    hub_identity_dpapi_file: PathBuf,

    #[arg(long)]
    state_file: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum WatchtowerAction {
    BeginChallenge,
    InjectStaleChallenge,
    Monitor,
}

impl WatchtowerAction {
    fn mode(self) -> HvmWatchtowerMode {
        match self {
            Self::BeginChallenge => HvmWatchtowerMode::BeginChallenge,
            Self::InjectStaleChallenge => HvmWatchtowerMode::BeginChallenge,
            Self::Monitor => HvmWatchtowerMode::Monitor,
        }
    }

    fn domain(self) -> &'static str {
        match self {
            Self::BeginChallenge => "begin-challenge",
            Self::InjectStaleChallenge => "inject-stale-challenge",
            Self::Monitor => "monitor",
        }
    }
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Validate the exact node and identities and print only public funding data.
    Status,
    /// Read and authenticate the existing durable lifecycle journal without signing.
    Inspect,
    /// Build once, persist before submission, and reconcile the exact deployment.
    Deploy {
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 6)]
        confirmations: u64,
        #[arg(long, default_value_t = 120)]
        wait_seconds: u64,
    },
    /// Create and confirm the exact two-party channel state.
    Initialize {
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
        #[arg(long, default_value_t = 120)]
        wait_seconds: u64,
    },
    /// Fund the initialized contract with the exact left deposit.
    Fund {
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 6)]
        confirmations: u64,
        #[arg(long, default_value_t = 120)]
        wait_seconds: u64,
    },
    /// Activate the verified channel ledger and renew all 18 storage leases.
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
    /// Co-sign one exact fee-free off-chain bill using the production HVM ledger.
    Pay {
        #[arg(long)]
        hub_state_file: PathBuf,
        /// Stable unique label. Reuse the same label after a lost response.
        #[arg(long)]
        payment_label: String,
        #[arg(long, default_value = "hpay-local-pilot-service")]
        recipient: String,
        #[arg(long)]
        amount_zhu: u64,
        #[arg(long, default_value_t = 300)]
        expires_seconds: u64,
    },
    /// Run the production challenge/monitor/finalize watchtower state machine.
    Watchtower {
        #[arg(long)]
        hub_state_file: PathBuf,
        #[arg(long, value_enum)]
        action: WatchtowerAction,
        /// Stable unique label. Reuse it after a lost response.
        #[arg(long)]
        operation_label: String,
        #[arg(long)]
        network_fee_zhu: u64,
        #[arg(long, default_value_t = 255)]
        gas_max: u8,
        #[arg(long, default_value_t = 180)]
        wait_seconds: u64,
    },
    /// Reconcile one exact durable HVM chain operation; never creates new bytes.
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
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    validate_hvm_pilot_node_url(&args.node_url)?;
    let network = HvmLocalPilotNetwork::canonical();
    let node = NodeClient::new(&args.node_url)?;
    let capabilities = node.capabilities().await?;
    network.validate_capabilities(&capabilities)?;

    #[cfg(windows)]
    match &args.command {
        Command::Status => {
            let left_address = l2_fast_pay_hub::windows_identity::load_dpapi_hub_public(
                &args.left_identity_dpapi_file,
            )?;
            let hub_address = l2_fast_pay_hub::windows_identity::load_dpapi_hub_public(
                &args.hub_identity_dpapi_file,
            )?;
            require_distinct_public_identities(&left_address, &hub_address)?;
            let balance_zhu = node.query_balance_zhu(&left_address).await?;
            let hub_balance_zhu = node.query_balance_zhu(&hub_address).await?;
            println!("HPAY HVM LOCAL PILOT");
            println!("Network: private chain 7 (not mainnet, not public testnet)");
            println!("Node: verified and fresh at height {}", capabilities.height);
            println!("Network instance: {}", network.network_instance_id);
            println!("Pilot left address: {left_address}");
            println!("Hub address: {hub_address}");
            println!("Pilot left balance (Zhu): {balance_zhu}");
            println!("Hub watchtower balance (Zhu): {hub_balance_zhu}");
            println!("Deployment protocol cost floor (Zhu): {HVM_PILOT_DEPLOY_PROTOCOL_COST_ZHU}");
            println!("No signer key was decrypted.");
            println!("No transaction was built, signed or submitted.");
            return Ok(());
        }
        Command::Inspect => {
            let state_file = args
                .state_file
                .as_deref()
                .ok_or("--state-file is required for durable journal inspection")?;
            if !state_file.is_file() {
                return Err("durable HVM pilot state does not exist".into());
            }
            let (left_address, left_state_key) =
                l2_fast_pay_hub::windows_identity::load_dpapi_hub_state_key(
                    &args.left_identity_dpapi_file,
                )?;
            let hub_address = l2_fast_pay_hub::windows_identity::load_dpapi_hub_public(
                &args.hub_identity_dpapi_file,
            )?;
            require_distinct_public_identities(&left_address, &hub_address)?;
            let store = HvmPilotStateStore::open(
                state_file,
                left_state_key.as_str(),
                network,
                &left_address,
                &hub_address,
            )?;
            print_inspection(&store)?;
            println!("No signer key was decrypted.");
            return Ok(());
        }
        _ => {}
    }

    #[cfg(windows)]
    let (
        left_address,
        left_secret,
        left_state_key,
        hub_address,
        hub_secret,
        hub_journal_key,
        hub_state_key,
    ) = {
        let (left_address, left_secret, _, left_state_key) =
            l2_fast_pay_hub::windows_identity::load_dpapi_hub_identity(
                &args.left_identity_dpapi_file,
            )?
            .into_parts();
        let (hub_address, hub_secret, hub_journal_key, hub_state_key) =
            l2_fast_pay_hub::windows_identity::load_dpapi_hub_identity(
                &args.hub_identity_dpapi_file,
            )?
            .into_parts();
        let left = Account::create_by(left_secret.as_str())?;
        let hub = Account::create_by(hub_secret.as_str())?;
        if left.readable() != left_address
            || hub.readable() != hub_address
            || left_address == hub_address
            || left_secret.as_str() == hub_secret.as_str()
        {
            return Err("Local Pilot identities are corrupt, mismatched or reused".into());
        }
        (
            left_address,
            left_secret,
            left_state_key,
            hub_address,
            hub_secret,
            hub_journal_key,
            hub_state_key,
        )
    };
    #[cfg(not(windows))]
    return Err("the current Local Pilot identity tool requires Windows DPAPI".into());

    match args.command {
        Command::Status | Command::Inspect => {
            unreachable!("read-only commands return before signer loading")
        }
        Command::Deploy {
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
        } => {
            if network_fee_zhu == 0 || gas_max == 0 || confirmations == 0 || wait_seconds == 0 {
                return Err("deploy fee, gas, confirmations and wait time must be positive".into());
            }
            let state_file = args
                .state_file
                .ok_or("--state-file is required for the durable deploy command")?;
            let mut store = HvmPilotStateStore::open(
                state_file,
                left_state_key.as_str(),
                network.clone(),
                &left_address,
                &hub_address,
            )?;
            if store.deployment().is_none() {
                let required = u128::from(HVM_PILOT_DEPLOY_PROTOCOL_COST_ZHU)
                    .checked_add(u128::from(network_fee_zhu))
                    .ok_or("deployment amount overflow")?;
                let balance_zhu = node.query_balance_zhu(&left_address).await?;
                if balance_zhu < required {
                    return Err(format!(
                        "pilot left balance is {balance_zhu} Zhu; deployment requires at least {required} Zhu"
                    )
                    .into());
                }
            }
            let left = Account::create_by(left_secret.as_str())?;
            let deployment =
                store.prepare_deployment(&left, network_fee_zhu, unix_timestamp()?, gas_max)?;
            let durable_phase = store
                .deployment()
                .map(|(phase, _)| phase.clone())
                .ok_or("durable deployment phase is missing")?;
            if durable_phase == HvmPilotTransactionPhase::RecoveryRequired {
                return Err(
                    "deployment is frozen in Recovery Required; automatic submission is disabled"
                        .into(),
                );
            }
            drop(left);
            drop(left_secret);
            drop(left_state_key);
            drop(hub_secret);

            let fresh = node.capabilities().await?;
            network.validate_capabilities(&fresh)?;
            if let Some(observation) = node
                .query_hvm_pilot_transaction(&deployment.transaction.transaction_hash, 40)
                .await?
            {
                verify_exact_observation(
                    &observation.body_hex,
                    &deployment.transaction.signed_transaction_hex,
                )?;
                if !observation.pending && observation.confirmations >= confirmations {
                    let block_height = observation
                        .block_height
                        .ok_or("confirmed deployment omitted its block height")?;
                    store.mark_deployment_confirmed(
                        &deployment.transaction.transaction_hash,
                        block_height,
                    )?;
                    print_deployment(&deployment, observation.confirmations);
                    return Ok(());
                }
                if durable_phase == HvmPilotTransactionPhase::Confirmed {
                    store.mark_deployment_recovery_required(
                        &deployment.transaction.transaction_hash,
                    )?;
                    return Err(
                        "confirmed deployment lost its confirmation proof; Recovery Required"
                            .into(),
                    );
                }
                store.mark_deployment_submitted(&deployment.transaction.transaction_hash)?;
            } else {
                if durable_phase == HvmPilotTransactionPhase::Confirmed {
                    store.mark_deployment_recovery_required(
                        &deployment.transaction.transaction_hash,
                    )?;
                    return Err(
                        "confirmed deployment disappeared from the node; Recovery Required".into(),
                    );
                }
                node.submit_hvm_local_pilot_transaction_bound(
                    &deployment.transaction.signed_transaction_hex,
                    &deployment.transaction.transaction_hash,
                    &network,
                )
                .await?;
                store.mark_deployment_submitted(&deployment.transaction.transaction_hash)?;
            }

            let deadline = tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(wait_seconds))
                .ok_or("deploy wait deadline overflow")?;
            loop {
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "deployment is not yet confirmed; exact hash {} remains durable for recovery",
                        deployment.transaction.transaction_hash
                    )
                    .into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                let fresh = node.capabilities().await?;
                network.validate_capabilities(&fresh)?;
                let Some(observation) = node
                    .query_hvm_pilot_transaction(&deployment.transaction.transaction_hash, 40)
                    .await?
                else {
                    continue;
                };
                verify_exact_observation(
                    &observation.body_hex,
                    &deployment.transaction.signed_transaction_hex,
                )?;
                if !observation.pending && observation.confirmations >= confirmations {
                    let block_height = observation
                        .block_height
                        .ok_or("confirmed deployment omitted its block height")?;
                    store.mark_deployment_confirmed(
                        &deployment.transaction.transaction_hash,
                        block_height,
                    )?;
                    print_deployment(&deployment, observation.confirmations);
                    break;
                }
            }
        }
        Command::Initialize {
            left_deposit_zhu,
            challenge_blocks,
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
        } => {
            require_execution_args(network_fee_zhu, gas_max, confirmations, wait_seconds)?;
            if left_deposit_zhu == 0 || challenge_blocks == 0 {
                return Err("channel deposit and challenge blocks must be positive".into());
            }
            let state_file = args
                .state_file
                .ok_or("--state-file is required for channel initialization")?;
            let mut store = HvmPilotStateStore::open(
                state_file,
                left_state_key.as_str(),
                network.clone(),
                &left_address,
                &hub_address,
            )?;
            if store.initialization().is_none()
                && node.query_balance_zhu(&left_address).await? < u128::from(network_fee_zhu)
            {
                return Err("pilot left balance cannot cover the initialization fee".into());
            }
            let left = Account::create_by(left_secret.as_str())?;
            let hub = Account::create_by(hub_secret.as_str())?;
            let parameters = if let Some((_, _, parameters, _)) = store.initialization() {
                if parameters.left_deposit_zhu != left_deposit_zhu
                    || parameters.challenge_blocks != challenge_blocks
                {
                    return Err(
                        "initialization retry changed the durable deposit or challenge period"
                            .into(),
                    );
                }
                parameters.clone()
            } else {
                let mut channel_id = [0_u8; 16];
                OsRng.fill_bytes(&mut channel_id);
                HvmPilotChannelParameters {
                    network_instance_id: HPAY_LOCAL_PILOT_NETWORK_INSTANCE_ID.into(),
                    channel_id: hex::encode(channel_id),
                    reuse_version: 1,
                    left_deposit_zhu,
                    right_hub_deposit_zhu: 0,
                    challenge_blocks,
                }
            };
            let transaction = store.prepare_initialization(
                &left,
                &hub,
                parameters,
                network_fee_zhu,
                unix_timestamp()?,
                gas_max,
            )?;
            let durable_phase = store
                .initialization()
                .map(|(phase, _, _, _)| phase.clone())
                .ok_or("durable initialization phase is missing")?;
            if durable_phase == HvmPilotTransactionPhase::RecoveryRequired {
                return Err(
                    "initialization is frozen in Recovery Required; automatic submission is disabled"
                        .into(),
                );
            }
            drop(left);
            drop(hub);
            drop(left_secret);
            drop(left_state_key);
            drop(hub_secret);
            network.validate_capabilities(&node.capabilities().await?)?;

            let existing = observe_exact_transaction(&node, &transaction, 44).await?;
            if let Some(observation) = existing.as_ref()
                && !observation.pending
                && observation.confirmations >= confirmations
            {
                let block_height = confirmed_height(observation)?;
                store.mark_initialization_confirmed(&transaction.transaction_hash, block_height)?;
                print_stage("initialization", &transaction, observation.confirmations);
                return Ok(());
            }
            if durable_phase == HvmPilotTransactionPhase::Confirmed {
                store.mark_initialization_recovery_required(&transaction.transaction_hash)?;
                return Err(
                    "confirmed initialization lost its exact confirmation proof; Recovery Required"
                        .into(),
                );
            }
            if existing.is_none() {
                node.submit_hvm_local_pilot_transaction_bound(
                    &transaction.signed_transaction_hex,
                    &transaction.transaction_hash,
                    &network,
                )
                .await?;
            }
            store.mark_initialization_submitted(&transaction.transaction_hash)?;
            let observation = wait_for_exact_confirmation(
                &node,
                &network,
                &transaction,
                44,
                confirmations,
                wait_seconds,
            )
            .await?;
            store.mark_initialization_confirmed(
                &transaction.transaction_hash,
                confirmed_height(&observation)?,
            )?;
            print_stage("initialization", &transaction, observation.confirmations);
        }
        Command::Fund {
            network_fee_zhu,
            gas_max,
            confirmations,
            wait_seconds,
        } => {
            require_execution_args(network_fee_zhu, gas_max, confirmations, wait_seconds)?;
            let state_file = args
                .state_file
                .ok_or("--state-file is required for exact channel funding")?;
            let mut store = HvmPilotStateStore::open(
                state_file,
                left_state_key.as_str(),
                network.clone(),
                &left_address,
                &hub_address,
            )?;
            let deposit = store
                .initialization()
                .map(|(_, _, parameters, _)| parameters.left_deposit_zhu)
                .ok_or("exact funding requires durable channel initialization")?;
            if store.funding().is_none() {
                let required = u128::from(deposit)
                    .checked_add(u128::from(network_fee_zhu))
                    .ok_or("funding balance requirement overflow")?;
                if node.query_balance_zhu(&left_address).await? < required {
                    return Err(format!(
                        "pilot left balance cannot cover exact deposit plus fee ({required} Zhu)"
                    )
                    .into());
                }
            }
            let left = Account::create_by(left_secret.as_str())?;
            let transaction =
                store.prepare_funding(&left, network_fee_zhu, unix_timestamp()?, gas_max)?;
            let durable_phase = store
                .funding()
                .map(|(phase, _)| phase.clone())
                .ok_or("durable funding phase is missing")?;
            if durable_phase == HvmPilotTransactionPhase::RecoveryRequired {
                return Err(
                    "funding is frozen in Recovery Required; automatic submission is disabled"
                        .into(),
                );
            }
            drop(left);
            drop(left_secret);
            drop(left_state_key);
            drop(hub_secret);
            network.validate_capabilities(&node.capabilities().await?)?;

            let existing = observe_exact_transaction(&node, &transaction, 1).await?;
            if let Some(observation) = existing.as_ref()
                && !observation.pending
                && observation.confirmations >= confirmations
            {
                let block_height = confirmed_height(observation)?;
                store.mark_funding_confirmed(&transaction.transaction_hash, block_height)?;
                let bundle = store
                    .initialization()
                    .map(|(_, _, _, bundle)| bundle.clone())
                    .ok_or("funding journal lost the recovery bundle")?;
                verify_hvm_activation_entry_snapshot(&node, &bundle).await?;
                print_stage("exact funding", &transaction, observation.confirmations);
                return Ok(());
            }
            if durable_phase == HvmPilotTransactionPhase::Confirmed {
                store.mark_funding_recovery_required(&transaction.transaction_hash)?;
                return Err(
                    "confirmed funding lost its exact confirmation proof; Recovery Required".into(),
                );
            }
            if existing.is_none() {
                node.submit_hvm_local_pilot_transaction_bound(
                    &transaction.signed_transaction_hex,
                    &transaction.transaction_hash,
                    &network,
                )
                .await?;
            }
            store.mark_funding_submitted(&transaction.transaction_hash)?;
            let observation = wait_for_exact_confirmation(
                &node,
                &network,
                &transaction,
                1,
                confirmations,
                wait_seconds,
            )
            .await?;
            store.mark_funding_confirmed(
                &transaction.transaction_hash,
                confirmed_height(&observation)?,
            )?;
            let bundle = store
                .initialization()
                .map(|(_, _, _, bundle)| bundle.clone())
                .ok_or("funding journal lost the recovery bundle")?;
            verify_hvm_activation_entry_snapshot(&node, &bundle).await?;
            print_stage("exact funding", &transaction, observation.confirmations);
        }
        Command::Activate {
            hub_state_file,
            network_fee_zhu,
            gas_max,
            lease_periods,
            wait_seconds,
        } => {
            if network_fee_zhu == 0
                || gas_max == 0
                || lease_periods == 0
                || lease_periods > l2_fast_pay_hub::hvm_watchtower::HVM_LEASE_RENEWAL_MAX_PERIODS
                || wait_seconds == 0
            {
                return Err("activation lease parameters are invalid".into());
            }
            if node.query_balance_zhu(&hub_address).await? < u128::from(network_fee_zhu) {
                return Err("Hub watchtower balance cannot cover the lease renewal fee".into());
            }
            let state_file = args
                .state_file
                .ok_or("--state-file is required for HVM activation")?;
            let store = HvmPilotStateStore::open(
                state_file,
                left_state_key.as_str(),
                network.clone(),
                &left_address,
                &hub_address,
            )?;
            let funding_confirmed = matches!(
                store.funding().map(|(phase, _)| phase),
                Some(HvmPilotTransactionPhase::Confirmed)
            );
            if !funding_confirmed {
                return Err("HVM activation requires exact confirmed funding".into());
            }
            let bundle = store
                .initialization()
                .map(|(_, _, _, bundle)| bundle.clone())
                .ok_or("HVM activation journal lost the recovery bundle")?;
            verify_hvm_activation_entry_snapshot(&node, &bundle).await?;
            drop(store);
            drop(left_secret);
            drop(left_state_key);

            let hub_signer = HubSigner::from_secret_hex(hub_secret.as_str())?;
            drop(hub_secret);
            let hub = HubState::new_secure_with_signer_policy(
                "HPAY HVM Local Pilot",
                hub_address.clone(),
                args.node_url.clone(),
                None,
                hub_state_file,
                hub_signer,
                hub_journal_key.as_str(),
                hub_state_key.as_str(),
                "local-pilot",
                0,
                0,
            )?;
            let commitment = hub
                .activate_hvm_channel_recovery(bundle.clone(), 1, 0)
                .await?;
            let operation_id = format!("pilot-lease-{commitment}");
            let request = if let Some(existing) =
                hub.hvm_lease_renewal_request(&operation_id, u64::MAX)?
            {
                if existing.binding_commitment != commitment
                    || existing.periods != lease_periods
                    || existing.network_fee_zhu != network_fee_zhu
                    || existing.gas_max != gas_max
                {
                    return Err(
                        "activation retry parameters do not match the durable lease request".into(),
                    );
                }
                existing
            } else {
                let now = unix_timestamp()?;
                HvmLeaseRenewalRequestV1 {
                    schema: HVM_LEASE_RENEWAL_REQUEST_SCHEMA.into(),
                    operation_id: operation_id.clone(),
                    idempotency_key: operation_id,
                    binding_commitment: commitment.clone(),
                    renew_when_live_blocks_at_or_below: u64::MAX,
                    periods: lease_periods,
                    network_fee_zhu,
                    timestamp: now,
                    gas_max,
                    created_unix: now,
                }
            };
            let deadline = tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(wait_seconds))
                .ok_or("lease wait deadline overflow")?;
            let mut response = hub.run_hvm_lease_renewal(request.clone()).await?;
            while response.status != "confirmed" {
                if response.status == "recovery_required" || tokio::time::Instant::now() >= deadline
                {
                    return Err(format!(
                        "lease renewal is {}; operation {} remains durable for reconciliation",
                        response.status, request.operation_id
                    )
                    .into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                response = hub.run_hvm_lease_renewal(request.clone()).await?;
            }
            node.verify_hvm_recovery_bundle(&bundle, 1, 1).await?;
            println!("HPAY HVM LOCAL PILOT");
            println!("Stage: activated and all 18 leases renewed");
            println!("Binding commitment: {commitment}");
            println!(
                "Renewal transaction: {}",
                response
                    .transaction_hash
                    .as_deref()
                    .ok_or("confirmed renewal omitted transaction hash")?
            );
            println!("Confirmations: {}", response.observed_confirmations);
        }
        Command::Pay {
            hub_state_file,
            payment_label,
            recipient,
            amount_zhu,
            expires_seconds,
        } => {
            if amount_zhu == 0 || !(30..=900).contains(&expires_seconds) {
                return Err(
                    "payment amount must be positive and expiry must be 30-900 seconds".into(),
                );
            }
            let state_file = args
                .state_file
                .ok_or("--state-file is required for HVM payment")?;
            let store = HvmPilotStateStore::open(
                state_file,
                left_state_key.as_str(),
                network.clone(),
                &left_address,
                &hub_address,
            )?;
            if !matches!(
                store.funding().map(|(phase, _)| phase),
                Some(HvmPilotTransactionPhase::Confirmed)
            ) {
                return Err("HVM payment requires exact confirmed pilot funding".into());
            }
            let bundle = store
                .initialization()
                .map(|(_, _, _, bundle)| bundle.clone())
                .ok_or("HVM payment journal lost the recovery bundle")?;
            node.verify_hvm_recovery_bundle(&bundle, 1, 1).await?;
            drop(store);

            let left = Account::create_by(left_secret.as_str())?;
            let hub_signer = HubSigner::from_secret_hex(hub_secret.as_str())?;
            drop(hub_secret);
            let hub = HubState::new_secure_with_signer_policy(
                "HPAY HVM Local Pilot",
                hub_address.clone(),
                args.node_url.clone(),
                None,
                hub_state_file,
                hub_signer,
                hub_journal_key.as_str(),
                hub_state_key.as_str(),
                "local-pilot",
                0,
                0,
            )?;
            let commitment = bundle.binding.commitment()?;
            if !hub.hvm_recovery_activation_recorded(&commitment)? {
                return Err("HVM payment requires completed activation and lease renewal".into());
            }
            let operation_id = payment_operation_id(&commitment, &payment_label)?;
            let request = if let Some(existing) = hub.hvm_payment_request(&operation_id)? {
                if existing.binding_commitment != commitment
                    || existing.payer != left_address
                    || existing.recipient != recipient
                    || existing.amount_zhu != amount_zhu
                    || existing.hub_fee_zhu != 0
                    || existing.idempotency_key != operation_id
                {
                    return Err(
                        "payment label is already bound to different immutable terms".into(),
                    );
                }
                existing
            } else {
                let previous = hub.hvm_latest_bill(&commitment)?;
                let now = unix_timestamp()?;
                let expires = now
                    .checked_add(expires_seconds)
                    .ok_or("payment expiry overflow")?;
                build_hvm_pilot_payment_request(
                    &left,
                    &bundle.binding,
                    &previous,
                    &operation_id,
                    &operation_id,
                    &recipient,
                    amount_zhu,
                    now,
                    expires,
                )?
            };
            let signed = hub
                .cosign_hvm_payment(request.clone(), unix_timestamp()?)
                .await?;
            signed.validate_fully_signed(&bundle.binding)?;
            if hub.hvm_latest_bill(&commitment)? != signed
                || signed.serial != request.proposed_bill.serial
                || signed.left_balance_zhu != request.proposed_bill.left_balance_zhu
                || signed.right_balance_zhu != request.proposed_bill.right_balance_zhu
            {
                return Err("durable HVM ledger did not commit the exact co-signed bill".into());
            }
            println!("HPAY HVM LOCAL PILOT");
            println!("Stage: fee-free payment bill fully signed and durable");
            println!("Operation: {operation_id}");
            println!("Binding commitment: {commitment}");
            println!("Bill serial: {}", signed.serial);
            println!("Amount (Zhu): {amount_zhu}");
            println!("Hub fee (Zhu): 0");
            println!("Left balance (Zhu): {}", signed.left_balance_zhu);
            println!("Right balance (Zhu): {}", signed.right_balance_zhu);
        }
        Command::Watchtower {
            hub_state_file,
            action,
            operation_label,
            network_fee_zhu,
            gas_max,
            wait_seconds,
        } => {
            if network_fee_zhu == 0 || gas_max == 0 || wait_seconds == 0 {
                return Err("watchtower fee, gas and wait time must be positive".into());
            }
            if node.query_balance_zhu(&hub_address).await? < u128::from(network_fee_zhu) {
                return Err("Hub watchtower balance cannot cover the transaction fee".into());
            }
            let state_file = args
                .state_file
                .ok_or("--state-file is required for HVM watchtower")?;
            let store = HvmPilotStateStore::open(
                state_file,
                left_state_key.as_str(),
                network.clone(),
                &left_address,
                &hub_address,
            )?;
            if !matches!(
                store.funding().map(|(phase, _)| phase),
                Some(HvmPilotTransactionPhase::Confirmed)
            ) {
                return Err("HVM watchtower requires exact confirmed pilot funding".into());
            }
            let bundle = store
                .initialization()
                .map(|(_, _, _, bundle)| bundle.clone())
                .ok_or("HVM watchtower journal lost the recovery bundle")?;
            match action {
                WatchtowerAction::BeginChallenge | WatchtowerAction::InjectStaleChallenge => {
                    node.verify_hvm_recovery_bundle(&bundle, 1, 1).await?;
                }
                WatchtowerAction::Monitor => {
                    node.verify_hvm_runtime_channel(&bundle, 1, 1).await?;
                }
            }
            drop(store);
            drop(left_secret);
            drop(left_state_key);

            let hub_signer = HubSigner::from_secret_hex(hub_secret.as_str())?;
            drop(hub_secret);
            let hub = HubState::new_secure_with_signer_policy(
                "HPAY HVM Local Pilot",
                hub_address.clone(),
                args.node_url.clone(),
                None,
                hub_state_file,
                hub_signer,
                hub_journal_key.as_str(),
                hub_state_key.as_str(),
                "local-pilot",
                0,
                0,
            )?;
            let commitment = bundle.binding.commitment()?;
            if !hub.hvm_recovery_activation_recorded(&commitment)? {
                return Err("HVM watchtower requires completed activation".into());
            }
            let operation_id =
                watchtower_operation_id(&commitment, action.domain(), &operation_label)?;
            let mode = action.mode();
            let request = if let Some(existing) = hub.hvm_watchtower_request(&operation_id)? {
                if existing.binding_commitment != commitment
                    || existing.mode != mode
                    || existing.idempotency_key != operation_id
                    || existing.network_fee_zhu != network_fee_zhu
                    || existing.gas_max != gas_max
                {
                    return Err(
                        "watchtower label is already bound to different immutable terms".into(),
                    );
                }
                existing
            } else {
                let now = unix_timestamp()?;
                HvmWatchtowerRequestV1 {
                    schema: HVM_WATCHTOWER_REQUEST_SCHEMA.into(),
                    operation_id: operation_id.clone(),
                    idempotency_key: operation_id.clone(),
                    binding_commitment: commitment.clone(),
                    mode,
                    network_fee_zhu,
                    timestamp: now,
                    gas_max,
                    created_unix: now,
                }
            };
            let deadline = tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(wait_seconds))
                .ok_or("watchtower wait deadline overflow")?;
            let mut response = run_watchtower_action(&hub, action, request.clone()).await?;
            while !matches!(response.status.as_str(), "confirmed" | "no_action") {
                if response.status == "recovery_required" || tokio::time::Instant::now() >= deadline
                {
                    return Err(format!(
                        "watchtower is {}; operation {} remains durable for reconciliation",
                        response.status, request.operation_id
                    )
                    .into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                response = run_watchtower_action(&hub, action, request.clone()).await?;
            }
            println!("HPAY HVM LOCAL PILOT");
            println!("Stage: watchtower {}", response.status);
            println!("Operation: {}", response.operation_id);
            println!("Action: {}", response.action);
            if let Some(hash) = response.transaction_hash.as_deref() {
                println!("Transaction: {hash}");
            }
            println!("Confirmations: {}", response.observed_confirmations);
        }
        Command::Reconcile {
            hub_state_file,
            operation_id,
            allow_exact_resubmit,
            wait_seconds,
        } => {
            if operation_id.trim().is_empty() || wait_seconds == 0 {
                return Err("reconciliation operation id or wait duration is invalid".into());
            }
            drop(left_secret);
            drop(left_state_key);
            let hub_signer = HubSigner::from_secret_hex(hub_secret.as_str())?;
            drop(hub_secret);
            let hub = HubState::new_secure_with_signer_policy(
                "HPAY HVM Local Pilot",
                hub_address,
                args.node_url,
                None,
                hub_state_file,
                hub_signer,
                hub_journal_key.as_str(),
                hub_state_key.as_str(),
                "local-pilot",
                0,
                0,
            )?;
            let deadline = tokio::time::Instant::now()
                .checked_add(std::time::Duration::from_secs(wait_seconds))
                .ok_or("reconciliation wait deadline overflow")?;
            let mut response = hub
                .reconcile_hvm_watchtower(&operation_id, allow_exact_resubmit)
                .await?;
            while response.status != "confirmed" {
                if response.status == "recovery_required" {
                    let detail = hub
                        .hvm_chain_operation_last_error(&operation_id)?
                        .unwrap_or_else(|| "no durable error detail".into());
                    if !allow_exact_resubmit || tokio::time::Instant::now() >= deadline {
                        return Err(format!("operation remains Recovery Required: {detail}").into());
                    }
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err(format!(
                        "operation {} remains {} after reconciliation timeout",
                        operation_id, response.status
                    )
                    .into());
                }
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                response = hub
                    .reconcile_hvm_watchtower(&operation_id, allow_exact_resubmit)
                    .await?;
            }
            println!("HPAY HVM LOCAL PILOT");
            println!("Stage: exact durable reconciliation confirmed");
            println!("Operation: {operation_id}");
            println!("Action: {}", response.action);
            println!(
                "Transaction: {}",
                response
                    .transaction_hash
                    .as_deref()
                    .ok_or("confirmed reconciliation omitted transaction hash")?
            );
            println!("Confirmations: {}", response.observed_confirmations);
        }
    }
    Ok(())
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
        return Err("Local Pilot identities are invalid or reused".into());
    }
    Ok(())
}

fn print_inspection(store: &HvmPilotStateStore) -> Result<(), Box<dyn std::error::Error>> {
    println!("HPAY HVM LOCAL PILOT");
    println!("Stage: authenticated durable journal inspection");
    if let Some((phase, deployment)) = store.deployment() {
        println!("Deployment phase: {phase:?}");
        println!(
            "Deployment transaction: {}",
            deployment.transaction.transaction_hash
        );
        println!("Contract: {}", deployment.contract_address);
        if let Some(height) = store.deployment_confirmed_height() {
            println!("Deployment confirmed height: {height}");
        }
    } else {
        println!("Deployment phase: Not prepared");
    }
    if let Some((phase, initialization, parameters, bundle)) = store.initialization() {
        println!("Initialization phase: {phase:?}");
        println!(
            "Initialization transaction: {}",
            initialization.transaction_hash
        );
        if let Some(height) = store.initialization_confirmed_height() {
            println!("Initialization confirmed height: {height}");
        }
        println!("Channel id: {}", parameters.channel_id);
        println!("Left deposit (Zhu): {}", parameters.left_deposit_zhu);
        println!("Challenge blocks: {}", parameters.challenge_blocks);
        println!("Binding commitment: {}", bundle.binding.commitment()?);
    } else {
        println!("Initialization phase: Not prepared");
    }
    if let Some((phase, funding)) = store.funding() {
        println!("Funding phase: {phase:?}");
        println!("Funding transaction: {}", funding.transaction_hash);
        if let Some(height) = store.funding_confirmed_height() {
            println!("Funding confirmed height: {height}");
        }
    } else {
        println!("Funding phase: Not prepared");
    }
    println!("No transaction was built, signed or submitted.");
    Ok(())
}

async fn run_watchtower_action(
    hub: &HubState,
    action: WatchtowerAction,
    request: HvmWatchtowerRequestV1,
) -> Result<l2_fast_pay_hub::hvm_watchtower::HvmWatchtowerResponseV1, Box<dyn std::error::Error>> {
    Ok(match action {
        WatchtowerAction::InjectStaleChallenge => {
            hub.run_hvm_local_pilot_stale_challenge(request).await?
        }
        WatchtowerAction::BeginChallenge | WatchtowerAction::Monitor => {
            hub.run_hvm_watchtower(request).await?
        }
    })
}

fn verify_exact_observation(
    observed: &str,
    signed: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if !observed.eq_ignore_ascii_case(signed) {
        return Err("node returned different signed bytes for the durable deployment hash".into());
    }
    Ok(())
}

fn print_deployment(
    deployment: &l2_fast_pay_hub::hvm_pilot::HvmPilotDeploymentTransaction,
    confirmations: u64,
) {
    println!("HPAY HVM LOCAL PILOT DEPLOYMENT");
    println!("Phase: confirmed");
    println!("Transaction: {}", deployment.transaction.transaction_hash);
    println!("Contract: {}", deployment.contract_address);
    println!("Confirmations: {confirmations}");
    println!("Source SHA-256: {}", deployment.source_sha256);
    println!("Bytecode SHA3: {}", deployment.bytecode_sha3);
}

fn unix_timestamp() -> Result<u64, Box<dyn std::error::Error>> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs())
}

fn payment_operation_id(
    binding_commitment: &str,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let label = label.trim();
    if label.is_empty()
        || label.len() > 64
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("payment label must be 1-64 ASCII letters, digits, '-' or '_'".into());
    }
    let mut digest = Sha256::new();
    digest.update(b"HPAY/HVM/LOCAL-PILOT/PAYMENT/V1");
    digest.update(binding_commitment.as_bytes());
    digest.update((label.len() as u64).to_be_bytes());
    digest.update(label.as_bytes());
    Ok(format!("pilot-pay-{}", hex::encode(digest.finalize())))
}

fn watchtower_operation_id(
    binding_commitment: &str,
    action: &str,
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let label = label.trim();
    if label.is_empty()
        || label.len() > 64
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("operation label must be 1-64 ASCII letters, digits, '-' or '_'".into());
    }
    let mut digest = Sha256::new();
    digest.update(b"HPAY/HVM/LOCAL-PILOT/WATCHTOWER/V1");
    digest.update(binding_commitment.as_bytes());
    digest.update(action.as_bytes());
    digest.update((label.len() as u64).to_be_bytes());
    digest.update(label.as_bytes());
    Ok(format!("pilot-watch-{}", hex::encode(digest.finalize())))
}

fn require_execution_args(
    network_fee_zhu: u64,
    gas_max: u8,
    confirmations: u64,
    wait_seconds: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    if network_fee_zhu == 0 || gas_max == 0 || confirmations == 0 || wait_seconds == 0 {
        return Err("fee, gas, confirmations and wait time must be positive".into());
    }
    Ok(())
}

async fn observe_exact_transaction(
    node: &NodeClient,
    transaction: &HvmPilotSignedTransaction,
    required_action: u16,
) -> Result<Option<TransactionObservation>, Box<dyn std::error::Error>> {
    let observation = node
        .query_hvm_pilot_transaction(&transaction.transaction_hash, required_action)
        .await?;
    if let Some(observation) = observation.as_ref() {
        verify_exact_observation(&observation.body_hex, &transaction.signed_transaction_hex)?;
    }
    Ok(observation)
}

async fn wait_for_exact_confirmation(
    node: &NodeClient,
    network: &HvmLocalPilotNetwork,
    transaction: &HvmPilotSignedTransaction,
    required_action: u16,
    confirmations: u64,
    wait_seconds: u64,
) -> Result<TransactionObservation, Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(wait_seconds))
        .ok_or("confirmation wait deadline overflow")?;
    loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "outcome is not yet confirmed; exact hash {} remains durable for recovery",
                transaction.transaction_hash
            )
            .into());
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        network.validate_capabilities(&node.capabilities().await?)?;
        let Some(observation) =
            observe_exact_transaction(node, transaction, required_action).await?
        else {
            continue;
        };
        if !observation.pending && observation.confirmations >= confirmations {
            return Ok(observation);
        }
    }
}

fn confirmed_height(
    observation: &TransactionObservation,
) -> Result<u64, Box<dyn std::error::Error>> {
    observation
        .block_height
        .filter(|height| *height > 0)
        .ok_or_else(|| "confirmed transaction omitted its block height".into())
}

fn print_stage(stage: &str, transaction: &HvmPilotSignedTransaction, confirmations: u64) {
    println!("HPAY HVM LOCAL PILOT");
    println!("Stage: {stage} confirmed");
    println!("Transaction: {}", transaction.transaction_hash);
    println!("Confirmations: {confirmations}");
}

async fn verify_hvm_activation_entry_snapshot(
    node: &NodeClient,
    bundle: &HvmChannelRecoveryBundleV1,
) -> Result<(), Box<dyn std::error::Error>> {
    // A newly funded channel has the canonical bootstrap lease shape with zero
    // recovery credit. After the first durable renewal, restart must instead
    // accept only the operational positive-recovery shape. Both verifiers are
    // exact, so a mixed, expired, or otherwise degraded snapshot still fails.
    if let Err(operational_error) = node.verify_hvm_recovery_bundle(bundle, 1, 1).await {
        node.verify_hvm_initial_recovery_bundle(bundle, 1)
            .await
            .map_err(|bootstrap_error| {
                format!(
                    "HVM activation snapshot is neither operational ({operational_error}) nor canonical bootstrap ({bootstrap_error})"
                )
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{payment_operation_id, watchtower_operation_id};

    #[test]
    fn payment_label_is_stable_scoped_and_strict() {
        let binding_a = "11".repeat(32);
        let binding_b = "22".repeat(32);
        let first = payment_operation_id(&binding_a, "community-demo-1").unwrap();
        assert_eq!(
            first,
            payment_operation_id(&binding_a, "community-demo-1").unwrap()
        );
        assert_ne!(
            first,
            payment_operation_id(&binding_b, "community-demo-1").unwrap()
        );
        assert_ne!(
            first,
            payment_operation_id(&binding_a, "community-demo-2").unwrap()
        );
        assert!(payment_operation_id(&binding_a, "bad label").is_err());
        assert!(payment_operation_id(&binding_a, "").is_err());

        let challenge = watchtower_operation_id(&binding_a, "begin-challenge", "exit-1").unwrap();
        assert_eq!(
            challenge,
            watchtower_operation_id(&binding_a, "begin-challenge", "exit-1").unwrap()
        );
        assert_ne!(
            challenge,
            watchtower_operation_id(&binding_a, "monitor", "exit-1").unwrap()
        );
    }
}
