//! Read-only HPAY mainnet infrastructure preflight.
//!
//! This deliberately performs no signing, submission, wallet unlock or state
//! mutation. A PASS proves only that the live node, Hub and HVM deployment
//! satisfy the same infrastructure contracts used by the wallet. It does not
//! replace the subsequent small-value canary lifecycle.

use std::collections::BTreeMap;

use anyhow::{Context, Result, bail};
use field::Address;
use hacash_wallet_core::l2_hub::L2HubClient;
use hacash_wallet_core::node::NodeClient;
use hacash_wallet_core::node_capabilities::CapabilitySource;
use hacash_wallet_core::node_discovery::MAINNET_BLOCK_ONE_HASH;
use hacash_wallet_core::settings::{validate_service_url, validate_signing_node_url};
use serde_json::json;

const USAGE: &str = "usage: cargo run -p hacash-wallet-core --example hpay_mainnet_infrastructure_preflight -- --node-url <https://node> --hub-url <https://hub> --hub-address <Hacash address> --payment <HAC> --channel-funding <HAC>";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    node_url: String,
    hub_url: String,
    hub_address: String,
    payment: String,
    channel_funding: String,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Args> {
    let allowed = [
        "--node-url",
        "--hub-url",
        "--hub-address",
        "--payment",
        "--channel-funding",
    ];
    let mut input = args.into_iter();
    let mut values = BTreeMap::new();
    while let Some(flag) = input.next() {
        if flag == "--help" || flag == "-h" {
            bail!(USAGE);
        }
        if !allowed.contains(&flag.as_str()) {
            bail!("unknown argument {flag}; {USAGE}");
        }
        let value = input
            .next()
            .filter(|value| !value.is_empty() && !value.starts_with("--"))
            .with_context(|| format!("{flag} requires a value; {USAGE}"))?;
        if values.insert(flag.clone(), value).is_some() {
            bail!("duplicate argument {flag}");
        }
    }

    let mut required = |flag: &str| {
        values
            .remove(flag)
            .with_context(|| format!("missing {flag}; {USAGE}"))
    };
    Ok(Args {
        node_url: required("--node-url")?,
        hub_url: required("--hub-url")?,
        hub_address: required("--hub-address")?,
        payment: required("--payment")?,
        channel_funding: required("--channel-funding")?,
    })
}

fn require_hvm_node_capabilities(
    capabilities: &hacash_wallet_core::NodeCapabilities,
) -> Result<()> {
    if !capabilities.features.action_guard
        || !capabilities.features.hvm
        || !capabilities.features.contract_state_leasing
        || !capabilities.features.req_sign_list
        || !capabilities.supports_transaction(3)
        || !capabilities.supports_action(40)
        || !capabilities.supports_action(41)
        || !capabilities.supports_action(44)
    {
        bail!(
            "mainnet node does not report the complete HPAY HVM, leasing and ReqSignList contract"
        );
    }
    Ok(())
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = parse_args(std::env::args().skip(1))?;
    let node_url = validate_signing_node_url(&args.node_url, "mainnet")
        .context("mainnet signing-node transport is not safe")?;
    let hub_url = validate_service_url(&args.hub_url, "Fast Pay Hub")
        .context("mainnet Hub transport is not safe")?;
    let hub_address = Address::from_readable(&args.hub_address)
        .map_err(|_| anyhow::anyhow!("Hub address is not a valid Hacash address"))?;
    let canonical_hub_address = hub_address.to_readable();
    if canonical_hub_address != args.hub_address {
        bail!("Hub address is not in canonical readable form");
    }

    let node = NodeClient::new(node_url.clone())?;
    let capabilities = node.capabilities().await?;
    if capabilities.source != CapabilitySource::Reported
        || !capabilities.supports_agent_mainnet_payment(MAINNET_BLOCK_ONE_HASH)
    {
        bail!("mainnet node capability identity or freshness contract is not green");
    }
    require_hvm_node_capabilities(&capabilities)?;
    let block_one = node.block_intro(1).await?;
    if block_one.height != 1 || !block_one.hash.eq_ignore_ascii_case(MAINNET_BLOCK_ONE_HASH) {
        bail!("mainnet node block 1 does not match the canonical Hacash anchor");
    }

    let hub = L2HubClient::new_for_trusted_bounded_mainnet_pilot(hub_url.clone(), "mainnet");
    let health = hub
        .require_channel_binding_ready(&canonical_hub_address, &args.channel_funding)
        .await?;
    let readiness = hub
        .require_mainnet_payment_ready(Some(&args.payment))
        .await?;
    readiness.require_cooperative_close_ready(true)?;
    let hub_node = readiness
        .fullnode_capabilities
        .as_ref()
        .context("Hub readiness omitted fullnode capabilities")?;
    // The shared registry V2 profile: the contract every channel this wallet
    // opens actually lives in. This used to read the V1 per-channel evidence,
    // which is a different contract and would have passed a preflight for a
    // rail nobody uses.
    let hvm_evidence = hub_node
        .channel_registry_unilateral_exit_evidence
        .as_ref()
        .filter(|evidence| {
            hub_node.channel_registry_unilateral_exit && evidence.is_verified_mainnet_deployment()
        })
        .context("Hub did not publish a verified HPAY HVM shared-registry mainnet deployment")?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "hpay-mainnet-infrastructure-preflight/1",
            "status": "pass",
            "scope": "read_only_infrastructure_only",
            "release_ready": false,
            "next_required_gate": "small_value_mainnet_canary_open_pay_agent_pay_close",
            "node": {
                "url": node_url,
                "height": capabilities.chain.height,
                "network_instance_id": capabilities.network.instance_id,
                "block_1_hash": block_one.hash,
                "transaction_submit_bound": capabilities.api.transaction_submit_bound,
            },
            "hub": {
                "url": hub_url,
                "address": health.hub_address,
                "api_version": health.version,
                "deployment_profile": health.deployment_profile,
                "wallet_fee_hac": readiness.wallet_fee_hac,
                "payment_cap_hac_zhu": readiness.max_payment_hac_zhu,
                "channel_funding_cap_hac_zhu": readiness.max_channel_funding_hac_zhu,
            },
            "hvm": {
                "verified_mainnet_deployment": true,
                "contract_address": hvm_evidence.deployment.contract_address,
                "deployment_tx_hash": hvm_evidence.deployment.deployment_tx_hash,
                "deployment_height": hvm_evidence.deployment.deployment_height,
                "settlement_profile": hvm_evidence.settlement_profile,
                "contract_code_sha3": hvm_evidence.on_chain_verification.contract_code_sha3,
                "deploying_hub_address": hvm_evidence.on_chain_verification.hub_address,
                "constructor_network_instance_id":
                    hvm_evidence.on_chain_verification.constructor_network_instance_id,
            }
        }))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_arguments_are_required_and_duplicates_fail() {
        let parsed = parse_args(
            [
                "--node-url",
                "https://node.example",
                "--hub-url",
                "https://hub.example",
                "--hub-address",
                "1LFPqztfKhamVuzzV5WV6pHfykktGD5pMW",
                "--payment",
                "0.001",
                "--channel-funding",
                "1",
            ]
            .into_iter()
            .map(str::to_owned),
        )
        .unwrap();
        assert_eq!(parsed.payment, "0.001");
        assert!(parse_args(["--node-url", "a"].into_iter().map(str::to_owned)).is_err());
        assert!(
            parse_args(
                [
                    "--node-url",
                    "a",
                    "--node-url",
                    "b",
                    "--hub-url",
                    "c",
                    "--hub-address",
                    "d",
                    "--payment",
                    "1",
                    "--channel-funding",
                    "1",
                ]
                .into_iter()
                .map(str::to_owned),
            )
            .is_err()
        );
    }
}
