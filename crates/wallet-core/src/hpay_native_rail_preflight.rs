//! Read-only mainnet preflight for the NATIVE ChannelPay rail with a voucher.
//!
//! This is the check for the owner who has abandoned the HVM shared-registry
//! rail because deploying it costs roughly 2000 HAC. It reads the node, the
//! Hub and the Hub's own declaration, and it judges exactly the gates that
//! will run for real when money moves on the native rail:
//!
//! * a channel opened as `[ChainAllow 0x0411, ChannelOpen 2]` on Type 2, and
//! * one Hub-countersigned delta-zero voucher `[ChainAllow 0x0411,
//!   ChannelClose 3]` on Type 2, taken once and never refreshed.
//!
//! It deliberately does NOT require `features.hvm`,
//! `features.contract_state_leasing`, or actions 40/41/44. Those are HVM
//! contract primitives that only the registry rail needs. The only wallet gate
//! that reads them sits behind `MainnetFastPayPolicy::TrustlessOnly`
//! (`l2_hub.rs:484`), and this owner is on `TrustedBoundedPilot`, so that
//! clause never executes. Demanding them would send a ready owner shopping for
//! a node feature nothing on their path will ever read.
//!
//! NOTHING HERE SIGNS, UNLOCKS, MUTATES OR BROADCASTS. Every network call is a
//! GET. The voucher-route test is a GET against a POST-only path, which axum
//! answers with 405 and an `Allow` header without invoking the handler, so no
//! body is deserialised, no mutation permit is taken and no Hub state moves.
//!
//! A green report means the infrastructure answered correctly, read-only, at
//! one instant. It does not mean the money is safe, it does not make the pilot
//! trustless, and the Hub can still refuse to countersign afterwards. See
//! [`cannot_be_checked`], which is part of the report and belongs on screen.

use serde::{Deserialize, Serialize};

use crate::l2_hub::{
    DeclaredHubCaps, HubHealth, HubMainnetReadiness, L2HubClient, VoucherRouteProbe,
    hub_fee_is_zero,
};
use crate::node::{BlockIntroResponse, NodeClient};
use crate::node_capabilities::{CapabilitySource, NodeCapabilities, network_instance_id};
use crate::node_discovery::MAINNET_BLOCK_ONE_HASH;
use crate::settings::{validate_service_url, validate_signing_node_url};

pub const PREFLIGHT_SCHEMA: &str = "hpay-native-rail-mainnet-preflight/1";

/// The mainnet chain, which is the only chain this preflight judges against.
///
/// The identity item is a mainnet identity item: chain 0, height at or past the
/// pinned checkpoint, the compiled block-1 anchor. Pointed at the chain 7 pilot
/// node it fails, correctly and by design, because chain 7 is not mainnet.
const MAINNET_CHAIN_ID: u32 = 0;

/// Everything a fatal item can be: passed, refused, or never reached.
///
/// `Skip` exists because a Hub that will not answer leaves its own items
/// unjudged, and an unjudged fatal item is not a passed one. The verdict
/// treats `Skip` exactly as it treats `Fail`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Pass,
    Fail,
    Skip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckSeverity {
    /// Money must not move while this is anything other than `Pass`.
    Fatal,
    /// Worth seeing before funding. Never blocks the verdict.
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreflightVerdict {
    /// Every fatal item was reached and passed.
    Pass,
    /// At least one fatal item failed or was never reached.
    NotPass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightCheck {
    /// Stable identifier, for logs and for support conversations.
    pub id: String,
    /// What this item asks, in plain words.
    pub title: String,
    pub severity: CheckSeverity,
    pub status: CheckStatus,
    /// What was actually read off the wire, whatever the verdict.
    pub observed: String,
    /// The note that belongs beside this item: why it failed or was skipped,
    /// or, on a pass, the caveat that stops the pass being read as more than
    /// it is.
    pub reason: Option<String>,
}

impl PreflightCheck {
    fn new(
        id: &str,
        title: &str,
        severity: CheckSeverity,
        status: CheckStatus,
        observed: String,
        reason: Option<String>,
    ) -> Self {
        Self {
            id: id.to_owned(),
            title: title.to_owned(),
            severity,
            status,
            observed,
            reason,
        }
    }

    fn fatal_pass(id: &str, title: &str, observed: String) -> Self {
        Self::new(
            id,
            title,
            CheckSeverity::Fatal,
            CheckStatus::Pass,
            observed,
            None,
        )
    }

    fn fatal_fail(id: &str, title: &str, observed: String, reason: String) -> Self {
        Self::new(
            id,
            title,
            CheckSeverity::Fatal,
            CheckStatus::Fail,
            observed,
            Some(reason),
        )
    }

    fn fatal_skip(id: &str, title: &str, reason: String) -> Self {
        Self::new(
            id,
            title,
            CheckSeverity::Fatal,
            CheckStatus::Skip,
            "not reached".to_owned(),
            Some(reason),
        )
    }

    fn warning(
        id: &str,
        title: &str,
        status: CheckStatus,
        observed: String,
        reason: Option<String>,
    ) -> Self {
        Self::new(id, title, CheckSeverity::Warning, status, observed, reason)
    }

    fn fatal_from_refusals(id: &str, title: &str, observed: String, refusals: Vec<String>) -> Self {
        if refusals.is_empty() {
            Self::fatal_pass(id, title, observed)
        } else {
            Self::fatal_fail(id, title, observed, refusals.join("; "))
        }
    }
}

/// One thing a read-only preflight genuinely cannot establish.
///
/// Carried in the report rather than in a comment, because a person reading a
/// green screen has to be able to read these on the same screen. A PASS must
/// never be taken to imply any of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UncheckableFact {
    pub id: String,
    pub title: String,
    pub detail: String,
}

/// The six of them, as owned strings for the report.
pub fn cannot_be_checked() -> Vec<UncheckableFact> {
    CANNOT_BE_CHECKED
        .iter()
        .map(|fact| UncheckableFact {
            id: fact.id.to_owned(),
            title: fact.title.to_owned(),
            detail: fact.detail.to_owned(),
        })
        .collect()
}

struct StaticUncheckableFact {
    id: &'static str,
    title: &'static str,
    detail: &'static str,
}

const CANNOT_BE_CHECKED: [StaticUncheckableFact; 6] = [
    StaticUncheckableFact {
        id: "allowlist_membership",
        title: "Whether this address is on the Hub's list",
        detail: "The Hub publishes only that a list exists, never who is on it, and it is right \
                 not to. Membership is enforced inside a signed POST that this preflight is \
                 forbidden from sending. Expect \"mainnet pilot channel-open user is not \
                 allowlisted\" as a live possibility at your first open.",
    },
    StaticUncheckableFact {
        id: "hub_will_countersign",
        title: "Whether the Hub will actually countersign your voucher",
        detail: "The route probe proves the route exists. Nothing in Hacash can compel a second \
                 signature, so a Hub that answers the probe may still refuse the real request.",
    },
    StaticUncheckableFact {
        id: "aggregate_tvl_at_admission",
        title: "Whether the Hub's total exposure leaves room for your deposit",
        detail: "The aggregate cap is display only and produces no refusal here. The Hub \
                 re-checks its live total at admission against state this wallet cannot see, so a \
                 deposit inside the per-channel cap can still be refused for the Hub's total.",
    },
    StaticUncheckableFact {
        id: "pass_expires",
        title: "A pass expires in about five and a half minutes",
        detail: "The Hub's readiness document is valid for at most 330 seconds and is fetched and \
                 judged again at the signing boundary. A green preflight grants no later \
                 authority. Every gate here runs again for real when money moves.",
    },
    StaticUncheckableFact {
        id: "block_one_not_independent",
        title: "The block 1 cross-check is not independent proof",
        detail: "Both readings come from the same node, so it catches an inconsistent node, not a \
                 wholly fabricated chain. What makes the anchor real is that the expected block 1 \
                 hash is compiled into this wallet, not that it was fetched twice.",
    },
    StaticUncheckableFact {
        id: "owner_side",
        title: "Your own side of this",
        detail: "No read-only check proves you hold the deposit plus L1 fees, that your vault \
                 unlocks, that your signing key is present, or that this device will still have \
                 the voucher bytes in six months. The voucher is issued once per channel and \
                 never refreshed, so keeping it is yours to do.",
    },
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightRequest {
    pub node_url: String,
    pub hub_url: String,
    /// The Hub's on-chain address, as this wallet expects it.
    pub hub_address: String,
    /// The address that will own the channel and hold the voucher.
    pub owner_address: String,
    /// The deposit this owner intends to put in the channel, in HAC.
    pub channel_deposit_hac: String,
    /// The single payment this owner intends to make, in HAC.
    pub payment_hac: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightReport {
    pub schema: String,
    pub generated_unix: u64,
    pub node_url: String,
    pub hub_url: String,
    pub owner_address: String,
    pub hub_address: String,
    pub channel_deposit_hac: String,
    pub payment_hac: String,
    pub verdict: PreflightVerdict,
    pub fatal_failed: usize,
    pub fatal_skipped: usize,
    pub warnings: usize,
    /// How long a green verdict is worth, in seconds. The Hub's own window.
    pub validity_seconds: u64,
    pub checks: Vec<PreflightCheck>,
    /// What this Hub declared, for display beside the verdict.
    pub declared_caps: DeclaredHubCaps,
    pub cannot_be_checked: Vec<UncheckableFact>,
}

/// The one rule the whole surface hangs on.
///
/// A fatal item that was never reached is not a fatal item that passed. This
/// counts `Skip` and `Fail` identically on purpose: an unreachable Hub leaves
/// its items unjudged, and "unjudged" must not render as "fine".
///
/// A run with no fatal items in it is also not a pass. Nothing failed only
/// because nothing was asked, and "nothing was asked" is the emptiest possible
/// case of the same mistake.
pub fn verdict_for(checks: &[PreflightCheck]) -> PreflightVerdict {
    let mut fatal_items = 0usize;
    for check in checks {
        if check.severity != CheckSeverity::Fatal {
            continue;
        }
        fatal_items += 1;
        if check.status != CheckStatus::Pass {
            return PreflightVerdict::NotPass;
        }
    }
    if fatal_items == 0 {
        return PreflightVerdict::NotPass;
    }
    PreflightVerdict::Pass
}

fn count(checks: &[PreflightCheck], severity: CheckSeverity, status: CheckStatus) -> usize {
    checks
        .iter()
        .filter(|check| check.severity == severity && check.status == status)
        .count()
}

/// Everything read off the wire, before a single judgement is made.
///
/// Split out so every fatal path in [`judge`] is reachable from a unit test
/// with no HTTP, no node and no Hub. Each field is either what the endpoint
/// answered or the reason it did not.
#[derive(Debug, Clone)]
pub struct PreflightObservations {
    /// The normalized signing-node URL, or why the transport is refused.
    pub signing_transport: Result<String, String>,
    /// The normalized Hub URL, or why the transport is refused.
    pub hub_transport: Result<String, String>,
    pub capabilities: Result<NodeCapabilities, String>,
    pub block_one: Result<BlockIntroResponse, String>,
    pub health: Result<HubHealth, String>,
    pub readiness: Result<HubMainnetReadiness, String>,
    /// The same readiness fetch, undecoded, for fields the typed struct does
    /// not carry. `allowlist_configured` is the one that matters.
    pub readiness_raw: Option<serde_json::Value>,
    pub voucher_route: Result<VoucherRouteProbe, String>,
    /// The wallet's own clock at the moment the Hub document was read.
    pub observed_unix: u64,
}

/// Read every endpoint this preflight judges. Reads only.
pub async fn observe(request: &PreflightRequest) -> PreflightObservations {
    let signing_transport =
        validate_signing_node_url(&request.node_url, "mainnet").map_err(|error| error.to_string());
    let hub_transport =
        validate_service_url(&request.hub_url, "Fast Pay Hub").map_err(|error| error.to_string());

    let (capabilities, block_one) = match signing_transport.as_ref() {
        Ok(url) => match NodeClient::new(url.clone()) {
            Ok(node) => (
                node.capabilities().await.map_err(|e| e.to_string()),
                node.block_intro(1).await.map_err(|e| e.to_string()),
            ),
            Err(error) => {
                let error = error.to_string();
                (Err(error.clone()), Err(error))
            }
        },
        Err(error) => (Err(error.clone()), Err(error.clone())),
    };

    let (health, readiness, readiness_raw, voucher_route) = match hub_transport.as_ref() {
        Ok(url) => {
            // The bounded-pilot client, because that is the policy this owner
            // consented to. It changes nothing here: every call below is a GET.
            let hub = L2HubClient::new_for_trusted_bounded_mainnet_pilot(url.clone(), "mainnet");
            let health = hub.health().await.map_err(|e| e.to_string());
            let (readiness, raw) = match hub.mainnet_readiness_with_raw().await {
                Ok((readiness, raw)) => (Ok(readiness), Some(raw)),
                Err(error) => (Err(error.to_string()), None),
            };
            let probe = hub
                .probe_channel_close_voucher_route()
                .await
                .map_err(|e| e.to_string());
            (health, readiness, raw, probe)
        }
        Err(error) => (
            Err(error.clone()),
            Err(error.clone()),
            None,
            Err(error.clone()),
        ),
    };

    PreflightObservations {
        signing_transport,
        hub_transport,
        capabilities,
        block_one,
        health,
        readiness,
        readiness_raw,
        voucher_route,
        observed_unix: crate::l2_hub::unix_now(),
    }
}

/// Read everything, then judge it.
pub async fn run_preflight(request: &PreflightRequest) -> PreflightReport {
    let observations = observe(request).await;
    judge(request, &observations)
}

pub fn judge(request: &PreflightRequest, observed: &PreflightObservations) -> PreflightReport {
    // The order is the reading order on the screen: your transport, then your
    // node, then the Hub, then the exact bytes this wallet would send.
    let checks = vec![
        check_signing_transport(observed),
        check_voucher_parties(request),
        check_node_identity(observed),
        check_block_one(observed),
        check_tip_freshness(observed),
        check_node_action_set(observed),
        check_registry_rail_is_not_required(observed),
        check_node_api_surface(observed),
        check_hub_open_ready(request, observed),
        check_hub_voucher_ready(request, observed),
        check_voucher_route_exists(observed),
        check_readiness_document(observed),
        check_declared_caps(request, observed),
        check_hub_fullnode(observed),
        check_hub_fullnode_instance(observed),
        check_hub_blockers(observed),
        check_disclosed_gaps(observed),
        check_allowlist_configured(observed),
        check_network_binding_and_voucher_shape(observed),
    ];

    let declared_caps = observed
        .readiness
        .as_ref()
        .map(HubMainnetReadiness::declared_caps_hac)
        .unwrap_or_default();

    PreflightReport {
        schema: PREFLIGHT_SCHEMA.to_owned(),
        generated_unix: observed.observed_unix,
        node_url: request.node_url.clone(),
        hub_url: request.hub_url.clone(),
        owner_address: request.owner_address.clone(),
        hub_address: request.hub_address.clone(),
        channel_deposit_hac: request.channel_deposit_hac.clone(),
        payment_hac: request.payment_hac.clone(),
        verdict: verdict_for(&checks),
        fatal_failed: count(&checks, CheckSeverity::Fatal, CheckStatus::Fail),
        fatal_skipped: count(&checks, CheckSeverity::Fatal, CheckStatus::Skip),
        warnings: checks
            .iter()
            .filter(|check| {
                check.severity == CheckSeverity::Warning && check.status != CheckStatus::Pass
            })
            .count(),
        validity_seconds: crate::l2_hub::MAX_READINESS_VALIDITY_SECONDS,
        checks,
        declared_caps,
        cannot_be_checked: cannot_be_checked(),
    }
}

// ---------------------------------------------------------------- node items

const TITLE_TRANSPORT: &str = "The connection to your node is one this wallet will sign against";

fn check_signing_transport(observed: &PreflightObservations) -> PreflightCheck {
    // Deliberately the predicate itself and not a copy of its rule. A
    // hand-rolled string test for "127.0.0.1" misses ::1, 127.0.0.2 and
    // "localhost"; a hand-rolled HTTPS test misses that validate_node_url runs
    // first. Loopback HTTP is allowed on purpose, so a node on this same
    // device passes.
    match observed.signing_transport.as_ref() {
        Ok(url) => PreflightCheck::fatal_pass(
            "signing_transport",
            TITLE_TRANSPORT,
            format!("accepted for mainnet signing: {url}"),
        ),
        Err(error) => PreflightCheck::fatal_fail(
            "signing_transport",
            TITLE_TRANSPORT,
            "refused".to_owned(),
            error.clone(),
        ),
    }
}

const TITLE_PARTIES: &str = "Your address and the Hub's address are two different real addresses";

fn check_voucher_parties(request: &PreflightRequest) -> PreflightCheck {
    let mut refusals = Vec::new();
    let owner = field::Address::from_readable(&request.owner_address);
    let hub = field::Address::from_readable(&request.hub_address);
    match owner.as_ref() {
        Ok(address) if address.to_readable() == request.owner_address => {}
        Ok(_) => refusals.push("your address is not in canonical readable form".to_owned()),
        Err(_) => refusals.push("your address is not a valid Hacash address".to_owned()),
    }
    match hub.as_ref() {
        Ok(address) if address.to_readable() == request.hub_address => {}
        Ok(_) => refusals.push("the Hub address is not in canonical readable form".to_owned()),
        Err(_) => refusals.push("the Hub address is not a valid Hacash address".to_owned()),
    }
    if request.owner_address == request.hub_address {
        refusals.push("your address and the Hub address are the same".to_owned());
    }
    PreflightCheck::fatal_from_refusals(
        "voucher_parties",
        TITLE_PARTIES,
        format!(
            "you: {}, Hub: {}",
            request.owner_address, request.hub_address
        ),
        refusals,
    )
}

const TITLE_IDENTITY: &str = "The node is really Hacash mainnet, worked out from the chain itself";

fn check_node_identity(observed: &PreflightObservations) -> PreflightCheck {
    let capabilities = match observed.capabilities.as_ref() {
        Ok(capabilities) => capabilities,
        Err(error) => {
            return PreflightCheck::fatal_skip("node_identity", TITLE_IDENTITY, error.clone());
        }
    };
    // One call, not a restatement of its clauses. The load-bearing one is the
    // instance id: it is a hash over the anchor, so a node claiming mainnet
    // with any other block 1 cannot forge it.
    let identity_ok = capabilities.source == CapabilitySource::Reported
        && capabilities.supports_agent_mainnet_payment(MAINNET_BLOCK_ONE_HASH);
    let expected_instance = network_instance_id(
        &capabilities.network.kind,
        capabilities.chain.id,
        capabilities.chain.mainnet,
        MAINNET_BLOCK_ONE_HASH,
        &capabilities.network.node_profile_id,
        capabilities.network.transaction_format_version,
    );
    let observed_text = format!(
        "chain id {}, mainnet {}, height {}, network kind \"{}\", profile \"{}\", block 1 {}, \
         instance id {}, tx format {}, transaction_ready {}",
        capabilities.chain.id,
        capabilities.chain.mainnet,
        capabilities.chain.height,
        capabilities.network.kind,
        capabilities.network.node_profile_id,
        capabilities
            .network
            .block_1_hash
            .as_deref()
            .unwrap_or("absent"),
        capabilities
            .network
            .instance_id
            .as_deref()
            .unwrap_or("absent"),
        capabilities.network.transaction_format_version,
        capabilities.network.transaction_ready,
    );
    if identity_ok {
        PreflightCheck::fatal_pass("node_identity", TITLE_IDENTITY, observed_text)
    } else {
        PreflightCheck::fatal_fail(
            "node_identity",
            TITLE_IDENTITY,
            observed_text,
            format!(
                "this node does not answer as Hacash mainnet. Mainnet is chain 0 with block 1 \
                 {MAINNET_BLOCK_ONE_HASH} and network instance id {expected_instance} recomputed \
                 from that anchor"
            ),
        )
    }
}

const TITLE_BLOCK_ONE: &str =
    "Block 1 read from the chain store matches the anchor built into this wallet";

fn check_block_one(observed: &PreflightObservations) -> PreflightCheck {
    let block_one = match observed.block_one.as_ref() {
        Ok(block_one) => block_one,
        Err(error) => {
            return PreflightCheck::fatal_skip("block_one", TITLE_BLOCK_ONE, error.clone());
        }
    };
    // The SAME node answering a second time on a different route. It catches a
    // node whose capability block was hand-edited while its chain store was
    // not. It is a consistency check, not independent proof.
    let observed_text = format!(
        "/query/block/intro?height=1 returned height {} hash {} (same node, second route)",
        block_one.height, block_one.hash
    );
    if block_one.height == 1 && block_one.hash.eq_ignore_ascii_case(MAINNET_BLOCK_ONE_HASH) {
        PreflightCheck::fatal_pass("block_one", TITLE_BLOCK_ONE, observed_text)
    } else {
        PreflightCheck::fatal_fail(
            "block_one",
            TITLE_BLOCK_ONE,
            observed_text,
            format!("the Hacash mainnet anchor is block 1 {MAINNET_BLOCK_ONE_HASH}"),
        )
    }
}

const TITLE_FRESH: &str = "The node's newest block is recent, checked against two separate clocks";

fn check_tip_freshness(observed: &PreflightObservations) -> PreflightCheck {
    let capabilities = match observed.capabilities.as_ref() {
        Ok(capabilities) => capabilities,
        Err(error) => {
            return PreflightCheck::fatal_skip("tip_freshness", TITLE_FRESH, error.clone());
        }
    };
    let sync = &capabilities.sync;
    let max = crate::node_capabilities::MAX_MAINNET_TIP_AGE_SECONDS;
    let skew = crate::node_capabilities::MAX_FUTURE_TIP_SKEW_SECONDS;
    let node_age = sync.observed_unix.saturating_sub(sync.tip_timestamp_unix);
    let local_age = observed
        .observed_unix
        .saturating_sub(sync.tip_timestamp_unix);
    let observed_text = format!(
        "tip timestamp {}, node clock {} (age {node_age}s), this device's clock {} (age \
         {local_age}s), node declares fresh {} against its own bound of {}s; the wallet's bound is \
         {max}s",
        sync.tip_timestamp_unix,
        sync.observed_unix,
        observed.observed_unix,
        sync.fresh,
        sync.max_tip_age_seconds,
    );
    let mut refusals = Vec::new();
    if sync.max_tip_age_seconds == 0 || sync.max_tip_age_seconds > max {
        refusals.push(format!(
            "the node declares a staleness bound of {}s; a node may not widen its own window past \
             {max}s",
            sync.max_tip_age_seconds
        ));
    }
    if sync.tip_age_seconds != node_age {
        refusals
            .push("the node's declared tip age does not match its own two timestamps".to_owned());
    }
    if !sync.fresh {
        refusals.push("the node itself reports its tip is not fresh".to_owned());
    }
    if node_age > max {
        refusals.push(format!(
            "against the node's own clock the tip is {node_age}s old, past the {max}s bound"
        ));
    }
    // The second clock. A node with a slow clock cannot launder a stale tip
    // past a wallet that measures the same tip against its own time.
    if local_age > max {
        refusals.push(format!(
            "against this device's clock the tip is {local_age}s old, past the {max}s bound"
        ));
    }
    if sync.tip_timestamp_unix > observed.observed_unix.saturating_add(skew) {
        refusals.push(format!(
            "the tip is dated more than {skew}s in the future of this device's clock"
        ));
    }
    PreflightCheck::fatal_from_refusals("tip_freshness", TITLE_FRESH, observed_text, refusals)
}

const TITLE_ACTIONS: &str =
    "The node accepts exactly the transaction and action kinds the open and the voucher contain";

fn check_node_action_set(observed: &PreflightObservations) -> PreflightCheck {
    let capabilities = match observed.capabilities.as_ref() {
        Ok(capabilities) => capabilities,
        Err(error) => {
            return PreflightCheck::fatal_skip("node_action_set", TITLE_ACTIONS, error.clone());
        }
    };
    // Read off the two builders, not assumed:
    //   open    = Type 2, [ChainAllow 0x0411, ChannelOpen 2]
    //   voucher = Type 2, [ChainAllow 0x0411, ChannelClose 3], delta zero
    //   a close carrying a real delta appends HacFromToTrs 14
    let mut refusals = Vec::new();
    if !capabilities.supports_transaction(2) {
        refusals.push("Type 2 transactions are not enabled".to_owned());
    }
    for (kind, what) in [
        (1u16, "HacFromTrs 1"),
        (2, "ChannelOpen 2"),
        (3, "ChannelClose 3"),
        (14, "HacFromToTrs 14"),
        (0x0411, "ChainAllow 0x0411"),
    ] {
        if !capabilities.supports_action(kind) {
            refusals.push(format!("action {what} is not enabled"));
        }
    }
    // Kept from the old check, but for a different reason than the old check
    // gave: action_guard is what makes 0x0411 legal at all, and 0x0411 is in
    // every transaction this design signs.
    if !capabilities.features.action_guard {
        refusals.push(
            "features.action_guard is off, which is what makes ChainAllow 0x0411 legal".to_owned(),
        );
    }
    let observed_text = format!(
        "transactions enabled {:?}; actions 1 {}, 2 {}, 3 {}, 14 {}, 0x0411 {}; action_guard {}",
        capabilities.transactions.enabled,
        capabilities.supports_action(1),
        capabilities.supports_action(2),
        capabilities.supports_action(3),
        capabilities.supports_action(14),
        capabilities.supports_action(0x0411),
        capabilities.features.action_guard,
    );
    PreflightCheck::fatal_from_refusals("node_action_set", TITLE_ACTIONS, observed_text, refusals)
}

const TITLE_REGISTRY_RAIL: &str =
    "The registry-rail contract features are NOT required on your path";

fn check_registry_rail_is_not_required(observed: &PreflightObservations) -> PreflightCheck {
    let detail = match observed.capabilities.as_ref() {
        Ok(capabilities) => format!(
            "for information only: this node reports hvm {}, contract_state_leasing {}, actions 40 \
             {}, 41 {}, 44 {}. None of these is read by any gate on the native rail",
            capabilities.features.hvm,
            capabilities.features.contract_state_leasing,
            capabilities.supports_action(40),
            capabilities.supports_action(41),
            capabilities.supports_action(44),
        ),
        Err(_) => "for information only: the node was not readable, and none of these would have \
                   been required anyway"
            .to_owned(),
    };
    PreflightCheck::warning(
        "registry_rail_not_required",
        TITLE_REGISTRY_RAIL,
        CheckStatus::Pass,
        detail,
        Some(
            "The old preflight demanded features.hvm, contract_state_leasing and actions 40/41/44. \
             Those belong to the HVM shared-registry contract, which costs roughly 2000 HAC to \
             deploy and which you are not using. The only wallet gate that reads them runs under \
             the trustless-only policy, and you are on the bounded pilot, so it never runs. \
             Nothing refuses without them."
                .to_owned(),
        ),
    )
}

const TITLE_API: &str = "The node exposes the routes this wallet's submit path uses";

fn check_node_api_surface(observed: &PreflightObservations) -> PreflightCheck {
    let capabilities = match observed.capabilities.as_ref() {
        Ok(capabilities) => capabilities,
        Err(error) => {
            return PreflightCheck::fatal_skip("node_api_surface", TITLE_API, error.clone());
        }
    };
    let api = capabilities.api;
    let mut refusals = Vec::new();
    for (present, name) in [
        (api.balance_query, "balance_query"),
        (api.transaction_submit, "transaction_submit"),
        // Named out loud: this wallet submits bound, so a node with plain
        // submit only is refused.
        (api.transaction_submit_bound, "transaction_submit_bound"),
        (api.transaction_query, "transaction_query"),
        (api.reconciliation_by_tx_hash, "reconciliation_by_tx_hash"),
    ] {
        if !present {
            refusals.push(format!("{name} is not available"));
        }
    }
    let observed_text = format!(
        "balance_query {}, transaction_submit {}, transaction_submit_bound {}, transaction_query \
         {}, reconciliation_by_tx_hash {}",
        api.balance_query,
        api.transaction_submit,
        api.transaction_submit_bound,
        api.transaction_query,
        api.reconciliation_by_tx_hash,
    );
    PreflightCheck::fatal_from_refusals("node_api_surface", TITLE_API, observed_text, refusals)
}

// ----------------------------------------------------------------- hub items

const TITLE_HUB_OPEN: &str = "The Hub answers, and says it can take a channel open";

fn check_hub_open_ready(
    request: &PreflightRequest,
    observed: &PreflightObservations,
) -> PreflightCheck {
    let health = match observed.health.as_ref() {
        Ok(health) => health,
        Err(error) => {
            return PreflightCheck::fatal_skip("hub_open_ready", TITLE_HUB_OPEN, error.clone());
        }
    };
    let mut refusals = Vec::new();
    if !health.ok {
        refusals.push("the Hub reports itself not ok".to_owned());
    }
    if health.version < 7 {
        refusals.push(format!(
            "the Hub speaks API version {}, not 7 or later",
            health.version
        ));
    }
    if !health.settlement_ready {
        refusals.push("settlement_ready is false".to_owned());
    }
    if !health.cross_channel_ready {
        refusals.push("cross_channel_ready is false".to_owned());
    }
    if !hub_fee_is_zero(health) {
        refusals.push("the Hub did not declare an exactly zero fee".to_owned());
    }
    if !health.trusted_bounded_pilot_ready {
        refusals.push("trusted_bounded_pilot_ready is false".to_owned());
    }
    if health.deployment_profile.as_deref() != Some(crate::l2_hub::MAINNET_BOUNDED_PILOT_PROFILE) {
        refusals.push(format!(
            "the Hub publishes deployment profile \"{}\", not \"{}\"",
            health.deployment_profile.as_deref().unwrap_or("none"),
            crate::l2_hub::MAINNET_BOUNDED_PILOT_PROFILE
        ));
    }
    match health.hub_address.as_deref().filter(|a| !a.is_empty()) {
        None => refusals.push("the Hub did not publish an on-chain address".to_owned()),
        Some(published) => {
            if published != request.hub_address {
                refusals.push(format!(
                    "the Hub publishes address {published}, and this wallet expects {}",
                    request.hub_address
                ));
            }
        }
    }
    let observed_text = format!(
        "ok {}, version {}, settlement_ready {}, cross_channel_ready {}, fee {}, \
         trusted_bounded_pilot_ready {}, profile {:?}, address {:?}",
        health.ok,
        health.version,
        health.settlement_ready,
        health.cross_channel_ready,
        crate::l2_hub::hub_fee_label(health).unwrap_or_else(|| "unpublished".to_owned()),
        health.trusted_bounded_pilot_ready,
        health.deployment_profile,
        health.hub_address,
    );
    PreflightCheck::fatal_from_refusals("hub_open_ready", TITLE_HUB_OPEN, observed_text, refusals)
}

const TITLE_HUB_VOUCHER: &str =
    "The Hub is ready to hand over a voucher, checked BEFORE your deposit goes in";

fn check_hub_voucher_ready(
    request: &PreflightRequest,
    observed: &PreflightObservations,
) -> PreflightCheck {
    // This is the item that closes the hostage window, and it is a different
    // flag set from the open. `take_l2_channel_close_voucher` refuses unless a
    // binding already exists and is active, so the voucher can only be TAKEN
    // after funding. Every flag its gate reads is readable now, before a
    // single zhu moves, so read them now.
    let health = match observed.health.as_ref() {
        Ok(health) => health,
        Err(error) => {
            return PreflightCheck::fatal_skip(
                "hub_voucher_ready",
                TITLE_HUB_VOUCHER,
                error.clone(),
            );
        }
    };
    let mut refusals = Vec::new();
    if !health.ok {
        refusals.push("the Hub reports itself not ok".to_owned());
    }
    if health.version < 7 {
        refusals.push(format!(
            "the Hub speaks API version {}, not 7 or later",
            health.version
        ));
    }
    if !health.settlement_ready {
        refusals.push("settlement_ready is false".to_owned());
    }
    // NOT cross_channel_ready. A Hub can publish one and not the other, and
    // the close path reads this one.
    if !health.official_channelpay_ready {
        refusals.push(
            "official_channelpay_ready is false, which is the flag the close path reads".to_owned(),
        );
    }
    if !hub_fee_is_zero(health) {
        refusals.push("the Hub did not declare an exactly zero fee".to_owned());
    }
    if health.hub_address.as_deref() != Some(request.hub_address.as_str()) {
        refusals.push(format!(
            "the Hub publishes address {:?}, and this wallet expects {}",
            health.hub_address, request.hub_address
        ));
    }
    let mut observed_text = format!(
        "official_channelpay_ready {}, settlement_ready {}, version {}",
        health.official_channelpay_ready, health.settlement_ready, health.version
    );
    match observed.readiness.as_ref() {
        Ok(readiness) => {
            observed_text.push_str(&format!(
                ", close_enabled {}, close_blockers {:?}",
                readiness.close_enabled, readiness.close_blockers
            ));
            if !readiness.close_enabled {
                refusals.push("the Hub reports close_enabled false".to_owned());
            }
            if !readiness.close_blockers.is_empty() {
                refusals.push(format!(
                    "the Hub published close blockers: {}",
                    readiness.close_blockers.join(", ")
                ));
            }
        }
        Err(error) => {
            observed_text.push_str(", readiness document unreadable");
            refusals.push(format!(
                "the Hub's readiness document could not be read, so close_enabled and \
                 close_blockers are unknown: {error}"
            ));
        }
    }
    PreflightCheck::fatal_from_refusals(
        "hub_voucher_ready",
        TITLE_HUB_VOUCHER,
        observed_text,
        refusals,
    )
}

const TITLE_VOUCHER_ROUTE: &str = "This Hub has a close-voucher route at all";

fn check_voucher_route_exists(observed: &PreflightObservations) -> PreflightCheck {
    // Nothing the Hub publishes answers this: API version 7 is 7 for a
    // voucher-capable Hub and an older one alike, and health carries no flag.
    // So the only read-only test is whether the path is registered. GET, never
    // POST: axum answers a registered path with an unregistered method as 405
    // plus Allow, without invoking the handler.
    let probe = match observed.voucher_route.as_ref() {
        Ok(probe) => probe,
        Err(error) => {
            return PreflightCheck::fatal_skip("voucher_route", TITLE_VOUCHER_ROUTE, error.clone());
        }
    };
    let observed_text = format!(
        "GET /v1/l1/channel/close-voucher answered {} with Allow: {}",
        probe.status,
        probe.allow.as_deref().unwrap_or("(none)")
    );
    if probe.status == 405 || probe.allows_post() {
        PreflightCheck::fatal_pass("voucher_route", TITLE_VOUCHER_ROUTE, observed_text)
    } else if probe.status == 404 {
        PreflightCheck::fatal_fail(
            "voucher_route",
            TITLE_VOUCHER_ROUTE,
            observed_text,
            "this Hub has no close-voucher route, so it is an older build. Do not fund it: the \
             voucher can only be taken after the deposit is on chain, and this Hub would not be \
             able to issue one."
                .to_owned(),
        )
    } else {
        // Unproven is not a pass.
        PreflightCheck::fatal_fail(
            "voucher_route",
            TITLE_VOUCHER_ROUTE,
            observed_text,
            "this answer neither proves nor disproves the route. Unproven is not a pass, so this \
             stays red."
                .to_owned(),
        )
    }
}

const TITLE_READINESS: &str =
    "The Hub's readiness document is the right kind, the right profile, and not expired";

fn check_readiness_document(observed: &PreflightObservations) -> PreflightCheck {
    let readiness = match observed.readiness.as_ref() {
        Ok(readiness) => readiness,
        Err(error) => {
            return PreflightCheck::fatal_skip(
                "readiness_document",
                TITLE_READINESS,
                error.clone(),
            );
        }
    };
    let now = observed.observed_unix;
    let max_validity = crate::l2_hub::MAX_READINESS_VALIDITY_SECONDS;
    let skew = crate::l2_hub::MAX_FUTURE_SKEW_SECONDS;
    let mut refusals = Vec::new();
    if readiness.schema != crate::l2_hub::MAINNET_READINESS_SCHEMA {
        refusals.push(format!(
            "the document is schema \"{}\", not \"{}\"",
            readiness.schema,
            crate::l2_hub::MAINNET_READINESS_SCHEMA
        ));
    }
    if !readiness.payments_enabled {
        refusals.push("payments_enabled is false".to_owned());
    }
    match readiness.mainnet_detected {
        Some(true) => {}
        Some(false) => refusals.push("the Hub reports it is not connected to mainnet".to_owned()),
        None => refusals
            .push("the Hub could not work out whether it is connected to mainnet".to_owned()),
    }
    if readiness.profile != crate::l2_hub::MAINNET_BOUNDED_PILOT_PROFILE
        || !readiness.trusted_bounded_pilot
    {
        refusals.push(format!(
            "the Hub publishes profile \"{}\" with trusted_bounded_pilot {}, and you consented to \
             the bounded pilot",
            readiness.profile, readiness.trusted_bounded_pilot
        ));
    }
    let window = readiness
        .valid_until_unix
        .checked_sub(readiness.evaluated_unix);
    match window {
        Some(seconds) if seconds <= max_validity => {}
        Some(seconds) => refusals.push(format!(
            "the Hub claims this document is good for {seconds}s, past the {max_validity}s maximum"
        )),
        None => refusals.push("the document expires before it was evaluated".to_owned()),
    }
    if readiness.evaluated_unix > now.saturating_add(skew) {
        refusals.push(format!(
            "the document is dated more than {skew}s in the future of this device's clock"
        ));
    }
    if now > readiness.valid_until_unix {
        refusals.push("the document has already expired".to_owned());
    }
    let observed_text = format!(
        "schema \"{}\", profile \"{}\", trusted_bounded_pilot {}, payments_enabled {}, \
         mainnet_detected {}, evaluated {} valid until {} ({} of at most {max_validity}s), this \
         device's clock {now}",
        readiness.schema,
        readiness.profile,
        readiness.trusted_bounded_pilot,
        readiness.payments_enabled,
        // Plain words rather than a Rust Option. "None" on a screen reads as
        // the Hub answering "no"; it actually means the Hub could not tell.
        match readiness.mainnet_detected {
            Some(true) => "yes",
            Some(false) => "no",
            None => "the Hub could not tell",
        },
        readiness.evaluated_unix,
        readiness.valid_until_unix,
        window.map_or_else(|| "invalid window".to_owned(), |s| format!("{s}s")),
    );
    PreflightCheck::fatal_from_refusals(
        "readiness_document",
        TITLE_READINESS,
        observed_text,
        refusals,
    )
}

const TITLE_CAPS: &str = "The Hub's own declared caps admit this deposit and this payment";

fn amount_zhu(wire: &str) -> Result<u64, String> {
    let amount = l2_fast_pay_hub::amount::parse_amount_mei(wire).map_err(|e| e.to_string())?;
    amount
        .as_millimeis()
        .checked_mul(crate::l2_hub::ZHU_PER_MILLIMEI)
        .ok_or_else(|| format!("{wire} HAC is larger than this wallet can represent in zhu"))
}

fn check_declared_caps(
    request: &PreflightRequest,
    observed: &PreflightObservations,
) -> PreflightCheck {
    let readiness = match observed.readiness.as_ref() {
        Ok(readiness) => readiness,
        Err(error) => {
            return PreflightCheck::fatal_skip("declared_caps", TITLE_CAPS, error.clone());
        }
    };
    // The Hub's numbers, judged against the Hub's own declaration. This build's
    // ceilings are printed beside them and never in place of them.
    let caps = readiness.declared_caps_hac();
    let mut refusals = Vec::new();
    match amount_zhu(&request.payment_hac) {
        Ok(zhu) if zhu <= readiness.max_payment_hac_zhu => {}
        Ok(zhu) => refusals.push(format!(
            "your {} HAC payment is {zhu} zhu and this Hub declares a per-payment cap of {} zhu",
            request.payment_hac, readiness.max_payment_hac_zhu
        )),
        Err(error) => refusals.push(format!("the payment amount could not be read: {error}")),
    }
    match amount_zhu(&request.channel_deposit_hac) {
        Ok(zhu) if zhu <= readiness.max_channel_funding_hac_zhu => {}
        Ok(zhu) => refusals.push(format!(
            "your {} HAC deposit is {zhu} zhu and this Hub declares a per-channel cap of {} zhu",
            request.channel_deposit_hac, readiness.max_channel_funding_hac_zhu
        )),
        Err(error) => refusals.push(format!("the deposit amount could not be read: {error}")),
    }
    // And the caps must themselves be sane against this build's ceilings.
    if readiness.max_payment_hac_zhu < crate::l2_hub::ZHU_PER_MILLIMEI
        || readiness.max_payment_hac_zhu > crate::l2_hub::MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU
    {
        refusals.push(format!(
            "this Hub's per-payment cap of {} zhu is below wallet precision or past this build's \
             ceiling of {} zhu",
            readiness.max_payment_hac_zhu,
            crate::l2_hub::MAINNET_PILOT_HARD_MAX_PAYMENT_HAC_ZHU
        ));
    }
    if readiness.max_channel_funding_hac_zhu < crate::l2_hub::ZHU_PER_MILLIMEI
        || readiness.max_channel_funding_hac_zhu
            > crate::l2_hub::MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU
    {
        refusals.push(format!(
            "this Hub's per-channel cap of {} zhu is below wallet precision or past this build's \
             ceiling of {} zhu",
            readiness.max_channel_funding_hac_zhu,
            crate::l2_hub::MAINNET_PILOT_HARD_MAX_CHANNEL_FUNDING_HAC_ZHU
        ));
    }
    let observed_text = format!(
        "this Hub declares: per payment {} HAC, per channel {} HAC, total across all channels {}. \
         You asked for a {} HAC deposit and a {} HAC payment. This build's ceilings, for \
         comparison only, are 1 HAC per payment and 10 HAC per channel",
        caps.max_payment_hac.as_deref().unwrap_or("not declared"),
        caps.max_channel_funding_hac
            .as_deref()
            .unwrap_or("not declared"),
        caps.max_aggregate_tvl_hac
            .as_deref()
            .map(|value| format!("{value} HAC"))
            .unwrap_or_else(|| "not declared".to_owned()),
        request.channel_deposit_hac,
        request.payment_hac,
    );
    PreflightCheck::fatal_from_refusals("declared_caps", TITLE_CAPS, observed_text, refusals)
}

const TITLE_HUB_NODE: &str =
    "The Hub's own full node agrees with the chain you are signing against";

fn check_hub_fullnode(observed: &PreflightObservations) -> PreflightCheck {
    let readiness = match observed.readiness.as_ref() {
        Ok(readiness) => readiness,
        Err(error) => {
            return PreflightCheck::fatal_skip("hub_fullnode", TITLE_HUB_NODE, error.clone());
        }
    };
    let Some(node) = readiness.fullnode_capabilities.as_ref() else {
        return PreflightCheck::fatal_fail(
            "hub_fullnode",
            TITLE_HUB_NODE,
            "the readiness document carries no fullnode_capabilities".to_owned(),
            "this Hub did not publish what its own node reports, so there is nothing to compare"
                .to_owned(),
        );
    };
    let now = observed.observed_unix;
    let max_age = crate::l2_hub::MAX_TIP_AGE_SECONDS;
    let skew = crate::l2_hub::MAX_FUTURE_SKEW_SECONDS;
    let reported_age = node.observed_unix.saturating_sub(node.tip_timestamp_unix);
    let local_age = now.saturating_sub(node.tip_timestamp_unix);
    let mut refusals = Vec::new();
    if node.observed_unix != readiness.evaluated_unix {
        refusals.push(
            "the Hub measured its node at a different moment than it wrote this document"
                .to_owned(),
        );
    }
    if node.api_version != 1 {
        refusals.push(format!(
            "the Hub's node speaks capability API {}",
            node.api_version
        ));
    }
    if node.chain_id != MAINNET_CHAIN_ID || !node.mainnet {
        refusals.push(format!(
            "the Hub's node is on chain {} with mainnet {}",
            node.chain_id, node.mainnet
        ));
    }
    if node.height < crate::l2_hub::MAINNET_MIN_SAFE_HEIGHT {
        refusals.push(format!(
            "the Hub's node is at height {}, below the pinned checkpoint of {}",
            node.height,
            crate::l2_hub::MAINNET_MIN_SAFE_HEIGHT
        ));
    }
    if node.height.checked_add(1) != Some(node.next_height) {
        refusals.push("the Hub's node reports an inconsistent next height".to_owned());
    }
    if node.tip_timestamp_unix > node.observed_unix.saturating_add(skew) {
        refusals.push(format!(
            "the Hub's node tip is more than {skew}s in the future of the Hub's own clock"
        ));
    }
    if node.tip_age_seconds != reported_age {
        refusals
            .push("the Hub's declared node tip age does not match its own timestamps".to_owned());
    }
    // Twice, two clocks, exactly as the Hub's own gate does it.
    if node.tip_age_seconds > max_age {
        refusals.push(format!(
            "against the Hub's clock its node tip is {}s old, past the {max_age}s bound",
            node.tip_age_seconds
        ));
    }
    if local_age > max_age {
        refusals.push(format!(
            "against this device's clock the Hub's node tip is {local_age}s old, past the \
             {max_age}s bound"
        ));
    }
    for (kind, what) in [
        (crate::l2_hub::REQUIRED_CHANNEL_OPEN_ACTION, "ChannelOpen 2"),
        (
            crate::l2_hub::REQUIRED_COOPERATIVE_CLOSE_ACTION,
            "ChannelClose 3",
        ),
    ] {
        if !node.enabled_actions.contains(&kind) {
            refusals.push(format!(
                "the Hub's node does not enable {what}, so it would not accept the transaction \
                 this wallet builds"
            ));
        }
    }
    let observed_text = format!(
        "the Hub's node: chain {} mainnet {} height {} next {} api {}, tip {} aged {}s by the \
         Hub's clock and {local_age}s by this device's, enabled actions {:?}",
        node.chain_id,
        node.mainnet,
        node.height,
        node.next_height,
        node.api_version,
        node.tip_timestamp_unix,
        node.tip_age_seconds,
        node.enabled_actions,
    );
    PreflightCheck::fatal_from_refusals("hub_fullnode", TITLE_HUB_NODE, observed_text, refusals)
}

const TITLE_HUB_NODE_INSTANCE: &str =
    "The Hub's node and your node are looking at the same mainnet";

fn check_hub_fullnode_instance(observed: &PreflightObservations) -> PreflightCheck {
    // No gate refuses on this. Two different mainnet views is still a thing to
    // see before funding, so it is a warning and not silence.
    let hub_instance = observed
        .readiness
        .as_ref()
        .ok()
        .and_then(|readiness| readiness.fullnode_capabilities.as_ref())
        .and_then(|node| node.network_instance_id.clone());
    let wallet_instance = observed
        .capabilities
        .as_ref()
        .ok()
        .and_then(|capabilities| capabilities.network.instance_id.clone());
    match (hub_instance.as_deref(), wallet_instance.as_deref()) {
        (Some(hub), Some(wallet)) if hub == wallet => PreflightCheck::warning(
            "hub_fullnode_instance",
            TITLE_HUB_NODE_INSTANCE,
            CheckStatus::Pass,
            format!("both report network instance {hub}"),
            None,
        ),
        (Some(hub), Some(wallet)) => PreflightCheck::warning(
            "hub_fullnode_instance",
            TITLE_HUB_NODE_INSTANCE,
            CheckStatus::Fail,
            format!("the Hub's node reports {hub}, your node reports {wallet}"),
            Some(
                "Nothing refuses on this, but two different chain identities means one of the two \
                 is not on the network you think it is."
                    .to_owned(),
            ),
        ),
        _ => PreflightCheck::warning(
            "hub_fullnode_instance",
            TITLE_HUB_NODE_INSTANCE,
            CheckStatus::Skip,
            format!(
                "the Hub's node reports {}, your node reports {}",
                hub_instance.as_deref().unwrap_or("nothing"),
                wallet_instance.as_deref().unwrap_or("nothing")
            ),
            Some(
                "One side did not name its chain identity, so they could not be compared."
                    .to_owned(),
            ),
        ),
    }
}

const TITLE_BLOCKERS: &str = "The Hub names nothing that blocks it";

fn check_hub_blockers(observed: &PreflightObservations) -> PreflightCheck {
    let readiness = match observed.readiness.as_ref() {
        Ok(readiness) => readiness,
        Err(error) => {
            return PreflightCheck::fatal_skip("hub_blockers", TITLE_BLOCKERS, error.clone());
        }
    };
    let mut refusals = Vec::new();
    if !readiness.blockers.is_empty() {
        refusals.push(format!(
            "the Hub published blockers: {}",
            readiness.blockers.join(", ")
        ));
    }
    if readiness.witness_identity_is_broken() {
        // The difference between waiting thirty seconds and never funding.
        refusals.push(
            "this Hub's one rollback-anchor witness is no longer the store it pinned. That \
             refusal is permanent on the Hub's own account, not a Hub that is briefly \
             unreachable"
                .to_owned(),
        );
    }
    let observed_text = format!(
        "gating blockers {:?}; witness identity broken {}",
        readiness.blockers,
        readiness.witness_identity_is_broken()
    );
    PreflightCheck::fatal_from_refusals("hub_blockers", TITLE_BLOCKERS, observed_text, refusals)
}

const TITLE_DISCLOSED: &str = "What the Hub discloses but has decided not to block on";

fn check_disclosed_gaps(observed: &PreflightObservations) -> PreflightCheck {
    // A bounded-pilot Hub publishes an empty `blockers` by design, so a
    // preflight that reads only that list gives a clean bill of health to a
    // Hub with a real disclosed gap. Both lists reach the screen.
    let readiness = match observed.readiness.as_ref() {
        Ok(readiness) => readiness,
        Err(error) => {
            return PreflightCheck::warning(
                "hub_disclosed_gaps",
                TITLE_DISCLOSED,
                CheckStatus::Skip,
                "not reached".to_owned(),
                Some(error.clone()),
            );
        }
    };
    if readiness.disclosed_blockers.is_empty() {
        PreflightCheck::warning(
            "hub_disclosed_gaps",
            TITLE_DISCLOSED,
            CheckStatus::Pass,
            "this Hub discloses no non-gating gaps".to_owned(),
            None,
        )
    } else {
        PreflightCheck::warning(
            "hub_disclosed_gaps",
            TITLE_DISCLOSED,
            CheckStatus::Fail,
            format!(
                "everything this Hub reports as outstanding, in its own order: {}",
                readiness.disclosed_gaps().join(", ")
            ),
            Some(format!(
                "These produce no refusal by design: the bounded pilot has already decided not to \
                 gate on them. They are still real gaps and you are funding despite them: {}",
                readiness.disclosed_blockers.join(", ")
            )),
        )
    }
}

const TITLE_ALLOWLIST: &str = "The Hub has an admission list configured at all";

fn check_allowlist_configured(observed: &PreflightObservations) -> PreflightCheck {
    // Read raw, because HubMainnetReadiness does not decode this field and
    // there is no deny_unknown_fields, so reading it raw breaks no typed
    // decode. It proves only that a list exists. Whether THIS address is on it
    // is enforced inside a signed POST and is not checkable read-only.
    let configured = observed
        .readiness_raw
        .as_ref()
        .and_then(|raw| raw.get("allowlist_configured"))
        .and_then(serde_json::Value::as_bool);
    match configured {
        Some(true) => PreflightCheck::warning(
            "allowlist_configured",
            TITLE_ALLOWLIST,
            CheckStatus::Pass,
            "this Hub reports allowlist_configured true".to_owned(),
            Some(
                "This proves a list exists and nothing more. Whether your address is on it cannot \
                 be read without sending a signed request, which this preflight will not do."
                    .to_owned(),
            ),
        ),
        Some(false) => PreflightCheck::warning(
            "allowlist_configured",
            TITLE_ALLOWLIST,
            CheckStatus::Fail,
            "this Hub reports allowlist_configured false".to_owned(),
            Some(
                "A Hub with no admission list will also publish the gating blocker \
                 mainnet_pilot_user_allowlist_is_not_configured, which is refused above."
                    .to_owned(),
            ),
        ),
        None => PreflightCheck::warning(
            "allowlist_configured",
            TITLE_ALLOWLIST,
            CheckStatus::Skip,
            "this Hub did not publish allowlist_configured".to_owned(),
            Some("An older Hub omits the field entirely.".to_owned()),
        ),
    }
}

const TITLE_BINDING: &str = "The network binding this wallet would send validates, and the voucher shape is the one that verifies";

fn check_network_binding_and_voucher_shape(observed: &PreflightObservations) -> PreflightCheck {
    let capabilities = match observed.capabilities.as_ref() {
        Ok(capabilities) => capabilities,
        Err(error) => {
            return PreflightCheck::fatal_skip("network_binding", TITLE_BINDING, error.clone());
        }
    };
    // Every field comes from the capabilities already in hand, so the exact
    // binding this wallet would send can be assembled and proved to validate
    // before anything is signed.
    let binding = l2_fast_pay_hub::l1_channel::L1ChannelNetworkBinding {
        network_kind: capabilities.network.kind.clone(),
        chain_id: capabilities.chain.id,
        mainnet: capabilities.chain.mainnet,
        block_1_hash: capabilities
            .network
            .block_1_hash
            .clone()
            .unwrap_or_default(),
        node_profile_id: capabilities.network.node_profile_id.clone(),
        network_instance_id: capabilities.network.instance_id.clone().unwrap_or_default(),
        transaction_format_version: capabilities.network.transaction_format_version,
    };
    let mut refusals = Vec::new();
    if let Err(error) = binding.validate() {
        refusals.push(format!("the binding does not validate: {error}"));
    }
    if !capabilities.chain.mainnet {
        refusals.push(
            "the binding this wallet would send is not a mainnet binding, and the Hub client is a \
             mainnet client, so the Hub would refuse it"
                .to_owned(),
        );
    }
    // The target shape, from the verifier that will judge the returned bytes.
    if capabilities.chain.id != MAINNET_CHAIN_ID {
        refusals.push(format!(
            "the voucher's ChainAllow must bind exactly chain {MAINNET_CHAIN_ID}, and this node is \
             chain {}",
            capabilities.chain.id
        ));
    }
    let observed_text = format!(
        "binding: kind \"{}\", chain {}, mainnet {}, block 1 {}, profile \"{}\", instance {}, tx \
         format {}. Target voucher shape: Type 2, actions exactly [ChainAllow 0x0411, ChannelClose \
         3], no HacFromToTrs 14 anywhere (that is what delta zero means in code), ChainAllow \
         binding exactly chain {MAINNET_CHAIN_ID}",
        binding.network_kind,
        binding.chain_id,
        binding.mainnet,
        if binding.block_1_hash.is_empty() {
            "absent"
        } else {
            &binding.block_1_hash
        },
        binding.node_profile_id,
        if binding.network_instance_id.is_empty() {
            "absent"
        } else {
            &binding.network_instance_id
        },
        binding.transaction_format_version,
    );
    PreflightCheck::fatal_from_refusals("network_binding", TITLE_BINDING, observed_text, refusals)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(severity: CheckSeverity, status: CheckStatus) -> PreflightCheck {
        PreflightCheck::new("x", "x", severity, status, String::new(), None)
    }

    #[test]
    fn all_fatal_items_passing_is_the_only_way_to_a_pass() {
        let checks = vec![
            check(CheckSeverity::Fatal, CheckStatus::Pass),
            check(CheckSeverity::Fatal, CheckStatus::Pass),
            check(CheckSeverity::Warning, CheckStatus::Fail),
            check(CheckSeverity::Warning, CheckStatus::Skip),
        ];
        assert_eq!(verdict_for(&checks), PreflightVerdict::Pass);
    }

    #[test]
    fn one_failed_fatal_item_denies_the_pass() {
        let checks = vec![
            check(CheckSeverity::Fatal, CheckStatus::Pass),
            check(CheckSeverity::Fatal, CheckStatus::Fail),
        ];
        assert_eq!(verdict_for(&checks), PreflightVerdict::NotPass);
    }

    /// The rule this whole surface hangs on: a skipped fatal item is not a
    /// passed one. This is the red-then-green case.
    #[test]
    fn one_skipped_fatal_item_denies_the_pass() {
        let checks = vec![
            check(CheckSeverity::Fatal, CheckStatus::Pass),
            check(CheckSeverity::Fatal, CheckStatus::Skip),
        ];
        assert_eq!(
            verdict_for(&checks),
            PreflightVerdict::NotPass,
            "a fatal item that was never reached must never render as a pass"
        );
    }

    #[test]
    fn an_empty_run_is_not_a_pass_by_accident() {
        // Nothing fatal failed because nothing fatal ran. The surface never
        // builds an empty list, but the rule must not depend on that.
        assert_eq!(verdict_for(&[]), PreflightVerdict::NotPass);
        assert_eq!(
            verdict_for(&[check(CheckSeverity::Warning, CheckStatus::Pass)]),
            PreflightVerdict::NotPass
        );
    }
}
