import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(new URL("../src/agent/AgentAdminPages.tsx", import.meta.url), "utf8");
const appSource = readFileSync(new URL("../src/App.tsx", import.meta.url), "utf8");
const agentAppSource = readFileSync(
  new URL("../src/agent/AgentWalletApp.tsx", import.meta.url),
  "utf8",
);
const companionSource = readFileSync(
  new URL("../src/agent/MobileCompanionPanel.tsx", import.meta.url),
  "utf8",
);
const accessSource = readFileSync(
  new URL("../src/agent/access.ts", import.meta.url),
  "utf8",
);
const desktopStyles = readFileSync(new URL("../src/styles.css", import.meta.url), "utf8");
const agentStyles = readFileSync(
  new URL("../src/agent/agent-wallet.css", import.meta.url),
  "utf8",
);const homeSource = readFileSync(new URL("../src/screens/HomeScreen.tsx", import.meta.url), "utf8");
const balanceSource = readFileSync(
  new URL("../src/components/BalanceOverview.tsx", import.meta.url),
  "utf8",
);
const assetTrendsSource = readFileSync(
  new URL("../src/assetTrends.ts", import.meta.url),
  "utf8",
);

test("Agent Rules exposes only the production-ready desktop approval mode", () => {
  assert.doesNotMatch(source, /<option value="mobile_manual"/);
  assert.doesNotMatch(source, /<option value="either_trusted_device"/);
  assert.match(source, /value={approvalModeLabel\(draft\.approvalMode\)} readOnly disabled/);
  assert.match(source, /draft\.approvalMode !== "desktop_manual"/);
});

test("persisted unsupported approval modes stay visible, unchanged and fail closed", () => {
  assert.match(source, /preserved unchanged and this policy is read-only/);
  assert.match(source, /Agent payments remain blocked/);
  assert.match(source, /mobile approval policy is read-only and remains blocked/);
});

test("Agent Wallet approval review remains wallet-fee free", () => {
  assert.match(source, /label="HPAY wallet fee"/);
  assert.match(source, /walletFee === 0n/);
  assert.match(source, /networkFee === 1_000n/);
});

test("payments to addresses the owner never vetted are owner-enabled, per agent, and off by default", () => {
  // The owner control exists on the unlocked desktop Rules page and is the
  // only place this is settable.
  assert.match(source, /allowUnlistedWithApproval: boolean;/);
  assert.match(source, /checked={draft\.allowUnlistedWithApproval}/);
  assert.match(
    source,
    /Let this agent propose payments to addresses that are not allowed above/,
  );
  // The draft round-trips it, so editing an unrelated field cannot silently
  // switch the owner's choice back off.
  assert.match(
    source,
    /allowUnlistedWithApproval: policy\.allow_unlisted_recipient_with_approval/,
  );
  assert.match(
    source,
    /allow_unlisted_recipient_with_approval: draft\.allowUnlistedWithApproval/,
  );
  // A pairing that has not been given rules keeps it off.
  assert.match(agentAppSource, /allow_unlisted_recipient_with_approval: false/);
});

test("an approval for an address that is not on the allowlist says so, in full", () => {
  assert.match(source, /RECIPIENT_STANDING_LABEL\[standing\]/);
  assert.match(
    source,
    /New recipient\. This address is not on this agent's allowlist\./,
  );
  // The copy states the property the backend actually holds: approving pays
  // once and grants nothing standing.
  assert.match(source, /not added to the allowlist/);
  assert.match(source, /className="agent-exact-address">\{approval\.recipient\}/);
  assert.match(source, /recipientStanding\(next\.recipient, policy\)/);
  assert.match(agentStyles, /\.agent-exact-address \{/);
  // A policy that fails to load is never reported as vetted.
  assert.match(source, /if \(!policy\) return "unverified";/);
});

test("wallet-space switches lock the wallet being left before navigation", () => {
  assert.match(
    appSource,
    /await wallet\.handleLock\(\);\s+onOpenAgent\(\);/,
  );
  assert.match(
    agentAppSource,
    /await agentWalletApi\.lock\(overview\.wallet_id\);\s+setOverview\(null\);\s+onOpenPersonal\(\);/,
  );
});
test("expired mobile pairing offers cannot remain actionable", () => {
  assert.match(companionSource, /setOffer\(pairingStatus\?\.offer \?\? null\)/);
  assert.doesNotMatch(companionSource, /current\s*\?\?\s*pairingStatus/);
  assert.match(companionSource, /Pairing expires in/);
  assert.match(companionSource, /busy \|\| pairingExpired/);
  assert.match(companionSource, /nextStatus\.walletId !== walletId/);
  assert.match(companionSource, /!bindAddress \|\|\s+!hasAuthorizedDevice/);
  // A dead listener slot is held, so CompanionSupervisor::start refuses
  // outright. Turning it on cannot succeed in that state and must not be
  // offered as if it could.
  assert.match(companionSource, /const listenerFailed = status\?\.phase === "failed"/);
  assert.match(companionSource, /Boolean\(offer\) \|\|\s+listenerFailed;/);
});


test("new mainnet Agent Wallet creation is explicit, bounded and fail closed", () => {
  assert.match(agentAppSource, /<option value="mainnet"/);
  assert.match(agentAppSource, /mainnetNodeUrl\.startsWith\("https:\/\/"\)/);
  assert.match(agentAppSource, /mainnetAcknowledged/);
  // The acknowledgement must be RENDERED, not merely mentioned. It used to be
  // imported and put in the create payload while the checkbox beside it read
  // "I understand the bounded pilot and recovery limitations", so the sentence
  // naming the loss was verified for string equality against a person who had
  // never been shown it. Matching the bare identifier passed that whole time.
  // Match the JSX braces, which only the rendered use has.
  assert.match(agentAppSource, /\{AGENT_MAINNET_PILOT_ACKNOWLEDGEMENT\}/);
  assert.doesNotMatch(agentAppSource, /I understand the bounded pilot and recovery limitations/);
  // The numbers are what no Hub may exceed. A Hub declares its own and the
  // only one ever measured on mainnet declared a hundredth of these, so the
  // screen must not offer them as the limits the person actually gets.
  assert.match(agentAppSource, /1 HAC per payment/);
  assert.match(agentAppSource, /10 HAC per channel/);
  assert.match(agentAppSource, /100 HAC aggregate TVL/);
  assert.match(agentAppSource, /no Hub may exceed/);
  assert.match(agentAppSource, /What your Hub\s+declares is what applies/);
});

test("Agent Wallet routing never uses payment readiness as a navigation redirect", () => {
  assert.match(agentAppSource, /uiState === "not_created"/);
  assert.match(agentAppSource, /uiState === "locked"/);
  assert.match(agentAppSource, /Payment readiness blockers/);
  assert.doesNotMatch(
    agentAppSource,
    /\b(?:history\.back|navigate|redirect|location\.replace)\(/,
  );
  assert.match(accessSource, /\? "available"\s*:\s*"read_only"/);
  assert.match(accessSource, /mobile_not_paired/);
  assert.match(accessSource, /wallet_not_funded/);
});

test("non-pilot build shows an explicit unavailable screen without auto-switching", () => {
  assert.match(agentAppSource, /AI Agent Wallet unavailable in this build/);
  assert.match(agentAppSource, /Use a reviewed HPAY Agent Wallet build to access this space/);
  const unavailable = agentAppSource
    .split('uiState === "unavailable_in_this_build"')[1]
    .split('uiState === "recovery_required"')[0];
  assert.doesNotMatch(unavailable, /onOpenPersonal\(\)/);
});

test("Local Pilot creation is bound to the verified private-chain identity", () => {
  assert.match(accessSource, /http:\/\/127\.0\.0\.1:8197/);
  assert.match(accessSource, /000087f67e55660eaefed72e0b9499147556a33a34f18fa48900f4a2fa30cd29/);
  assert.match(accessSource, /9ebd8657a72faed35ed4d6e309fab2ef259f054e4820684fab6c6b848e4438f3/);
  assert.match(agentAppSource, /PRIVATE DEVELOPMENT NETWORK/);
  assert.match(agentAppSource, /NO MAINNET FUNDS/);
});


test("desktop startup surfaces remain true black with gold-only emphasis", () => {
  assert.match(desktopStyles, /\.space-welcome-card\s*{[^}]*background:\s*#000;/s);
  assert.match(desktopStyles, /\.space-choice-grid button\s*{[^}]*background:\s*#000;/s);
  assert.match(
    desktopStyles,
    /\.space-choice-grid button:hover,[^{]*{[^}]*background:\s*#000;/s,
  );
  assert.match(agentStyles, /\.agent-entry \.agent-center-card\s*{[^}]*background:\s*#000;/s);
  assert.match(
    agentStyles,
    /\.agent-entry \.wallet-space-switcher button\.active\s*{[^}]*background:\s*#000;[^}]*border:\s*1px solid #ff9d00;/s,
  );
});
test("premium dashboard stays connected to real wallet data", () => {
  assert.match(homeSource, /history\.slice\(0, 5\)/);
  assert.match(balanceSource, /<AssetMark kind=\{kind\}/);
  assert.match(balanceSource, /balance-portfolio-layout/);
  assert.doesNotMatch(homeSource, /Quick actions|DashboardActionIcon|ActionButton/);
  assert.match(homeSource, /trends=\{assetTrends\}/);
  assert.match(balanceSource, /trendPolyline\(trend\)/);
  assert.match(assetTrendsSource, /summary\.hac_mei/);
  assert.match(assetTrendsSource, /summary\.btc_wallet_satoshi \+ summary\.btc_channel_satoshi/);
  assert.match(agentAppSource, /Separate wallet and permission domain/);
  assert.doesNotMatch(homeSource, /12,345|Alpha Agent|UI DEMO/);
});

test("payment readiness never gates clearing the emergency stop", () => {
  // The deadlock: the enable control inherited the payment prerequisite list,
  // so a wallet with no paired phone could never leave an emergency stop.
  assert.doesNotMatch(agentAppSource, /writeBlockers\.filter/);
  assert.doesNotMatch(agentAppSource, /enableBlockers/);
  assert.match(agentAppSource, /agentWalletLocalEnableBlockers\(runtime, overview\)/);
  assert.match(agentAppSource, /localEnableBlockers,\s*\}\);/);
  assert.match(agentAppSource, /disabled=\{stopControl\.disabled\}/);
  assert.match(agentAppSource, /title=\{stopControl\.reason\}/);
  // The enable predicate must not consult any payment prerequisite.
  const enablePredicate = accessSource
    .split("export function agentWalletLocalEnableBlockers")[1]
    .split("export function agentWalletPairingBlockers")[0];
  for (const irrelevant of [
    "node_not_ready",
    "wallet_not_funded",
    "mobile_not_paired",
    "witness_not_initialized",
    "payments_suspended",
  ]) {
    assert.ok(
      !enablePredicate.includes(`blockers.push("${irrelevant}")`),
      `clearing an emergency stop must not require ${irrelevant}`,
    );
  }
  assert.ok(enablePredicate.includes('blockers.push("recovery_required")'));
});

test("the Security page offers a way out of an emergency stop", () => {
  // Security could engage the stop and then rendered no control that clears it.
  assert.match(source, /emergencyStopControl/);
  assert.match(source, /Enable locally/);
  assert.match(source, /localEnableBlockers/);
  assert.match(agentAppSource, /onEnable=\{onEnable\}/);
  assert.match(agentAppSource, /localEnableBlockers=\{localEnableBlockers\}/);
});

test("pairing a phone is gated only on what pairing genuinely needs", () => {
  const pairingPredicate = accessSource.split("export function agentWalletPairingBlockers")[1];
  for (const irrelevant of [
    "node_not_ready",
    "wallet_not_funded",
    "mobile_not_paired",
    "witness_not_initialized",
    "wrong_network",
    "missing_block_one",
  ]) {
    assert.ok(
      !pairingPredicate.includes(`blockers.push("${irrelevant}")`),
      `pairing a phone must not require ${irrelevant}`,
    );
  }
  assert.match(companionSource, /pairingBlockers/);
  // The panel renders the refusal through pairingRefusalText, which is built
  // from PAIRING_BLOCKER_LABELS and additionally says when the escape route it
  // names ("Enable locally") is itself refused.
  assert.match(companionSource, /pairingRefusalText\(pairingBlockers, localEnableBlockers\)/);
  assert.match(accessSource, /PAIRING_BLOCKER_LABELS\[blocker\]/);
  assert.match(companionSource, /pairingBlockers\.length > 0/);
});

test("a refused non-payment action never explains itself with payment prose", () => {
  assert.match(accessSource, /LOCAL_ENABLE_BLOCKER_LABELS/);
  assert.match(accessSource, /PAIRING_BLOCKER_LABELS/);
  const enableLabels = accessSource
    .split("export const LOCAL_ENABLE_BLOCKER_LABELS")[1]
    .split("export const PAIRING_BLOCKER_LABELS")[0];
  assert.doesNotMatch(enableLabels, /Funding is required before a test payment\./);
  // The pairing refusal must name the escape route out of the deadlock.
  assert.match(accessSource, /Clear the emergency stop in Payment control first, then pair the phone\./);
});

test("the payment predicate keeps every prerequisite", () => {
  const paymentPredicate = accessSource
    .split("export function agentWalletPaymentBlockers")[1]
    .split("export function agentWalletLocalEnableBlockers")[0];
  for (const required of [
    "disabled_by_build",
    "missing_block_one",
    "wrong_network",
    "node_not_ready",
    "wallet_not_funded",
    "mobile_not_paired",
    "witness_not_initialized",
    "payments_suspended",
    "recovery_required",
  ]) {
    assert.ok(
      paymentPredicate.includes(`blockers.push("${required}")`),
      `the payment gate must keep ${required}`,
    );
  }
  assert.match(agentAppSource, /paymentBlockers\.map/);
  assert.match(agentAppSource, /paymentBlockers\.length === 0 \? "Ready"/);
});
