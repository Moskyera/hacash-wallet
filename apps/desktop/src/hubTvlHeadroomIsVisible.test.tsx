/// A HUB AT ITS CAP LOOKED PERFECTLY HEALTHY, AND THE SENTENCE THAT SAID
/// OTHERWISE COULD NEVER FIRE.
///
/// The first mainnet Fast Pay channel open was refused because the Hub's whole
/// aggregate TVL budget was held by an earlier channel-open that had been
/// broadcast and never mined. The wallet already carried the right sentence for
/// that state: "This Hub is already at or over its own total cap". It was gated
/// on `aggregate_tvl_within_limit`, which is the Hub's `current <= cap` and so
/// reads TRUE at exactly the cap. At one hundred percent utilisation the flag
/// says fine, the blocker list is empty, payments are enabled, and every new
/// channel is refused.
///
/// So the person saw nothing, signed, and got "Agent Wallet state requires
/// manual recovery" three times over eight hours.
///
/// These tests pin the fixed reading. Nothing here greps a source file: each
/// case renders the real card and reads what a person would actually see.

import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import {
  HubDeclarationCard,
  hubHasNoRoomForANewChannel,
  type HubDeclarationView,
} from "@hacash/wallet-ui";

/// The owner's Hub, in the state it was actually in: a bounded pilot whose
/// aggregate cap is exactly one 0.2 HAC channel, with that whole cap already
/// held. Every gate reads healthy.
const ownersHub: HubDeclarationView = {
  hub_url: "http://127.0.0.1:8790",
  reachable: true,
  error: null,
  name: "HPAY",
  hub_address: "18bV2fjWhpQpmGRLifS8PDmzA6ATRJwVgq",
  version: 7,
  settlement_ready: true,
  cross_channel_ready: true,
  hub_fee_mei: "0",
  deployment_profile: "mainnet-bounded-pilot",
  mainnet_checked: true,
  readiness_profile: "mainnet-bounded-pilot",
  payments_enabled: true,
  declared_caps: {
    max_payment_hac: "0.1",
    max_channel_funding_hac: "0.2",
    max_aggregate_tvl_hac: "0.2",
    // Exactly at the cap, and therefore still "within" it.
    aggregate_tvl_within_limit: true,
    aggregate_tvl_hac: "0.2",
    new_channel_admission_available: false,
  },
  blockers: [],
  disclosed_blockers: ["unilateral_l1_dispute_path_is_not_ready"],
  limitations: [],
  readiness_error: null,
};

function withCaps(
  overrides: Partial<HubDeclarationView["declared_caps"]>,
): HubDeclarationView {
  return {
    ...ownersHub,
    declared_caps: { ...ownersHub.declared_caps, ...overrides },
  };
}

describe("a Hub sitting exactly on its aggregate cap", () => {
  it("is read as having no room, even though it is within its limit", () => {
    expect(ownersHub.declared_caps.aggregate_tvl_within_limit).toBe(true);
    expect(hubHasNoRoomForANewChannel(ownersHub.declared_caps)).toBe(true);
  });

  it("says so on the screen, with the two numbers", () => {
    const html = renderToStaticMarkup(
      <HubDeclarationCard declaration={ownersHub} />,
    );
    expect(html).toContain("already at its own total cap");
    expect(html).toContain("0.2 HAC of 0.2 HAC");
    expect(html).toContain("will not take a new channel right now");
  });

  it("does not claim the Hub is broken, because it is not", () => {
    const html = renderToStaticMarkup(
      <HubDeclarationCard declaration={ownersHub} />,
    );
    expect(html).toContain("Its existing channels are unaffected");
  });
});

describe("what must not trigger the sentence", () => {
  it("stays silent for a Hub with room", () => {
    const roomy = withCaps({
      aggregate_tvl_hac: "0",
      new_channel_admission_available: true,
    });
    expect(hubHasNoRoomForANewChannel(roomy.declared_caps)).toBe(false);
    const html = renderToStaticMarkup(
      <HubDeclarationCard declaration={roomy} />,
    );
    expect(html).not.toContain("will not take a new channel right now");
  });

  it("stays silent for an older Hub that does not measure it", () => {
    // Absence is not a declaration of "closed". A required boolean defaulted
    // to false here would tell every person on an older Hub that their Hub was
    // shut, which is a worse lie than the one being fixed.
    const older = withCaps({
      aggregate_tvl_hac: undefined,
      new_channel_admission_available: undefined,
    });
    expect(hubHasNoRoomForANewChannel(older.declared_caps)).toBe(false);
    const html = renderToStaticMarkup(
      <HubDeclarationCard declaration={older} />,
    );
    expect(html).not.toContain("will not take a new channel right now");
  });
});

describe("the reading that already worked keeps working", () => {
  it("still fires when the Hub says it is over its cap", () => {
    const over = withCaps({
      aggregate_tvl_within_limit: false,
      new_channel_admission_available: undefined,
      aggregate_tvl_hac: undefined,
    });
    expect(hubHasNoRoomForANewChannel(over.declared_caps)).toBe(true);
    const html = renderToStaticMarkup(<HubDeclarationCard declaration={over} />);
    expect(html).toContain("will not take a new channel right now");
    // With no measurement to show, the sentence carries no invented numbers.
    expect(html).not.toContain("HAC of");
  });
});
