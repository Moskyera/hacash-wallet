import { describe, expect, it } from "vitest";
import type { SendPreview } from "./api";
import { bindReviewedHacSend } from "./reviewedHacSend";

function fastPayPreview(): SendPreview {
  return {
    plan: {
      rail: "L2Fast",
      summary: "Fast Pay 12 HAC",
      estimated_fee: "0 HAC",
      channel_id: "channel-1",
      rail_label: "Instant (Fast Pay)",
      rail_detail: "Fee-free L2 payment",
      fee_breakdown: {
        payer_debit_mei: 12,
        recipient_credit_mei: 12,
        hub_fee_mei: 0,
        hub_fee_payer: "sender",
        l1_fee_wire: null,
        l1_fee_mei: null,
        service_fee_mei: null,
        service_fee_rate: null,
        service_fee_treasury: null,
      },
    },
    from: "1From",
    to: "1To",
    amount_mei: 12,
    amount_wire: "12:248",
    fee: "0",
    service_fee_mei: 0,
    service_fee_treasury: null,
    hip23: { ok: true, warnings: [], errors: [] },
    fast_pay: {
      state: "ready",
      message: "Ready",
      provider_name: "HPAY Hub",
      hub_url: "https://hub.example",
      can_enable: true,
      default_deposit_mei: 100,
    },
    send_options: {
      hub_fee_payer: "sender",
      force_l1: false,
      l1_fee_speed: "normal",
      service_fee_enabled: true,
      service_fee_rate: 0.003,
    },
  };
}

describe("desktop HAC reviewed send binding", () => {
  it("detaches confirmation from later form or preview mutations", () => {
    const preview = fastPayPreview();
    const reviewed = bindReviewedHacSend(preview);

    preview.to = "1Changed";
    preview.amount_mei = 99;
    preview.amount_wire = "99:248";
    preview.plan.channel_id = "channel-2";
    preview.plan.rail = "L1OnChain";
    preview.send_options.force_l1 = true;

    expect(reviewed).toEqual({
      to: "1To",
      amountMei: 12,
      options: expect.objectContaining({ force_l1: false }),
      expectation: {
        from: "1From",
        to: "1To",
        amount_wire: "12:248",
        rail: "L2Fast",
        channel_id: "channel-1",
      },
    });
  });

  it("freezes the execution request and its security-relevant children", () => {
    const reviewed = bindReviewedHacSend(fastPayPreview());

    expect(Object.isFrozen(reviewed)).toBe(true);
    expect(Object.isFrozen(reviewed.options)).toBe(true);
    expect(Object.isFrozen(reviewed.expectation)).toBe(true);
  });
});
