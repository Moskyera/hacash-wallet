import {
  SUPPORTED_LOCALES,
  translate,
  validateLocaleCatalogContent,
  validateLocaleCatalogParity,
} from "@hacash/wallet-ui";
import { describe, expect, it } from "vitest";

describe("air-gap inspection locale gate", () => {
  it("keeps every Air-gap inspection label in catalog parity", () => {
    expect(() => validateLocaleCatalogParity()).not.toThrow();
    expect(() => validateLocaleCatalogContent()).not.toThrow();
  });

  it("translates all non-technical inspection copy in every supported locale", () => {
    const keys = [
      "airgap.inspection.verifiedTitle",
      "airgap.inspection.encodedUnsignedTitle",
      "airgap.inspection.unsignedTitle",
      "airgap.inspection.signedTitle",
      "airgap.inspection.signedReadyTitle",
      "airgap.inspection.network",
      "airgap.inspection.transactionType",
      "airgap.inspection.from",
      "airgap.inspection.to",
      "airgap.inspection.amount",
      "airgap.inspection.networkFee",
      "airgap.inspection.walletFee",
      "airgap.inspection.walletFeeRecipient",
      "airgap.inspection.bodyHash",
      "airgap.inspection.matchedNote",
      "airgap.inspection.type4QuantumOnly",
      "airgap.inspection.missing",
    ];

    for (const { code } of SUPPORTED_LOCALES) {
      if (code === "en") continue;
      for (const key of keys) {
        expect(translate(code, key), `${code}.${key}`).not.toBe(translate("en", key));
      }
    }
  });
});
