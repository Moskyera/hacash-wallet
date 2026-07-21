import {
  SUPPORTED_LOCALES,
  applyDocumentLocale,
  localeDirection,
  normalizeLocaleTag,
  translate,
  validateLocaleCatalogParity,
  validateLocaleCatalogContent,
} from "@hacash/wallet-ui";
import { describe, expect, it } from "vitest";

describe("shared locale catalog", () => {
  it("keeps native language labels as real UTF-8", () => {
    expect(SUPPORTED_LOCALES.map(({ code, label }) => [code, label])).toEqual([
      ["en", "English"],
      ["el", "Ελληνικά"],
      ["zh-CN", "简体中文"],
      ["ja", "日本語"],
      ["tr", "Türkçe"],
      ["vi", "Tiếng Việt"],
      ["ru", "Русский"],
      ["es", "Español"],
      ["fr", "Français"],
      ["pt", "Português"],
      ["ar", "العربية"],
      ["sv", "Svenska"],
      ["de", "Deutsch"],
    ]);
  });

  it("contains the same keys for every supported locale", () => {
    expect(() => validateLocaleCatalogParity()).not.toThrow();
    expect(SUPPORTED_LOCALES).toHaveLength(13);
  });

  it("translates the primary Quantum, Settings and Security surfaces in every language", () => {
    const primaryKeys = [
      "quantum.sendTitle",
      "settings.title",
      "security.privateKey",
      "common.continue",
      "home.refreshing",
      "home.pullToRefresh",
      "home.fastPayOn",
      "home.enable",
      "home.disable",
      "home.scanAndPay",
      "home.recent",
    ];
    for (const { code } of SUPPORTED_LOCALES) {
      if (code === "en") continue;
      for (const key of primaryKeys) {
        expect(translate(code, key), `${code}.${key}`).not.toBe(translate("en", key));
      }
    }
    expect(translate("el", "quantum.nodeReachableHeight", { height: 123 })).toContain("123");
  });

  it("translates every non-technical Istanbul and native-asset surface", () => {
    const keys = [
      "istanbul.title",
      "istanbul.subtitle",
      "istanbul.fact.height",
      "istanbul.address.kind.private_key",
      "istanbul.transaction.signerPolicy",
      "nativeAssets.title",
      "nativeAssets.help",
      "nativeAssets.hidden",
    ];
    for (const { code } of SUPPORTED_LOCALES) {
      if (code === "en") continue;
      for (const key of keys) {
        expect(translate(code, key), `${code}.${key}`).not.toBe(translate("en", key));
      }
    }
  });

  it("rejects suspicious question-mark and replacement-character corruption", () => {
    expect(() => validateLocaleCatalogContent()).not.toThrow();
  });

  it.each([
    ["zh-CN", "zh-CN"],
    ["zh_Hans_CN", "zh-CN"],
    ["pt-BR", "pt"],
    ["ar-EG", "ar"],
    ["el-GR", "el"],
    ["ja-JP", "ja"],
    ["tr-TR", "tr"],
    ["vi-VN", "vi"],
    ["ru-RU", "ru"],
    ["es-MX", "es"],
    ["fr-CA", "fr"],
    ["sv-SE", "sv"],
    ["de-AT", "de"],
    ["unknown", "en"],
  ])("normalizes browser locale %s to %s", (input, expected) => {
    expect(normalizeLocaleTag(input)).toBe(expected);
  });

  it("interpolates named parameters without dropping unknown placeholders", () => {
    expect(translate("en", "update.trustedAvailable", { platform: "Windows" })).toBe(
      "A trusted Windows update is available.",
    );
    expect(translate("en", "unknown.key", { platform: "Linux" })).toBe("unknown.key");
    expect(translate("en", "update.trustedAvailable")).toContain("{platform}");
  });

  it("uses RTL only for Arabic and restores LTR", () => {
    const root = { lang: "", dir: "" };
    applyDocumentLocale("ar", root);
    expect(root).toEqual({ lang: "ar", dir: "rtl" });

    applyDocumentLocale("de", root);
    expect(root).toEqual({ lang: "de", dir: "ltr" });
    expect(localeDirection("ar")).toBe("rtl");
    expect(SUPPORTED_LOCALES.filter(({ code }) => code !== "ar").every(
      ({ code }) => localeDirection(code) === "ltr",
    )).toBe(true);
  });
});
