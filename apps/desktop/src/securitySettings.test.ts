import fs from "node:fs";
import { describe, expect, it } from "vitest";

const screen = fs.readFileSync(
  new URL("./screens/SecurityInfoScreen.tsx", import.meta.url),
  "utf8",
);

describe("desktop security settings", () => {
  it("requires a registered WebAuthn authenticator before WebAuthn-only policies", () => {
    expect(screen).toContain('const webauthnConfigured = status?.webauthn_enabled === true');
    expect(screen).toContain(
      'disabled={busy || coldVault || !webauthnConfigured || !currentPassphrase}',
    );
    expect(screen).toMatch(/status\?\.watch_only \|\|\s*!webauthnConfigured \|\|\s*!currentPassphrase/);
    expect(screen).toContain(
      "Register WebAuthn before enabling Paranoid or the WebAuthn signing gate.",
    );
  });
});

