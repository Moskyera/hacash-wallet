/**
 * WHERE THE URL COMES FROM, ON THE SHELL THAT CANNOT SUPPLY IT ITSELF.
 *
 * The phone has the same two empty boxes as the desktop: a relay URL that
 * `DustWhisperSettings::default()` leaves blank
 * (crates/wallet-core/src/dust_whisper.rs:33) and a hub URL whose only preset is
 * a loopback dev entry (crates/wallet-core/src/fast_pay.rs:24-29). It does not
 * have the desktop's way out. `should_manage_relay` in
 * crates/wallet-tauri-common/src/desktop_relay.rs:101 opens with
 * `cfg!(not(any(target_os = "android", target_os = "ios")))`, so the embedded
 * relay never runs on a phone, and `WhisperScreen` pins `auto_start_relay` to
 * false for that reason.
 *
 * So the phone may not repeat the desktop's "this computer can run one". It can
 * only say the true half: somebody has to run a relay, it can be you, and the
 * machine it runs on is not this one.
 */
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { pollReport } from "./messengerPoll";

const HERE = dirname(fileURLToPath(import.meta.url));

function source(relative: string): string {
  return readFileSync(join(HERE, relative), "utf8");
}

const RUN_ONE = /somebody has to run|run your own|run one yourself/i;
const RELAY_GUIDE = /docs\/RUNNING-A-RELAY\.md/;
const HUB_GUIDE = /docs\/HUB-OPERATOR\.md/;

describe("the relay field says where a relay comes from", () => {
  it("names the guide on the screen that asks for the URL", () => {
    const whisper = source("components/WhisperScreen.tsx");
    expect(whisper).toMatch(RELAY_GUIDE);
    expect(whisper).toMatch(RUN_ONE);
  });

  it("names the guide in the messenger empty state", () => {
    const messenger = source("components/MessengerScreen.tsx");
    expect(messenger).toMatch(RELAY_GUIDE);
    expect(messenger).toMatch(RUN_ONE);
  });

  it("names the guide in both refusals to enable DUST Whisper without one", () => {
    const whisper = source("components/WhisperScreen.tsx");
    expect(whisper).toMatch(/Add at least one relay URL/);
    const session = source("hooks/useWalletSession.ts");
    expect(session).toMatch(/Add a relay URL/);
    expect(session).toMatch(RELAY_GUIDE);
  });

  it("names the guide on the pay options that need a relay", () => {
    const payOptions = source("components/DustWhisperPayOptions.tsx");
    expect(payOptions).toMatch(RELAY_GUIDE);
  });

  it("names the guide when an inbox check had no relay to check", () => {
    const report = pollReport({
      added: 0,
      relays_tried: 0,
      relays_answered: 0,
      relays_refused: 0,
      rejected_envelopes: 0,
      undecryptable: 0,
      store_full: false,
    });
    expect(report.kind).toBe("error");
    expect(report.text).toMatch(RELAY_GUIDE);
    expect(report.text).toMatch(RUN_ONE);
    expect(report.text).not.toMatch(/nothing new/i);
  });
});

describe("the phone does not offer to host what it cannot host", () => {
  it("keeps the local relay switch off, as the shell requires", () => {
    // crates/wallet-tauri-common/src/desktop_relay.rs:101 refuses to manage a
    // relay on android or ios, so a true switch here would be a control that
    // does nothing.
    expect(source("components/WhisperScreen.tsx")).toMatch(/auto_start_relay:\s*false/);
  });

  it("never tells the owner this phone can run the relay", () => {
    const files = [
      "components/WhisperScreen.tsx",
      "components/MessengerScreen.tsx",
      "components/DustWhisperPayOptions.tsx",
      "messengerPoll.ts",
      "hooks/useWalletSession.ts",
    ];
    for (const file of files) {
      expect(source(file)).not.toMatch(/this (?:phone|device) can (?:run|host)/i);
    }
  });
});

describe("the hub field says where a hub comes from", () => {
  it("names the operator guide beside the discovery button", () => {
    const panel = source("components/HubDiscoveryPanel.tsx");
    expect(panel).toMatch(HUB_GUIDE);
    expect(panel).toMatch(RUN_ONE);
  });
});

describe("the relay operator sees the whole transaction, and the wallet says so", () => {
  /**
   * Same claim as the desktop test of this name, and for the same reason: the
   * relay decrypts a submitted transaction before forwarding it
   * (crates/dust-whisper/src/relay.rs:94, forwarded in clear at :109-121), and
   * docs/RUNNING-A-RELAY.md section 6.5 tells the operator so. The user pasting
   * the URL should not be the only party who has not been told.
   */
  it("says the encryption ends at the relay on the screen that turns it on", () => {
    const whisper = source("components/WhisperScreen.tsx");
    expect(whisper).toMatch(/encryption ends at the relay/i);
    expect(whisper).toMatch(/sees the whole transaction/i);
  });
});
