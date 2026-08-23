/// THE DESKTOP SHELL COULD ALREADY DO THIS AND HAD NO WAY IN.
///
/// `crates/wallet-tauri-common/src/handlers.rs` registers messenger_threads,
/// messenger_messages, messenger_mark_read, messenger_send and
/// messenger_poll_inbox for both shells, and only the desktop shell can host a
/// relay (crates/wallet-tauri-common/src/desktop_relay.rs). Yet
/// `grep -rni messenger apps/desktop/src/` returned nothing: there was no
/// screen, no nav entry and no binding.
///
/// These tests are about the surface a person can reach, so they render the
/// real router with the real screen rather than reading source strings. The
/// last two are about what the screen SAYS: this wallet has shipped a control
/// that did nothing, an instruction naming a control that did not exist and a
/// success message for something that had not happened, so a new screen has to
/// prove it claims neither encryption it has not verified nor delivery the core
/// did not report.

import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(async () => undefined),
}));

// The locale provider reads `navigator.languages` at first render, which does
// not exist under the node test environment. Only the lookup is replaced; every
// other export of the shared package stays real.
vi.mock("@hacash/wallet-ui", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    useLocale: () => ({ locale: "en", setLocale: () => {}, t: (key: string) => key }),
  };
});

const { NAV_GROUPS } = await import("./types");
const { default: DesktopRouter } = await import("./DesktopRouter");
const { sendOutcome, messengerBlockedReason } = await import("./MessagesScreen");
type DesktopRouterProps = Parameters<typeof DesktopRouter>[0];
type ChatMessage = Parameters<typeof sendOutcome>[0];

const UNLOCKED = {
  address: "1AVRUVLKKCrzMBtwvbcUgsQBd9JJmvNRT8",
  locked: false,
  watch_only: false,
  hardware_signing_mode: "software",
};

function renderMessages(relayUrls: string[], enabled = true, autoStart = true): string {
  const props = {
    screen: "messages",
    data: {
      status: UNLOCKED,
      dustWhisper: {
        enabled,
        relay_urls: relayUrls,
        fallback_direct: true,
        auto_start_relay: autoStart,
      },
      hideAddresses: false,
    },
    actions: { setScreen: () => {}, onNotify: () => {} },
  } as unknown as DesktopRouterProps;
  return renderToStaticMarkup(<DesktopRouter {...props} />);
}

function outgoing(delivered: boolean, delivery_error?: string): ChatMessage {
  return {
    id: "m1",
    peer: "1AVRUVLKKCrzMBtwvbcUgsQBd9JJmvNRT8",
    direction: "out",
    body: "meet me at 9",
    timestamp_utc: "2026-08-22T09:00:00+00:00",
    delivered,
    delivery_error,
  };
}

describe("the desktop messenger surface", () => {
  it("offers a Messages destination in the sidebar", () => {
    const ids = NAV_GROUPS.flatMap((group) => group.items.map((item) => item.id));
    expect(ids).toContain("messages");
  });

  it("renders a conversation surface for the messages screen", () => {
    const markup = renderMessages(["http://127.0.0.1:8787"]);
    expect(markup).not.toBe("");
    expect(markup).toContain("New conversation");
    expect(markup).toContain("Check the relay for new messages");
  });

  it("says a relay is missing, and refuses to offer sending, when none is configured", () => {
    const withoutRelay = renderMessages([]);
    expect(withoutRelay).toContain("No message relay is configured");
    // The inbox control is the only send-or-receive action on the thread list,
    // and without a relay `messenger_poll_inbox` cannot reach anything, so the
    // control has to be off rather than offering a round trip that goes nowhere.
    expect(withoutRelay).toMatch(
      /<button[^>]*disabled=""[^>]*>Check the relay for new messages<\/button>/,
    );

    const withRelay = renderMessages(["http://127.0.0.1:8787"]);
    expect(withRelay).not.toContain("No message relay is configured");
    expect(withRelay).toMatch(
      /<button(?![^>]*disabled)[^>]*>Check the relay for new messages<\/button>/,
    );
  });

  it("does not present a loopback relay as running when the shell would not start it", () => {
    // `should_manage_relay`, crates/wallet-tauri-common/src/desktop_relay.rs:
    // both switches, or nothing is listening on the URL that is configured.
    const idle = "configured but is not running";
    expect(renderMessages(["http://127.0.0.1:8787"], false, true)).toContain(idle);
    expect(renderMessages(["http://127.0.0.1:8787"], true, false)).toContain(idle);
    expect(renderMessages(["http://127.0.0.1:8787"], true, true)).not.toContain(idle);
    // A remote relay is not this shell's to start, so the notice is wrong there.
    expect(renderMessages(["http://relay.example:8787"], false, false)).not.toContain(idle);
  });

  it("makes no claim about encryption", () => {
    const markup = renderMessages(["http://127.0.0.1:8787"]) + renderMessages([]);
    expect(markup).not.toMatch(/encrypt/i);
    expect(markup).not.toMatch(/end-to-end/i);
  });

  it("never reports a send the core did not report as accepted", () => {
    const undelivered = sendOutcome(outgoing(false));
    expect(undelivered.kind).toBe("error");
    expect(undelivered.text).toMatch(/not been delivered/i);
    expect(undelivered.text).not.toMatch(/\bsent\b/i);

    const accepted = sendOutcome(outgoing(true));
    expect(accepted.kind).toBe("success");
    expect(accepted.text).toMatch(/relay accepted/i);
  });

  it("passes on the relay's own reason for refusing, when it gave one", () => {
    // "inbox full" and "the relay is down" are different problems and only one
    // of them is worth waiting out. `messenger_send` used to discard the
    // relay's answer, so both reached this screen as the same sentence.
    const refused = sendOutcome(outgoing(false, "inbox full"));
    expect(refused.kind).toBe("error");
    expect(refused.text).toMatch(/inbox full/i);
    expect(refused.text).toMatch(/not been delivered/i);
  });

  it("explains the two wallet states the core refuses the messenger for", () => {
    // crates/wallet-core/src/wallet.rs `require_signing_account` rejects both.
    expect(messengerBlockedReason({ ...UNLOCKED, watch_only: true } as never)).toMatch(
      /watch-only/i,
    );
    expect(
      messengerBlockedReason({ ...UNLOCKED, hardware_signing_mode: "airgap_only" } as never),
    ).toMatch(/Cold Vault/);
    expect(messengerBlockedReason({ ...UNLOCKED, locked: true } as never)).toMatch(/Unlock/);
    expect(messengerBlockedReason(UNLOCKED as never)).toBeNull();
  });
});

/**
 * WHICH RELAY TOOK IT, NOT ONLY THAT ONE DID.
 *
 * `messenger_send` stops at the first relay in the list that accepts, and a
 * wallet hosting its own relay always has one that accepts, on this machine.
 * So "A relay accepted the message." was also what a person was told about a
 * message that never left the computer they typed it on, while their friend's
 * replies kept arriving through a second relay and the thread looked like a
 * conversation. The core records the URL now; this is the screen saying it.
 */
describe("what the screen says about where a message went", () => {
  const OWN: Parameters<typeof sendOutcome>[1] = {
    hosting: true,
    serving: true,
    listen_addr: "127.0.0.1:8787",
    bind: "loopback",
    loopback_only: true,
    port: 8787,
    own_url: "http://127.0.0.1:8787",
    lan_addr: null,
    lan_url: null,
    idle_reason: null,
    allowlist: [],
  own_address: "1Owner",
  served_addresses: ["1Owner"],
  serves_nobody: false,
  transaction_reach:
    "Transactions are not relayed for anybody else. This relay forwards a transaction to your fullnode only when it was submitted from this computer.",
    relay_urls: ["http://127.0.0.1:8787", "http://192.168.1.24:8787"],
  } as never;

  it("says a message accepted by this machine's own relay went no further", () => {
    const msg = { ...outgoing(true), delivered_via: "http://127.0.0.1:8787" } as never;
    const outcome = sendOutcome(msg, OWN);
    expect(outcome.kind).toBe("success");
    expect(outcome.text).toMatch(/relay accepted/i);
    expect(outcome.text).toContain("http://127.0.0.1:8787");
    expect(outcome.text).toMatch(/gone no further than this machine/i);
  });

  it("names the relay plainly when it is the one the other person uses", () => {
    const msg = { ...outgoing(true), delivered_via: "http://192.168.1.24:8787" } as never;
    expect(sendOutcome(msg, OWN).text).toContain("Accepted by http://192.168.1.24:8787.");
  });

  it("still says only what it knows about a record with no relay named", () => {
    // Records written before the wallet kept this field, and every undelivered
    // message. Nothing is invented for either.
    expect(sendOutcome(outgoing(true), OWN).text).toBe("A relay accepted the message.");
    expect(sendOutcome(outgoing(false), OWN).text).toMatch(/not been delivered/i);
  });

  it("puts the same note beside the message itself, not only in the toast", () => {
    const source = readFileSync(new URL("./MessagesScreen.tsx", import.meta.url), "utf8");
    expect(source).toMatch(/acceptedByNote\(m\.delivered_via, relayEndpoint\)/);
  });
});
