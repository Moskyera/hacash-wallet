/// WHAT THE TWO SCREENS ACTUALLY RENDER ABOUT THE RELAY THIS WALLET HOSTS.
///
/// `relayReach.test.ts` holds the sentences. This file holds the screens: it
/// renders the real Privacy and Messages screens through the real router, with
/// the report `wallet_relay_endpoint` really returns, and reads the markup.
///
/// The failure it exists to catch is a person being handed an address for a
/// socket nobody can reach. That is not a copy bug in a string somewhere, it is
/// what ends up on the screen, so this reads the screen.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

const HERE = dirname(fileURLToPath(import.meta.url));
const source = (relative: string) => readFileSync(join(HERE, relative), "utf8");

vi.mock("@tauri-apps/api/core", () => ({
  invoke: vi.fn(async () => undefined),
}));

vi.mock("@hacash/wallet-ui", async (importOriginal) => {
  const actual = await importOriginal<Record<string, unknown>>();
  return {
    ...actual,
    useLocale: () => ({ locale: "en", setLocale: () => {}, t: (key: string) => key }),
  };
});

const { default: DesktopRouter } = await import("./DesktopRouter");
type DesktopRouterProps = Parameters<typeof DesktopRouter>[0];
type RelayEndpoint = NonNullable<DesktopRouterProps["data"]["relayEndpoint"]>;

const UNLOCKED = {
  address: "1AVRUVLKKCrzMBtwvbcUgsQBd9JJmvNRT8",
  locked: false,
  watch_only: false,
  hardware_signing_mode: "software",
};

const HOSTING_LOOPBACK: RelayEndpoint = {
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
  relay_urls: ["http://127.0.0.1:8787"],
};

const HOSTING_WIDE: RelayEndpoint = {
  ...HOSTING_LOOPBACK,
  listen_addr: "0.0.0.0:8787",
  bind: "all_interfaces",
  loopback_only: false,
  lan_addr: "192.168.1.24",
  lan_url: "http://192.168.1.24:8787",
};

function render(
  screen: "privacy" | "messages",
  relayEndpoint: RelayEndpoint | null,
  /**
   * The relay list this wallet is configured with, in order.
   *
   * The order is not a preference: a send stops at the first relay that
   * accepts and polling tries every one, so a list with this wallet's own
   * relay above somebody else's is a thread that carries one direction. The
   * screens have to say so, and this is how a test puts one in that state.
   */
  relayAllowlist: string[] = [],
): string {
  const relayUrls = relayEndpoint?.relay_urls ?? ["http://127.0.0.1:8787"];
  const whisper = {
    enabled: true,
    relay_urls: relayUrls,
    fallback_direct: true,
    auto_start_relay: true,
    relay_bind: relayEndpoint?.bind ?? "loopback",
    relay_allowlist: relayAllowlist,
  };
  const props = {
    screen,
    data: {
      status: {
        ...UNLOCKED,
        dust_whisper: whisper,
      },
      dustWhisper: whisper,
      relayEndpoint,
      relayHealth: [],
      privacy: {
        hide_balances: false,
        hide_addresses: false,
        screen_privacy: false,
        store_tx_history: true,
        clipboard_clear_secs: 30,
        pause_auto_lock_dapp: true,
      },
      hideAddresses: false,
      busy: false,
    },
    actions: {
      setScreen: () => {},
      onNotify: () => {},
      onSavePrivacy: () => {},
      onSaveWhisper: async () => null,
      onClearHistory: () => {},
    },
  } as unknown as DesktopRouterProps;
  return renderToStaticMarkup(<DesktopRouter {...props} />);
}

describe("the Privacy screen, on a wallet hosting a relay on loopback", () => {
  const markup = render("privacy", HOSTING_LOOPBACK);

  it("shows the address the wallet is serving on", () => {
    expect(markup).toContain("127.0.0.1:8787");
  });

  it("says in words that this is the only machine that can reach it", () => {
    expect(markup).toContain("this computer and nothing else");
  });

  it("offers no address to hand anybody", () => {
    expect(markup).not.toContain("192.168");
    expect(markup).not.toMatch(/The address to give the other person/);
  });

  it("offers the choice to widen it, and does not take it", () => {
    // The control exists, and loopback is what is selected.
    expect(markup).toContain("Who this relay accepts connections from");
    expect(markup).toMatch(/<option value="loopback" selected=""/);
    expect(markup).not.toMatch(/<option value="all_interfaces" selected=""/);
  });

  it("does not list the consequences of a choice nobody has made", () => {
    expect(markup).not.toContain("stops being yours alone");
  });
});

describe("the Privacy screen, on a wallet accepting other machines", () => {
  const markup = render("privacy", HOSTING_WIDE);

  it("says what the socket is", () => {
    expect(markup).toContain("0.0.0.0:8787");
    expect(markup).toContain("every network this computer is on");
  });

  it("gives the address, and says it is the other person's relay list it goes in", () => {
    expect(markup).toContain("http://192.168.1.24:8787");
    expect(markup).toContain("no federation");
  });

  it("says what has to be true, where the person is deciding", () => {
    expect(markup).toContain("same network as this computer");
    expect(markup).toContain("port forwarded");
    expect(markup).toContain("carrier grade NAT");
  });

  it("does not promise the address works", () => {
    expect(markup).not.toMatch(/will be able to (?:reach|connect)/i);
  });
});

describe("the Messages screen", () => {
  it("tells a person looking for a relay that their own wallet is running one", () => {
    const markup = render("messages", HOSTING_LOOPBACK);
    expect(markup).toContain("The relay this wallet is running");
    expect(markup).toContain("127.0.0.1:8787");
    expect(markup).toContain("No other machine can reach it");
  });

  it("hands over the address only once there is one that means anything", () => {
    expect(render("messages", HOSTING_LOOPBACK)).not.toContain("192.168");
    expect(render("messages", HOSTING_WIDE)).toContain("http://192.168.1.24:8787");
  });

  it("says nothing about an address when the wallet has not answered", () => {
    const markup = render("messages", null);
    expect(markup).not.toContain("The relay this wallet is running");
  });
});

/**
 * THE SENTENCE ABOUT THE RELAY BOX, AGAINST WHAT IS IN THE BOX.
 *
 * The screen used to say "This box is empty on a new wallet because there is no
 * public relay to fill it with", one element above a textarea that the screen
 * itself had filled with `http://127.0.0.1:8787` from `DEFAULT_DUST_WHISPER`.
 * The prefill is load-bearing: that line is what makes the wallet host a relay
 * at all. The sentence was the thing that was wrong, and it was the sentence
 * that made a second person treat the prefilled line as their own typing and
 * leave it where it was.
 */
describe("the relay URL box and the paragraph above it", () => {
  const markup = render("privacy", HOSTING_LOOPBACK);

  it("does not claim the box is empty when the screen has filled it in", () => {
    // The claim that used to sit one element above a box the screen itself
    // fills in. A static render runs no effects, so the prefill is not in this
    // markup; it is in the two lines below, which is where it was invisible
    // from and why the sentence survived as long as it did.
    expect(markup).not.toContain("This box is empty on a new wallet");
    expect(source("PrivacyScreen.tsx")).toContain("DEFAULT_DUST_WHISPER.relay_urls");
    expect(source("../privacy.ts")).toMatch(
      /relay_urls: \["http:\/\/127\.0\.0\.1:8787"\]/,
    );
  });

  it("says what the line in the box is and what keeping it does", () => {
    expect(markup).toContain("which is this wallet");
    expect(markup).toMatch(/Keeping that line is what makes this wallet host one/i);
    expect(markup).toContain("docs/RUNNING-A-RELAY.md");
  });

  it("tells the second person where a friend's address goes, before they save", () => {
    expect(markup).toMatch(/their address goes above that line, or\s+replaces it/i);
    expect(markup).toMatch(/stops at the first relay in this list that accepts/i);
    expect(markup).toMatch(/always accepts/i);
    // The half that hides it: replies keep arriving.
    expect(markup).toMatch(/their\s+replies would still arrive/i);
  });
});

/** The box that says who a widened relay is for. */
describe("the allowlist control", () => {
  const markup = render("privacy", HOSTING_WIDE);

  it("is on the screen where the bind is chosen", () => {
    expect(markup).toContain("Addresses this relay carries mail for");
    expect(markup).toContain('id="relay-allowlist"');
  });

  it("says an empty box is a relay for the owner alone, and never that it is open", () => {
    expect(markup).toMatch(/Empty means the relay is for you alone/i);
    expect(markup).toMatch(/plus your own, which is added for you/i);
    expect(markup).toMatch(/refused on every route/i);
    expect(markup).not.toMatch(/carries mail for anybody who can reach it/i);
  });
});

/**
 * The configuration where everything a person sends stops on their own machine.
 */
describe("a wallet whose own relay is above somebody else's in its list", () => {
  const TRAPPED: RelayEndpoint = {
    ...HOSTING_LOOPBACK,
    relay_urls: ["http://127.0.0.1:8787", "http://192.168.1.24:8787"],
  };
  const SAFE: RelayEndpoint = {
    ...HOSTING_LOOPBACK,
    relay_urls: ["http://192.168.1.24:8787", "http://127.0.0.1:8787"],
  };

  it("says so on the Privacy screen", () => {
    const markup = render("privacy", TRAPPED);
    expect(markup).toContain("Your messages are not leaving this computer");
    expect(markup).toContain("http://192.168.1.24:8787");
  });

  it("says so on the Messages screen, where somebody is trying to reach a person", () => {
    const markup = render("messages", TRAPPED);
    expect(markup).toContain("Nothing you send is reaching the other relay in your list");
    expect(markup).toMatch(/Open Privacy to reorder the relay list/);
  });

  it("says nothing when the list is the right way round", () => {
    for (const screen of ["privacy", "messages"] as const) {
      const markup = render(screen, SAFE);
      expect(markup).not.toContain("Your messages are not leaving this computer");
      expect(markup).not.toContain("Nothing you send is reaching the other relay");
    }
  });

  it("says nothing on a wallet with one relay, which is most of them", () => {
    for (const screen of ["privacy", "messages"] as const) {
      const markup = render(screen, HOSTING_LOOPBACK);
      expect(markup).not.toContain("Your messages are not leaving this computer");
      expect(markup).not.toContain("Nothing you send is reaching the other relay");
    }
  });
});
