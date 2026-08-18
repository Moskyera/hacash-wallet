import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DESKTOP_CONTROLS } from "./desktopControls";
import {
  DESKTOP_IRREVERSIBLE_ACTIONS,
  OPEN_PROVIDER_CHANNEL_WARNING,
} from "./irreversibleActions";
import {
  OPEN_EXIT_CONTROL_LABEL,
  OPEN_PHONE_CANNOT,
  openPressResultLine,
  registryOpenView,
  type AgentHvmRegistryOpenStatus,
} from "./registryOpen";

const readRaw = (name: string) =>
  readFileSync(new URL(`./${name}`, import.meta.url), "utf8");

/** The source with its comments removed. A comment is not a rendered warning. */
const read = (name: string) =>
  readRaw(name)
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^[ \t]*\/\/.*$/gm, " ");

const ADMIN = read("AgentAdminPages.tsx");

const formatZhu = (raw: string) => {
  const zhu = BigInt(raw);
  const whole = zhu / 1_000_000n;
  const fraction = (zhu % 1_000_000n).toString().padStart(6, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction} HAC` : `${whole} HAC`;
};

const READY: AgentHvmRegistryOpenStatus = {
  open_ready: true,
  blocked_reason: "",
  hub_url: "http://127.0.0.1:8790",
  hub_address: "1AZDABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
  hub_reachable: true,
  hub_read_error: "",
  fullnode_reachable: true,
  spendable_l1_zhu: 20_000_000,
  deposit_zhu: 5_000_000,
  required_l1_fee_zhu: 1_500_000,
  chain_transaction_count: 2,
  challenge_blocks: 6,
};

describe("the open section says what is about to be locked up", () => {
  it("names the exact deposit and says it cannot be reversed by anyone", () => {
    const view = registryOpenView(false, READY, formatZhu);
    expect(view).not.toBeNull();
    expect(view?.lockUpLine).toContain("5 HAC");
    expect(view?.lockUpLine).toContain("cannot be cancelled once it is in a block");
    // Not "your provider will not take it". The chain cannot undo it either,
    // and an owner told only the first half will look for a support desk.
    expect(view?.lockUpLine).toContain("neither this app nor your provider can reverse it");
  });

  it("says the full refund is already held, and that this wallet checked it", () => {
    const view = registryOpenView(false, READY, formatZhu);
    // The whole point of the exchange. It has to name the amount, name the
    // order, and say who did the checking, because "your provider guarantees
    // it" is exactly the sentence this design exists to stop being necessary.
    expect(view?.refundLine).toContain("Nothing is funded until");
    expect(view?.refundLine).toContain("returns the whole 5 HAC");
    expect(view?.refundLine).toContain(
      "checks that signature against its own record of the channel rather than taking your provider's word for it",
    );
    expect(view?.refundLine).toContain("never expires");
  });

  it("says a refusing provider costs nothing at all", () => {
    const view = registryOpenView(false, READY, formatZhu);
    // Nothing may be left half-funded, and the owner must be told plainly.
    expect(view?.refusalLine).toContain("no channel");
    expect(view?.refusalLine).toContain("Nothing is sent to the network");
    expect(view?.refusalLine).toContain("no fee is charged");
    expect(view?.refusalLine).toContain("nothing to undo");
  });

  it("charges the fee separately from the deposit and never folds them together", () => {
    const view = registryOpenView(false, READY, formatZhu);
    expect(view?.feeLine).toContain("1.5 HAC");
    expect(view?.feeLine).toContain("on top of the deposit");
    expect(view?.feeLine).toContain("2 transactions");
  });

  it("names the control that gets the money back out, exactly", () => {
    const view = registryOpenView(false, READY, formatZhu);
    // Two false instructions in this codebase caused a permanent,
    // unrecoverable device revocation, and both named a control that did not
    // exist. This one is checked against the control table itself.
    expect(DESKTOP_CONTROLS.start_exit_without_provider).toBe(OPEN_EXIT_CONTROL_LABEL);
    expect(view?.exitLine).toContain(OPEN_EXIT_CONTROL_LABEL);
    expect(view?.exitLine).toContain("6 blocks");
    expect(view?.exitLine).toContain("costs further network fees");
  });

  it("says the phone can never do this, rather than not yet", () => {
    const view = registryOpenView(false, READY, formatZhu);
    expect(view?.phoneLine).toBe(OPEN_PHONE_CANNOT);
    expect(OPEN_PHONE_CANNOT).toContain("never will");
    expect(OPEN_PHONE_CANNOT).toContain("approval identity, not a Hacash spending key");
    // No build gives it one, so nothing here may imply waiting for a release.
    expect(OPEN_PHONE_CANNOT).not.toMatch(/yet|soon|future release/i);
  });

  it("disappears entirely once this wallet already has a channel", () => {
    expect(registryOpenView(true, READY, formatZhu)).toBeNull();
  });
});

describe("the open is withheld with a stated reason, never silently", () => {
  it("refuses when the balance cannot cover the deposit and the fee together", () => {
    const view = registryOpenView(
      false,
      { ...READY, spendable_l1_zhu: 5_500_000 },
      formatZhu,
    );
    expect(view?.canOpen).toBe(false);
    // The deposit alone fits. The deposit plus the fee does not, and an owner
    // refused on the balance is owed the number they have to reach.
    expect(view?.openWithheldReason).toContain("6.5 HAC");
    expect(view?.openWithheldReason).toContain("5.5 HAC");
  });

  it("refuses when the provider did not answer, and says nothing was asked", () => {
    const view = registryOpenView(
      false,
      { ...READY, hub_reachable: false, hub_read_error: "connection refused" },
      formatZhu,
    );
    expect(view?.canOpen).toBe(false);
    expect(view?.openWithheldReason).toContain("Nothing has been asked of it and no money has moved");
    expect(view?.openWithheldReason).toContain("connection refused");
  });

  it("refuses when this build cannot open, in the backend's own words", () => {
    const view = registryOpenView(
      false,
      { ...READY, open_ready: false, blocked_reason: "the exact reason from Rust" },
      formatZhu,
    );
    expect(view?.canOpen).toBe(false);
    expect(view?.openWithheldReason).toBe("the exact reason from Rust");
  });

  it("still says a reachable provider can refuse to guarantee the refund", () => {
    const view = registryOpenView(false, READY, formatZhu);
    const provider = view?.preconditions.find((entry) => entry.label === "Your provider");
    expect(provider?.met).toBe(true);
    // "ready" here must not read as "your money is already guaranteed".
    expect(provider?.detail).toContain("it can refuse");
  });
});

describe("the result sentence is the backend's numbers, not the form's", () => {
  const RESULT = {
    schema: "hpay-agent-registry-open-result/1",
    binding_commitment: "a".repeat(64),
    hub_url: "http://127.0.0.1:8790",
    hub_address: "1AZDABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
    contract_address: "1AZDDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
    deposit_zhu: 5_000_000,
    refunded_zhu: 5_000_000,
    refund_bill_commitment: "c".repeat(64),
    refund_guaranteed: true,
  };

  it("reports the refund the countersigned bill actually carries", () => {
    const line = openPressResultLine(RESULT, formatZhu);
    expect(line).toContain("returning all 5 HAC");
    expect(line).toContain("checked that signature itself");
    expect(line).toContain("does not expire");
  });

  it("never claims the deposit was sent when it was not", () => {
    // The exit screen used to print one fixed "the exit has started" over
    // every answer, including answers that said nothing had. The same lie
    // here would send an owner looking for a channel balance that is not
    // there, and would hide the step they still have to take.
    const line = openPressResultLine(RESULT, formatZhu);
    expect(line).toContain("No money has moved yet");
    expect(line).toContain("has not been sent");
    expect(line).toContain("this wallet cannot send it for you yet");
    expect(line).not.toContain("locked in the contract");
  });

  it("says nothing moved when the provider did not guarantee the refund", () => {
    const line = openPressResultLine(
      { ...RESULT, refund_guaranteed: false },
      formatZhu,
    );
    expect(line).toContain("no channel was opened");
    expect(line).toContain("no money has moved");
  });
});

describe("funding sits behind the irreversible-action machinery", () => {
  const entry = DESKTOP_IRREVERSIBLE_ACTIONS.find(
    (action) => action.id === "open_provider_channel",
  );

  it("is listed there rather than carrying a confirmation shape of its own", () => {
    expect(entry).toBeDefined();
    expect(entry?.control).toBe("open_provider_channel");
    expect(entry?.warning).toBe(OPEN_PROVIDER_CHANNEL_WARNING);
    expect(entry?.confirmLabel).toBe("Confirm, open this channel");
  });

  it("warns about the deposit, the fee and the refund before the first press", () => {
    expect(OPEN_PROVIDER_CHANNEL_WARNING).toContain("commits this wallet to one provider channel and one deposit, permanently");
    expect(OPEN_PROVIDER_CHANNEL_WARNING).toContain("The press itself moves no money and costs no fee");
    expect(OPEN_PROVIDER_CHANNEL_WARNING).toContain("cannot be reversed");
    expect(OPEN_PROVIDER_CHANNEL_WARNING).toContain("spent whatever happens next");
    expect(OPEN_PROVIDER_CHANNEL_WARNING).toContain("no channel opens, nothing is sent and nothing is charged");
  });

  it("renders that warning above the control, outside any disclosure", () => {
    const warning = ADMIN.indexOf("{OPEN_PROVIDER_CHANNEL_WARNING}");
    const control = ADMIN.indexOf("{DESKTOP_CONTROLS.open_provider_channel}");
    expect(warning).toBeGreaterThan(0);
    expect(control).toBeGreaterThan(warning);
    const before = ADMIN.slice(0, warning);
    expect(before.split("<details").length - before.split("</details>").length).toBe(0);
  });

  it("takes a second press, and the second press is the one that calls Rust", () => {
    expect(ADMIN).toContain("Confirm, open this channel");
    const first = ADMIN.indexOf("onClick={() => setConfirmOpen(true)}");
    expect(first).toBeGreaterThan(0);
    const confirmBlock = ADMIN.slice(
      ADMIN.indexOf("{confirmOpen ? ("),
      ADMIN.indexOf("Confirm, open this channel"),
    );
    expect(confirmBlock).toContain("agentWalletApi.openHvmRegistryChannel");
    // The unconfirmed press must not be able to send anything.
    const firstPress = ADMIN.slice(first, first + 200);
    expect(firstPress).not.toContain("openHvmRegistryChannel");
  });
});

describe("the panel only exists where opening is possible", () => {
  it("is hidden once a channel is bound, so the exit owns the screen", () => {
    expect(ADMIN).toContain("{!overview.hvm_registry_binding && overview.pilot_enabled && (");
  });

  it("reads the provider only from what the owner typed, and never on load", () => {
    // The exit section must stay readable when every provider is unreachable,
    // so the one read on this page that touches a Hub is not part of `load`.
    const loadBody = ADMIN.slice(
      ADMIN.indexOf("const load = useCallback(async () => {"),
      ADMIN.indexOf("}, [overview.wallet_id]);"),
    );
    expect(loadBody).not.toContain("hvmRegistryOpenStatus");
    // Whitespace-collapsed: the repository checks out with CRLF on Windows and
    // a line ending is not a fact about where a call lives.
    expect(ADMIN.replace(/\s+/g, " ")).toContain(
      "agentWalletApi .hvmRegistryOpenStatus(",
    );
  });
});
