import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { DESKTOP_CONTROLS } from "./desktopControls";
import { formatZhu } from "./AgentAdminPages";
import {
  DESKTOP_IRREVERSIBLE_ACTIONS,
  FUND_PROVIDER_CHANNEL_WARNING,
} from "./irreversibleActions";
import { OPEN_FUND_CONTROL_LABEL, OPEN_PHONE_CANNOT } from "./registryOpen";
import {
  REGISTRY_CHANNEL_NOTE_KEY,
  adoptPressResultLine,
  clearChannelNote,
  fundPressResultLine,
  readChannelNote,
  registryChannelStage,
  channelNoteFromWallet,
  mergeResumableChannel,
  registryFundingView,
  writeChannelNote,
  type RegistryChannelNote,
} from "./registryFunding";

const readRaw = (name: string) =>
  readFileSync(new URL(`./${name}`, import.meta.url), "utf8");

/** The source with its comments removed. A comment is not a rendered control. */
const read = (name: string) =>
  readRaw(name)
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/^[ \t]*\/\/.*$/gm, " ");

const ADMIN = read("AgentAdminPages.tsx");
const API = readRaw("api.ts");

/** How deep inside <details> a given index sits. 0 means always visible. */
function disclosureDepth(source: string, index: number): number {
  const before = source.slice(0, index);
  return before.split("<details").length - before.split("</details>").length;
}



const NOTE: RegistryChannelNote = {
  schema: "hpay-desktop-registry-channel-note/1",
  wallet_id: "wallet-1",
  hub_url: "http://127.0.0.1:8790",
  binding_commitment: "a".repeat(64),
  contract_address: "1AZDDEFGHIJKLMNOPQRSTUVWXYZabcdefg",
  deposit_zhu: 500_000_000,
  refunded_zhu: 500_000_000,
  required_l1_fee_zhu: 150_000_000,
  funding_transaction_hash: null,
  funding_confirmed: false,
  network_fee_zhu: null,
};

const SENT: RegistryChannelNote = {
  ...NOTE,
  funding_transaction_hash: "b".repeat(64),
};

const FUNDED: RegistryChannelNote = {
  ...SENT,
  funding_confirmed: true,
  network_fee_zhu: 30_682_605,
};

function memoryStore() {
  const cells = new Map<string, string>();
  return {
    getItem: (key: string) => cells.get(key) ?? null,
    setItem: (key: string, value: string) => void cells.set(key, value),
    removeItem: (key: string) => void cells.delete(key),
  };
}

/* -------------------------------------------------------------------------- */
/* The hop this whole file exists for: a press that reaches the funding command */
/* -------------------------------------------------------------------------- */

describe("an owner can reach the funding command from the screen", () => {
  it("has a renderer wrapper that invokes the real Tauri command", () => {
    // The command was registered in the shell and permitted in the capability
    // allowlist long before anything called it. A command nothing invokes is a
    // capability that exists for whoever reads the source and for nobody else.
    expect(API).toContain('invoke<AgentHvmRegistryFundingResult>(');
    expect(API).toContain('"agent_wallet_fund_hvm_registry_channel"');
    expect(API).toContain('invoke<AgentHvmRegistryAdoptionResult>(');
    expect(API).toContain('"agent_wallet_adopt_hvm_registry_channel"');
  });

  it("calls that wrapper from the Security page, not from a helper nobody presses", () => {
    expect(ADMIN).toContain("agentWalletApi.fundHvmRegistryChannel(overview.wallet_id)");
    expect(ADMIN).toContain("agentWalletApi.adoptHvmRegistryChannel(overview.wallet_id)");
  });

  it("puts the funding call behind a control an owner presses, and behind a second press", () => {
    const control = ADMIN.indexOf("DESKTOP_CONTROLS.fund_provider_channel");
    expect(control, "the funding control is never rendered").toBeGreaterThan(0);
    // The first press only arms the confirmation. It must not be able to spend.
    const arming = ADMIN.indexOf("onClick={() => setConfirmFund(true)}");
    expect(arming).toBeGreaterThan(0);
    expect(ADMIN.slice(arming, arming + 200)).not.toContain("fundHvmRegistryChannel");
    // The second press is the one that reaches Rust.
    const confirmBlock = ADMIN.slice(
      ADMIN.indexOf("{confirmFund ? ("),
      ADMIN.indexOf("Confirm, send the deposit"),
    );
    expect(confirmBlock).toContain("agentWalletApi.fundHvmRegistryChannel");
  });

  it("is on a panel a person can actually be looking at", () => {
    // Rendered on the Security page, in the same section stack as the exit, and
    // only where a channel can exist at all.
    const security = ADMIN.slice(ADMIN.indexOf("function SecurityPage("));
    expect(security).toContain(
      '{!overview.hvm_registry_binding && overview.pilot_enabled && fundingView && (',
    );
    expect(security).toContain('aria-label="Finishing a channel you have opened"');
  });

  it("does not reach the funding command through the manager or a test double", () => {
    // Every hop from the press to Rust is production renderer code. `api.ts`
    // owns the only `invoke` and the panel owns the only press.
    const invocations = API.split('"agent_wallet_fund_hvm_registry_channel"').length - 1;
    expect(invocations).toBe(1);
    expect(ADMIN).not.toContain("fundHvmRegistryChannelMock");
  });
});

/* -------------------------------------------------------------------------- */
/* What the press is allowed to cost, said before it                          */
/* -------------------------------------------------------------------------- */

describe("the funding press states the cost before it is pressed", () => {
  const view = registryFundingView(NOTE, formatZhu);

  it("names the exact amount and says nobody can reverse it", () => {
    expect(view.lockUpLine).toContain("5 HAC");
    expect(view.lockUpLine).toContain("cannot be cancelled once it is in a block");
    expect(view.lockUpLine).toContain("neither this app nor your provider can reverse it");
  });

  it("names the fee separately and never folds it into the deposit", () => {
    expect(view.feeLine).toContain("1.5 HAC");
    expect(view.feeLine).toContain("on top of the deposit");
    // A registry call is a contract call: the chain takes the whole gas budget
    // out of the main balance before the call runs. Quoting the network fee
    // alone understated a measured exit by a factor of ten.
    expect(view.feeLine).toContain("gas");
    expect(view.feeLine).toContain("spent");
  });

  it("says the full refund is already held, and who checked it", () => {
    expect(view.refundHeldLine).toContain("already signed a receipt returning all 5 HAC");
    expect(view.refundHeldLine).toContain("checked that signature itself");
    expect(view.refundHeldLine).toContain("from the moment this channel was opened");
    expect(view.refundHeldLine).toContain("never expires");
    expect(view.refundHeldLine).toContain("without your provider's permission");
  });

  it("says the phone can never do this, rather than not yet", () => {
    expect(view.phoneLine).toBe(OPEN_PHONE_CANNOT);
    expect(view.phoneLine).toContain("approval identity, not a Hacash spending key");
    expect(view.phoneLine).not.toMatch(/yet|soon|future release/i);
  });

  it("says what this desktop's note is, and that it decides nothing", () => {
    expect(view.noteLine).toContain("decides nothing on its own");
    expect(view.noteLine).toContain("worked out again inside this wallet");
    expect(view.noteLine).toContain("refused in its own words");
  });
});

describe("funding sits behind the irreversible-action machinery", () => {
  const entry = DESKTOP_IRREVERSIBLE_ACTIONS.find(
    (action) => action.id === "fund_provider_channel",
  );

  it("is listed there rather than carrying a confirmation shape of its own", () => {
    expect(entry).toBeDefined();
    expect(entry?.control).toBe("fund_provider_channel");
    expect(entry?.warning).toBe(FUND_PROVIDER_CHANNEL_WARNING);
    expect(entry?.confirmLabel).toBe("Confirm, send the deposit");
  });

  it("states what is locked, what it costs, and that the refund is already held", () => {
    expect(FUND_PROVIDER_CHANNEL_WARNING).toContain("This sends your deposit");
    expect(FUND_PROVIDER_CHANNEL_WARNING).toContain(
      "cannot be cancelled or reversed by this app, by your provider or by anyone else",
    );
    expect(FUND_PROVIDER_CHANNEL_WARNING).toContain(
      "network fee and the reserved gas are charged on top of the deposit",
    );
    expect(FUND_PROVIDER_CHANNEL_WARNING).toContain("spent whatever happens to the channel afterwards");
    expect(FUND_PROVIDER_CHANNEL_WARNING).toContain("you have held that full refund from the moment the channel opened");
    expect(FUND_PROVIDER_CHANNEL_WARNING).toContain("It never expires");
  });

  it("renders that warning above the control, outside any disclosure", () => {
    const warning = ADMIN.indexOf("{FUND_PROVIDER_CHANNEL_WARNING}");
    const control = ADMIN.indexOf("DESKTOP_CONTROLS.fund_provider_channel");
    expect(warning).toBeGreaterThan(0);
    expect(disclosureDepth(ADMIN, warning)).toBe(0);
    expect(control).toBeGreaterThan(warning);
  });

  it("keeps the amount, the fee and the refund out of a disclosure too", () => {
    for (const needle of [
      "{fundingView.lockUpLine}",
      "{fundingView.feeLine}",
      "{fundingView.refundHeldLine}",
    ]) {
      const index = ADMIN.indexOf(needle);
      expect(index, `${needle} is never rendered`).toBeGreaterThan(0);
      expect(disclosureDepth(ADMIN, index)).toBe(0);
    }
  });
});

/* -------------------------------------------------------------------------- */
/* Resume                                                                     */
/* -------------------------------------------------------------------------- */

describe("the screen resumes instead of pretending every press is fresh", () => {
  it("knows the three states a half-open channel can be in", () => {
    expect(registryChannelStage(NOTE)).toBe("refund_held");
    expect(registryChannelStage(SENT)).toBe("funding_sent");
    expect(registryChannelStage(FUNDED)).toBe("funded");
  });

  it("offers carrying on, not starting, once a deposit has been signed and sent", () => {
    const view = registryFundingView(SENT, formatZhu);
    expect(view.resumeLine).toContain("already been signed and handed to the network");
    expect(view.resumeLine).toContain("b".repeat(64));
    // The reading that matters to someone afraid they have paid twice.
    expect(view.resumeLine).toContain("does not sign a second transfer");
    expect(view.resumeLine).toContain("nothing here can charge you twice");
    expect(DESKTOP_CONTROLS.continue_funding_provider_channel).toBe(
      "Carry on sending the deposit",
    );
  });

  it("says nothing about resuming before there is anything to resume", () => {
    expect(registryFundingView(NOTE, formatZhu).resumeLine).toBe("");
  });

  it("stops asking for money once the deposit is in a block", () => {
    const view = registryFundingView(FUNDED, formatZhu);
    expect(view.actionSpendsMoney).toBe(false);
    expect(view.resumeLine).toContain("is in a block");
    expect(view.resumeLine).toContain("Nothing further is spent");
    expect(view.finishLine).toContain("does not ask your provider anything");
    expect(view.finishLine).toContain(DESKTOP_CONTROLS.start_exit_without_provider);
  });

  it("renders the continue label and the finish label from the control table", () => {
    expect(ADMIN).toContain("DESKTOP_CONTROLS.continue_funding_provider_channel");
    expect(ADMIN).toContain("DESKTOP_CONTROLS.finish_opening_channel");
  });

  it("hides the open form while a channel is waiting to be finished", () => {
    // Otherwise the next visit shows an empty form, which reads as though the
    // first press never happened and invites a second channel this wallet
    // would refuse anyway.
    //
    // Gated on `resumableChannel` and not on the browser note, so that a
    // wallet holding an unfinished channel hides the open form even on a
    // machine that has never stored a note.
    expect(ADMIN).toContain(
      "{!overview.hvm_registry_binding && overview.pilot_enabled && !resumableChannel && (",
    );
  });

  it("survives the app closing, and is written from the backend's own answer", () => {
    const store = memoryStore();
    writeChannelNote(store, NOTE);
    expect(store.getItem(REGISTRY_CHANNEL_NOTE_KEY)).toContain("hpay-desktop-registry-channel-note/1");
    expect(readChannelNote(store, "wallet-1")).toEqual(NOTE);
    // Another wallet's note is not this wallet's channel.
    expect(readChannelNote(store, "wallet-2")).toBeNull();
    clearChannelNote(store);
    expect(readChannelNote(store, "wallet-1")).toBeNull();
  });

  it("treats an unreadable or foreign note as no note at all", () => {
    const store = memoryStore();
    store.setItem(REGISTRY_CHANNEL_NOTE_KEY, "{not json");
    expect(readChannelNote(store, "wallet-1")).toBeNull();
    store.setItem(REGISTRY_CHANNEL_NOTE_KEY, JSON.stringify({ schema: "something-else" }));
    expect(readChannelNote(store, "wallet-1")).toBeNull();
  });

  it("gives an owner a way out of a note this desktop cannot back", () => {
    // A note is not proof of a channel. Without this, a stale note would hide
    // the open form behind a channel the wallet does not hold.
    expect(DESKTOP_CONTROLS.forget_channel_note).toBe("Forget this note");
    expect(ADMIN).toContain("DESKTOP_CONTROLS.forget_channel_note");
    expect(ADMIN).toContain("clearChannelNote(window.localStorage)");
  });

  it("drops the note the moment the wallet's own binding takes over", () => {
    expect(ADMIN).toContain("if (overview.hvm_registry_binding) {");
  });
});

/* -------------------------------------------------------------------------- */
/* Refusals                                                                   */
/* -------------------------------------------------------------------------- */

describe("refusals are rendered plainly, where the press was", () => {
  it("captures the refusal of every one of the three presses", () => {
    // Three catch blocks, one per press, each of which shows the backend's own
    // sentence rather than the page banner swallowing it.
    expect(ADMIN.split("setChannelRefusal(readableError(reason))").length - 1).toBe(3);
  });

  it("renders it on the open panel and on the finishing panel, never collapsed", () => {
    const occurrences: number[] = [];
    let index = ADMIN.indexOf("{channelRefusal}");
    while (index !== -1) {
      occurrences.push(index);
      index = ADMIN.indexOf("{channelRefusal}", index + 1);
    }
    expect(occurrences.length).toBeGreaterThanOrEqual(2);
    for (const at of occurrences) expect(disclosureDepth(ADMIN, at)).toBe(0);
  });

  it("does not paraphrase the backend, which already says nothing was spent", () => {
    // "This provider would not countersign the refund that lets you close this
    // channel on your own, so no channel was opened. Nothing was funded and
    // nothing was spent." is the Rust sentence, and it is shown as it is.
    const refusal = ADMIN.slice(ADMIN.indexOf("{channelRefusal}") - 200, ADMIN.indexOf("{channelRefusal}") + 40);
    expect(refusal).not.toContain("something went wrong");
    expect(ADMIN).toContain('<p className="agent-warning" role="status">{channelRefusal}</p>');
  });

  it("says a failed funding leaves nothing locked up", () => {
    const view = registryFundingView(NOTE, formatZhu);
    expect(view.refusalLine).toContain("nothing is locked up");
    expect(view.refusalLine).toContain("never built a second time");
  });
});

/* -------------------------------------------------------------------------- */
/* The sentence shown after a press                                           */
/* -------------------------------------------------------------------------- */

describe("the result sentence is the backend's answer, not a fixed line", () => {
  it("does not call a sent transaction a funded channel", () => {
    const line = fundPressResultLine(
      {
        schema: "hpay-agent-registry-funding-result/1",
        transaction_hash: "b".repeat(64),
        contract_address: NOTE.contract_address,
        deposit_zhu: 500_000_000,
        network_fee_zhu: 30_682_605,
        confirmed: false,
        confirmed_block_height: null,
      },
      formatZhu,
    );
    expect(line).toContain("has not yet seen it in a block");
    expect(line).toContain("pressing again hands the same transaction over");
    expect(line).not.toContain("is in the channel contract");
  });

  it("names the block and the real charge once it has confirmed", () => {
    const line = fundPressResultLine(
      {
        schema: "hpay-agent-registry-funding-result/1",
        transaction_hash: "b".repeat(64),
        contract_address: NOTE.contract_address,
        deposit_zhu: 500_000_000,
        network_fee_zhu: 30_682_605,
        confirmed: true,
        confirmed_block_height: 4_211,
      },
      formatZhu,
    );
    expect(line).toContain("is in the channel contract");
    expect(line).toContain("4211");
    expect(line).toContain("0.30682605 HAC");
    // And it does not stop there: one step is still owed, and it is named.
    expect(line).toContain(DESKTOP_CONTROLS.finish_opening_channel);
  });

  it("says the exit works only once the channel is really adopted", () => {
    const done = adoptPressResultLine({
      schema: "hpay-agent-registry-adoption-result/1",
      binding_commitment: "a".repeat(64),
      hub_address: "1AZDABCDEFGHIJKLMNOPQRSTUVWXYZabcd",
      hub_url: NOTE.hub_url,
      exit_available: true,
    });
    expect(done).toContain("Your provider was not asked and cannot undo it");
    expect(done).toContain(DESKTOP_CONTROLS.start_exit_without_provider);

    const not = adoptPressResultLine({
      schema: "hpay-agent-registry-adoption-result/1",
      binding_commitment: "",
      hub_address: "",
      hub_url: "",
      exit_available: false,
    });
    expect(not).toContain("No money moved");
  });
});

/* -------------------------------------------------------------------------- */
/* The open screen may no longer say the deposit cannot be sent               */
/* -------------------------------------------------------------------------- */

describe("the open screen points at the control that sends the deposit", () => {
  it("names it exactly as the control table does", () => {
    // Two false instructions in this codebase caused a permanent,
    // unrecoverable device revocation, and both named a control that did not
    // exist. This one is checked against the table itself.
    expect(DESKTOP_CONTROLS.fund_provider_channel).toBe(OPEN_FUND_CONTROL_LABEL);
  });

  it("no longer claims this wallet cannot send the deposit", () => {
    const source = readRaw("registryOpen.ts");
    expect(source).not.toContain("this wallet cannot send it for you yet");
  });
});

/* -------------------------------------------------------------------------- */
/* Losing the browser note must not strand a deposit                          */
/* -------------------------------------------------------------------------- */

describe("the wallet's own record is what the panel resumes from", () => {
  const IN_PROGRESS = {
    schema: "hpay-agent-registry-channel-in-progress/1",
    refund_held: true,
    deposit_zhu: 500_000_000,
    funding_transaction_hash: "39a35d66",
    funding_confirmed: true,
    funding_confirmed_block_height: 4242,
    network_fee_zhu: 1_000_000,
  } as const;

  it("rebuilds a finishable channel with no browser storage at all", () => {
    const note = channelNoteFromWallet("wallet-1", "http://127.0.0.1:8790", IN_PROGRESS, 150_000_000);
    expect(note, "a funded channel must be recoverable from the wallet alone").not.toBeNull();
    expect(note?.deposit_zhu).toBe(500_000_000);
    expect(note?.funding_transaction_hash).toBe("39a35d66");
    expect(note?.funding_confirmed).toBe(true);
    // Every channel this flow opens is refunded in full, and the wallet
    // refuses to fund one that is not.
    expect(note?.refunded_zhu).toBe(note?.deposit_zhu);
  });

  it("renders the finishing panel from that record", () => {
    const note = channelNoteFromWallet("wallet-1", "http://127.0.0.1:8790", IN_PROGRESS, 150_000_000);
    const view = registryFundingView(note!, formatZhu);
    expect(view.heading.length).toBeGreaterThan(0);
    // 500_000_000 chain zhu is five HAC, and the panel must say so.
    expect(view.lockUpLine).toContain("5 HAC");
  });

  it("offers nothing to finish before a refund is held, because nothing was spent", () => {
    expect(
      channelNoteFromWallet("wallet-1", "http://h", { ...IN_PROGRESS, refund_held: false }, 0),
    ).toBeNull();
    expect(channelNoteFromWallet("wallet-1", "http://h", null, 0)).toBeNull();
    expect(channelNoteFromWallet("wallet-1", "http://h", undefined, 0)).toBeNull();
  });

  it("prefers the wallet's record over this desktop's note, and gates both panels on the same value", () => {
    const source = readRaw("AgentAdminPages.tsx");
    expect(source).toContain("channelNoteFromWallet(");
    expect(source).toContain("openStatus?.channel_in_progress");
    // One derived value feeds the finishing panel and hides the open form, so
    // the two can never disagree about whether a channel is unfinished.
    expect(source).toContain("const resumableChannel = mergeResumableChannel(walletChannel, channelNote);");
    expect(source).toContain("overview.pilot_enabled && !resumableChannel &&");
    expect(source).toContain("const fundingView = resumableChannel");
  });

  it("asks the backend for it, rather than only writing it locally", () => {
    const source = readRaw("registryOpen.ts");
    expect(source).toContain("channel_in_progress: AgentHvmRegistryChannelInProgress | null;");
  });
  it("keeps the labels this desktop holds while the wallet decides the money", () => {
    const fromWallet = channelNoteFromWallet("wallet-1", "http://h", IN_PROGRESS, 150_000_000)!;
    const fromNote = {
      ...fromWallet,
      binding_commitment: "31db53",
      contract_address: "1CONTRACT",
      // A stale note that has not seen the deposit land. The wallet has.
      funding_transaction_hash: null,
      funding_confirmed: false,
      deposit_zhu: 1,
    };
    const merged = mergeResumableChannel(fromWallet, fromNote)!;
    // Money comes from the wallet, always.
    expect(merged.deposit_zhu).toBe(500_000_000);
    expect(merged.funding_transaction_hash).toBe("39a35d66");
    expect(merged.funding_confirmed).toBe(true);
    // Labels the wallet does not report come from the note rather than blank.
    expect(merged.binding_commitment).toBe("31db53");
    expect(merged.contract_address).toBe("1CONTRACT");
  });

  it("still resumes with no note at all, which is the case that stranded money", () => {
    const fromWallet = channelNoteFromWallet("wallet-1", "http://h", IN_PROGRESS, 150_000_000);
    expect(mergeResumableChannel(fromWallet, null)).toBe(fromWallet);
    expect(mergeResumableChannel(null, null)).toBeNull();
  });
});
