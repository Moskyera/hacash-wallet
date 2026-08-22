import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { pollReport } from "./messengerPoll";
import type { MessengerPollOutcome } from "./api";

const HERE = dirname(fileURLToPath(import.meta.url));

function outcome(over: Partial<MessengerPollOutcome> = {}): MessengerPollOutcome {
  return {
    added: 0,
    relays_tried: 1,
    relays_answered: 1,
    relays_refused: 0,
    rejected_envelopes: 0,
    ...over,
  };
}

describe("what the inbox check is allowed to say", () => {
  it("never reports an empty inbox when no relay is configured", () => {
    const report = pollReport(outcome({ relays_tried: 0, relays_answered: 0 }));
    expect(report.kind).toBe("error");
    expect(report.text).toMatch(/no relay is configured/i);
    expect(report.text).not.toMatch(/nothing new/i);
  });

  it("never reports an empty inbox when no relay answered", () => {
    const report = pollReport(outcome({ relays_answered: 0 }));
    expect(report.kind).toBe("error");
    expect(report.text).toMatch(/no relay answered/i);
    expect(report.text).not.toMatch(/nothing new/i);
  });

  it("says a refused claim is a refusal, not an empty mailbox", () => {
    const report = pollReport(outcome({ relays_answered: 0, relays_refused: 1 }));
    expect(report.kind).toBe("error");
    expect(report.text).toMatch(/refused/i);
    expect(report.text).not.toMatch(/nothing new/i);
    expect(report.text).not.toMatch(/empty/i);
  });

  it("only says nothing new when a relay actually answered", () => {
    const report = pollReport(outcome());
    expect(report.kind).toBe("info");
    expect(report.text).toMatch(/nothing new/i);
  });

  it("counts the messages it took", () => {
    const report = pollReport(outcome({ added: 3 }));
    expect(report.kind).toBe("success");
    expect(report.text).toMatch(/3 new message/i);
  });

  it("mentions envelopes it threw away rather than hiding them", () => {
    const report = pollReport(outcome({ rejected_envelopes: 2 }));
    expect(report.text).toMatch(/2 item\(s\) were discarded/i);
  });

  it("treats a missing answer as a failure, never as an empty inbox", () => {
    for (const empty of [null, undefined]) {
      const report = pollReport(empty);
      expect(report.kind).toBe("error");
      expect(report.text).not.toMatch(/nothing new/i);
    }
  });

  it("is what both shipped screens actually call", () => {
    const mobile = readFileSync(
      join(HERE, "../../mobile/src/components/MessengerScreen.tsx"),
      "utf8",
    );
    const desktop = readFileSync(
      join(HERE, "screens/MessagesScreen.tsx"),
      "utf8",
    );
    for (const source of [mobile, desktop]) {
      expect(source).toMatch(/pollReport\(/);
      // The sentence this replaced, in both of its wordings.
      expect(source).not.toMatch(/relay had nothing new/i);
    }
  });
});
