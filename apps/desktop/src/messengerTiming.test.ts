import { describe, expect, it } from "vitest";
import { LATE_ARRIVAL_MS, arrivalNote, utcStamp } from "./messengerTiming";

function incoming(sent: string, received: string | null) {
  return { direction: "in" as const, timestamp_utc: sent, received_utc: received };
}

describe("what a held message is allowed to look like", () => {
  it("says nothing about a message that arrived when it said it was sent", () => {
    const sent = "2026-08-23T02:19:00Z";
    const received = new Date(Date.parse(sent) + 4000).toISOString();
    expect(arrivalNote(incoming(sent, received))).toBeNull();
  });

  it("marks a message the relay sat on, with a date and not just a clock", () => {
    const sent = "2026-08-20T09:00:00Z";
    const received = new Date(Date.parse(sent) + LATE_ARRIVAL_MS * 200).toISOString();
    const note = arrivalNote(incoming(sent, received));
    expect(note).toMatch(/held, arrived/);
    expect(note).toMatch(/2026-08-2/);
    expect(note).toMatch(/UTC/);
  });

  it("says nothing when the wallet has no arrival time of its own", () => {
    expect(arrivalNote(incoming("2026-08-20T09:00:00Z", null))).toBeNull();
  });

  it("says nothing about outgoing messages, which this wallet timed itself", () => {
    expect(
      arrivalNote({
        direction: "out",
        timestamp_utc: "2026-08-20T09:00:00Z",
        received_utc: "2026-08-27T09:00:00Z",
      }),
    ).toBeNull();
  });

  it("hands back an unparseable time rather than inventing one", () => {
    expect(utcStamp("not a time")).toBe("not a time");
  });
});
