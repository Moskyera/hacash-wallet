import { useCallback, useEffect, useRef, useState } from "react";

export type Type4ProbeFailureKind = "unsupported" | "other";

export type Type4ProbeResult =
  | { status: "ok"; balance: number }
  | { status: "failed"; message: string; kind: Type4ProbeFailureKind };

export type Type4Probe =
  | { status: "idle" }
  | { status: "loading" }
  | Type4ProbeResult;

export function canOpenLegacyFund(probe: Type4Probe): boolean {
  return probe.status === "ok";
}

export function type4Balance(probe: Type4Probe): number | null {
  return probe.status === "ok" ? probe.balance : null;
}

function defaultFormatError(error: unknown): string {
  if (typeof error === "string") return error;
  if (error instanceof Error) return error.message;
  return String(error);
}

export function useType4Probe(
  accountKey: string | null | undefined,
  load: () => Promise<Type4ProbeResult>,
  formatError: (error: unknown) => string = defaultFormatError,
) {
  const [probe, setProbe] = useState<Type4Probe>({ status: "idle" });
  const requestId = useRef(0);

  const refresh = useCallback(async () => {
    const currentRequest = ++requestId.current;
    if (!accountKey) {
      setProbe({ status: "idle" });
      return;
    }

    setProbe({ status: "loading" });
    try {
      const next = await load();
      if (requestId.current === currentRequest) setProbe(next);
    } catch (error) {
      if (requestId.current === currentRequest) {
        setProbe({ status: "failed", kind: "other", message: formatError(error) });
      }
    }
  }, [accountKey, formatError, load]);

  useEffect(() => {
    void refresh();
    return () => {
      requestId.current += 1;
    };
  }, [refresh]);

  return { probe, refresh };
}
