import { useEffect, useState } from "react";
import { api, type HacdDiamondInfo } from "../api";

type State =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; info: HacdDiamondInfo }
  | { status: "not_found" }
  | { status: "error"; message: string };

export function useHacdDiamond(name: string | null) {
  const [state, setState] = useState<State>({ status: "idle" });

  useEffect(() => {
    if (!name || name.length < 4) {
      setState({ status: "idle" });
      return;
    }

    let cancelled = false;
    setState({ status: "loading" });

    void api
      .queryDiamond(name)
      .then((info) => {
        if (cancelled) return;
        setState({ status: "ready", info });
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : String(err);
        const lower = msg.toLowerCase();
        if (
          lower.includes("not found")
          || lower.includes("cannot find diamond")
          || lower.includes("find diamond")
          || msg.includes("ret=1")
        ) {
          setState({ status: "not_found" });
          return;
        }
        setState({ status: "error", message: msg });
      });

    return () => {
      cancelled = true;
    };
  }, [name]);

  return state;
}