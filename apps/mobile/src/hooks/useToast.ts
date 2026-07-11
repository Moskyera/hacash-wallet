import { useCallback, useEffect, useRef, useState } from "react";

export type ToastKind = "success" | "info" | "error";

const TOAST_MS = 4000;

export function useToast() {
  const [toast, setToast] = useState<{ msg: string; kind: ToastKind } | null>(null);
  const toastTimer = useRef<number | null>(null);

  const showToast = useCallback((msg: string, kind: ToastKind = "info") => {
    if (toastTimer.current != null) {
      window.clearTimeout(toastTimer.current);
    }
    setToast({ msg, kind });
    toastTimer.current = window.setTimeout(() => {
      setToast(null);
      toastTimer.current = null;
    }, TOAST_MS);
  }, []);

  useEffect(() => {
    return () => {
      if (toastTimer.current != null) window.clearTimeout(toastTimer.current);
    };
  }, []);

  return { toast, showToast };
}