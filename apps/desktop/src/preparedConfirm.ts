import type { PreparedOperationView } from "./api";

/**
 * Shows the core's own description of a prepared operation and waits for the
 * user to accept it.
 *
 * This exists because the platform ceremony cannot be trusted to display what is
 * being approved. Windows Hello renders the text we hand it, but WebAuthn has no
 * way to show transaction detail at all: `navigator.credentials.get()` produces a
 * generic identity prompt. Without this step the trusted display is built by the
 * core, sent to the renderer, and then never seen by anyone.
 *
 * It lives outside React so `authorizePreparedOperation` can await it from plain
 * async code, which means every prepared flow gets the confirmation without each
 * call site having to remember. A security step that call sites can forget is a
 * security step that will eventually be forgotten.
 */
export type PendingConfirmation = {
  view: PreparedOperationView;
  resolve: (approved: boolean) => void;
};

type Listener = (pending: PendingConfirmation | null) => void;

let current: PendingConfirmation | null = null;
let listener: Listener | null = null;

export function subscribePreparedConfirmation(next: Listener): () => void {
  listener = next;
  next(current);
  return () => {
    if (listener === next) listener = null;
  };
}

export function requestPreparedConfirmation(
  view: PreparedOperationView,
): Promise<boolean> {
  // Fail closed. If the host is not mounted we must reject rather than return a
  // promise nobody will ever settle: a hung approval looks exactly like a frozen
  // wallet and leaves the operation open.
  if (!listener) {
    return Promise.reject(
      new Error("cannot confirm this operation: the confirmation dialog is unavailable"),
    );
  }
  // A newer operation supersedes an older one, matching the core, where preparing
  // anything new invalidates the previous ticket.
  current?.resolve(false);
  return new Promise<boolean>((resolve) => {
    const pending: PendingConfirmation = {
      view,
      resolve: (approved) => {
        if (current === pending) {
          current = null;
          listener?.(null);
        }
        resolve(approved);
      },
    };
    current = pending;
    listener?.(pending);
  });
}
