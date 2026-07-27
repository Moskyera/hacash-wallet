/**
 * Suppresses the background lock while a system dialog the user asked for is on screen.
 *
 * Android grants the camera permission through an ActivityResultLauncher, which starts a
 * separate activity. The WebView therefore sees visibilitychange "hidden" and the wallet
 * treats it as the app being backgrounded: it locks, and the user lands on the unlock
 * screen in the middle of trying to scan a QR code. They never left the app.
 *
 * The suppression is deliberately narrow, because a background lock is a real protection
 * and this is a hole in it:
 *
 * - It only defers the lock. Concealing the screen, clearing the passphrase field and
 *   wiping the clipboard still happen, so nothing sensitive is visible in the recents
 *   list either way.
 * - It is armed only by our own code, immediately before an action the user initiated by
 *   tapping a button. Nothing reachable from a QR payload or a dApp can arm it.
 * - It expires on its own. If the dialog never resolves, the window closes and the next
 *   background event locks normally.
 * - Returning to the foreground clears it at once, so the window is usually well under a
 *   second in practice.
 */
const DEFAULT_WINDOW_MS = 15_000;

let suppressUntil = 0;

/** Call immediately before triggering a system dialog the user asked for. */
export function expectSystemDialog(windowMs: number = DEFAULT_WINDOW_MS): void {
  suppressUntil = Date.now() + windowMs;
}

/** Call when the app is in the foreground again. */
export function clearSystemDialogExpectation(): void {
  suppressUntil = 0;
}

/** True while a user-initiated system dialog may still be covering the app. */
export function systemDialogInFlight(): boolean {
  return Date.now() < suppressUntil;
}
