const KEY = "hacash_wallet_how_it_works_dismissed";

/**
 * Whether the owner has asked not to be prompted to read the explanation again.
 *
 * A display preference, so it lives in local storage rather than in wallet settings:
 * nothing here affects policy, and a settings change would need the passphrase.
 * Reads are defensive because a WebView can refuse storage, and a wallet must not fail
 * to open because a banner could not remember a choice.
 */
export function howItWorksDismissed(): boolean {
  try {
    return localStorage.getItem(KEY) === "1";
  } catch {
    return false;
  }
}

export function dismissHowItWorks(): void {
  try {
    localStorage.setItem(KEY, "1");
  } catch {
    // Nothing to recover: the prompt simply appears again next time.
  }
}
