/**
 * What is wrong with a deposit amount, in words, before it is sent anywhere.
 *
 * The core parser (`parse_amount_mei`, crates/l2-fast-pay-hub/src/amount.rs)
 * refuses several shapes and reports every one of them as the same five words:
 * "payment amount is invalid". That is true and it is useless. The owner typed
 * `0,2` on a Greek keyboard, got those five words, and had no way to know a
 * comma was the whole problem.
 *
 * This mirrors the parser's rules exactly, and is tested against it:
 *   - empty is refused
 *   - a comma is refused (the parser only splits on `.`)
 *   - a missing leading digit is refused, so `.2` fails but `0.2` passes
 *   - at most three fraction digits, so `0.2000` fails and `0.200` passes
 *   - digits only, so a unit suffix like `0.2 HAC` fails
 *   - zero is refused separately by the caller
 *
 * It returns the reason to SHOW, not a corrected value. Silently rewriting
 * `0,2` into `0.2` would be a wallet deciding what someone meant to type about
 * money, and the one time it guesses wrong it guesses about an amount.
 */
export function explainInvalidDepositAmount(raw: string): string | null {
  const value = raw.trim();
  if (value.length === 0) {
    return "Type the amount you want to put in the channel, for example 0.2";
  }
  if (value.includes(",")) {
    return "Use a full stop for the decimal point, not a comma. Type 0.2 rather than 0,2.";
  }
  // A Hacash "unit:exponent" amount is a different, valid notation and the
  // parser accepts it. Do not second-guess it here.
  if (value.includes(":")) return null;
  const parts = value.split(".");
  if (parts.length > 2) {
    return "That has more than one decimal point.";
  }
  const [whole, fraction = ""] = parts;
  if (whole.length === 0) {
    return "Put a digit before the decimal point. Type 0.2 rather than .2.";
  }
  if (!/^\d+$/.test(whole) || (fraction.length > 0 && !/^\d+$/.test(fraction))) {
    return "Use digits only, with no spaces, letters or currency symbols.";
  }
  if (value.includes(".") && fraction.length === 0) {
    return "Put a digit after the decimal point, or remove the decimal point.";
  }
  if (fraction.length > 3) {
    return "At most three digits after the decimal point. 0.200 is the smallest step.";
  }
  if (/^0+(\.0*)?$/.test(value)) {
    return "The deposit has to be more than zero.";
  }
  return null;
}

/**
 * Whether the channel-setup review button must refuse the press.
 *
 * The reason this is a function and not an inline expression on the button is
 * that it has to be the SAME value the panel renders its explanation from. A
 * screen that names a problem and then lets the press through sends the bad
 * amount anyway, and the owner gets "payment amount is invalid" back from the
 * core: the exact five words `explainInvalidDepositAmount` exists to replace.
 *
 * It is here rather than in the panel so it can be tested without a DOM. The
 * desktop tests render to static markup and cannot type into an input, so a
 * predicate hidden inside the component is a predicate nothing can check.
 */
export function channelSetupReviewIsBlocked(hubUrl: string, deposit: string): boolean {
  return (
    hubUrl.trim().length === 0 ||
    deposit.trim().length === 0 ||
    explainInvalidDepositAmount(deposit) !== null
  );
}
