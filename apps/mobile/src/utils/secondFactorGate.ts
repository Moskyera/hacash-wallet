import { BIOMETRIC_THRESHOLD_MEI } from "./appConstants";

/**
 * Mirror of `authorization_requirement()` in
 * crates/wallet-core/src/wallet/authorization_service.rs.
 *
 * The core is the only authority. This exists so the interface can warn, and can
 * route a payment to the rail that supports authorization, before the core has to
 * refuse. It must never be more permissive than the core: where it is, the user gets
 * a raw policy error at the moment of paying instead of a usable hint.
 */
export function needsSecondFactor(
  amountMei: number,
  securityProfile?: string | null,
  hardwareMode?: string | null,
): boolean {
  // A hardware gate and a Cold Vault both demand a factor for every amount. The
  // profile threshold cannot express that, so it is checked first.
  if (hardwareMode === "webauthn_gate" || hardwareMode === "airgap_only") {
    return true;
  }
  if (securityProfile === "paranoid") {
    return true;
  }
  // The core rounds the policed amount up before comparing (hip23::policy_amount_mei_ceil),
  // so 99.5 HAC does require a factor even though the threshold reads as 100.
  return Math.ceil(amountMei) >= BIOMETRIC_THRESHOLD_MEI;
}

export async function maybeSecondFactorGate(opts: {
  amountMei: number;
  securityProfile?: string | null;
  hardwareMode?: string | null;
  biometricSendEnabled?: boolean;
  nativeBiometricAvailable?: boolean;
}): Promise<void> {
  const { amountMei, securityProfile, hardwareMode } = opts;
  if (!needsSecondFactor(amountMei, securityProfile, hardwareMode)) return;
  throw new Error(
    "Protected signing requires an exact prepared operation; this legacy authorization path is blocked.",
  );
}
