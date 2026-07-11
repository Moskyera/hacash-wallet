import { api } from "../api";
import { runWebAuthnAuth } from "../webauthn";
import { BIOMETRIC_THRESHOLD_MEI } from "./appConstants";

export function needsSecondFactor(
  amountMei: number,
  securityProfile?: string | null,
): boolean {
  return (
    securityProfile === "paranoid" ||
    (securityProfile !== "paranoid" && amountMei >= BIOMETRIC_THRESHOLD_MEI)
  );
}

export async function maybeWebAuthnGate(opts: {
  amountMei: number;
  securityProfile?: string | null;
  webauthnEnabled?: boolean;
  nativeBiometricAvailable?: boolean;
}): Promise<void> {
  const { amountMei, securityProfile, webauthnEnabled, nativeBiometricAvailable } = opts;
  if (!needsSecondFactor(amountMei, securityProfile)) return;

  if (webauthnEnabled) {
    const options = await api.webauthnAuthBegin();
    const assertion = await runWebAuthnAuth(options);
    await api.webauthnAuthFinish(assertion);
    return;
  }

  if (nativeBiometricAvailable) {
    await api.confirmBiometric();
    return;
  }

  throw new Error("Register WebAuthn or enable biometrics for large sends");
}