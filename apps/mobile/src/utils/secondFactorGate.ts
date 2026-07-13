import { api } from "../api";
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

export async function maybeSecondFactorGate(opts: {
  amountMei: number;
  securityProfile?: string | null;
  biometricSendEnabled?: boolean;
  nativeBiometricAvailable?: boolean;
}): Promise<void> {
  const {
    amountMei,
    securityProfile,
    biometricSendEnabled = true,
    nativeBiometricAvailable,
  } = opts;
  if (!needsSecondFactor(amountMei, securityProfile)) return;

  if (nativeBiometricAvailable && biometricSendEnabled) {
    await api.confirmBiometric();
    return;
  }

  throw new Error("Enable biometric confirm in Security for large sends");
}