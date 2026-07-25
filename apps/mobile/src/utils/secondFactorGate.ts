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
  const { amountMei, securityProfile } = opts;
  if (!needsSecondFactor(amountMei, securityProfile)) return;
  throw new Error(
    "Protected signing requires an exact prepared operation; this legacy authorization path is blocked.",
  );
}