import { api, type PreparedOperationView } from "./api";

export async function authorizePreparedOperation(
  prepared: PreparedOperationView,
  nativeBiometricAvailable: boolean,
  biometricSendEnabled: boolean,
): Promise<void> {
  if (!prepared.authorization_required) return;
  if (prepared.webauthn_required) {
    throw new Error(
      "This exact operation requires WebAuthn. Use the desktop wallet or change the authenticated security policy.",
    );
  }
  if (!nativeBiometricAvailable || !biometricSendEnabled) {
    throw new Error("Enable biometric confirmation for this exact operation");
  }
  await api.confirmBiometric(prepared.id);
}
