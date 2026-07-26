import { api, type PreparedOperationView } from "./api";
import { requestPreparedConfirmation } from "./preparedConfirm";

export async function authorizePreparedOperation(
  prepared: PreparedOperationView,
  nativeBiometricAvailable: boolean,
  biometricSendEnabled: boolean,
): Promise<void> {
  if (!prepared.authorization_required) return;
  // Show the core's description before the biometric prompt, so approval is
  // never given to a bare fingerprint request with no stated purpose.
  if (!(await requestPreparedConfirmation(prepared))) {
    throw new Error("Operation cancelled. Nothing was signed.");
  }
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
