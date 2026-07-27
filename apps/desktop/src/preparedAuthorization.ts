import { api, type PreparedOperationView } from "./api";
import { requestPreparedConfirmation } from "./preparedConfirm";
import { runWebAuthnAuth, webAuthnClientOrigin } from "./webauthn";

export async function authorizePreparedOperation(
  prepared: PreparedOperationView,
  nativeBiometricAvailable: boolean,
): Promise<void> {
  if (!prepared.authorization_required) return;
  // Show the core's description before any ceremony. Windows Hello displays the
  // text we pass it, but a WebAuthn prompt cannot show operation detail at all,
  // so without this the user approves a generic prompt and never sees what it
  // covers.
  if (!(await requestPreparedConfirmation(prepared))) {
    throw new Error("Operation cancelled. Nothing was signed.");
  }
  const status = await api.status();
  if (prepared.webauthn_required || status.webauthn_enabled) {
    if (!status.webauthn_enabled) {
      throw new Error("This exact operation requires registered WebAuthn");
    }
    const options = await api.webauthnAuthBegin(prepared.id, webAuthnClientOrigin());
    const assertion = await runWebAuthnAuth(options);
    await api.webauthnAuthFinish(prepared.id, assertion);
    return;
  }
  if (!nativeBiometricAvailable) {
    throw new Error("Windows Hello is required for this exact operation");
  }
  await api.confirmBiometricNative(prepared.id);
}
