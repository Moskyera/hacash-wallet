function bufferToBase64Url(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function base64UrlToBuffer(base64url: string): ArrayBuffer {
  const padded = base64url.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  const binary = atob(padded + pad);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function decodeOptions(optionsJson: string): CredentialCreationOptions | CredentialRequestOptions {
  const parsed = JSON.parse(optionsJson) as Record<string, unknown>;
  const publicKey = parsed.publicKey as Record<string, unknown>;
  publicKey.challenge = base64UrlToBuffer(publicKey.challenge as string);
  if (publicKey.user) {
    const user = publicKey.user as Record<string, unknown>;
    user.id = base64UrlToBuffer(user.id as string);
  }
  if (Array.isArray(publicKey.allowCredentials)) {
    publicKey.allowCredentials = (publicKey.allowCredentials as Record<string, string>[]).map(
      (c) => ({ ...c, id: base64UrlToBuffer(c.id) }),
    );
  }
  return parsed as CredentialCreationOptions | CredentialRequestOptions;
}

function serializeCredential(cred: PublicKeyCredential): string {
  const response = cred.response as AuthenticatorAttestationResponse | AuthenticatorAssertionResponse;
  const payload: Record<string, unknown> = {
    id: cred.id,
    rawId: bufferToBase64Url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufferToBase64Url(response.clientDataJSON),
    },
  };
  if ("attestationObject" in response) {
    const att = response as AuthenticatorAttestationResponse;
    (payload.response as Record<string, unknown>).attestationObject = bufferToBase64Url(
      att.attestationObject,
    );
    const pk = att.getPublicKey?.();
    if (pk) {
      (payload.response as Record<string, unknown>).publicKey = bufferToBase64Url(pk);
    }
  }
  if ("authenticatorData" in response) {
    const assert = response as AuthenticatorAssertionResponse;
    (payload.response as Record<string, unknown>).authenticatorData = bufferToBase64Url(
      assert.authenticatorData,
    );
    (payload.response as Record<string, unknown>).signature = bufferToBase64Url(assert.signature);
  }
  return JSON.stringify(payload);
}

export async function runWebAuthnRegister(optionsJson: string): Promise<string> {
  const options = decodeOptions(optionsJson) as CredentialCreationOptions;
  const cred = (await navigator.credentials.create(options)) as PublicKeyCredential | null;
  if (!cred) throw new Error("WebAuthn registration cancelled");
  return serializeCredential(cred);
}

export async function runWebAuthnAuth(optionsJson: string): Promise<string> {
  const options = decodeOptions(optionsJson) as CredentialRequestOptions;
  const cred = (await navigator.credentials.get(options)) as PublicKeyCredential | null;
  if (!cred) throw new Error("WebAuthn authentication cancelled");
  return serializeCredential(cred);
}

export function webAuthnClientOrigin(): string {
  return typeof window !== "undefined" ? window.location.origin : "";
}

export function webAuthnAvailable(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential;
}