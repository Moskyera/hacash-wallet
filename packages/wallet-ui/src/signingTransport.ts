/**
 * Can this node be used to SIGN on this network, as the settings layer judges
 * it?
 *
 * A deliberate mirror of `validate_signing_node_url` in
 * crates/wallet-core/src/settings.rs, and nothing more. It grants nothing the
 * core would not already accept and refuses nothing the core would accept: the
 * core still enforces the rule at prepare time and again at the signing
 * boundary, and this is only used to say so on screen beforehand.
 *
 * The rule: on mainnet, signing needs HTTPS, or HTTP to a host on this same
 * machine. Nothing leaves the machine in the loopback case, which is why the
 * settings layer treats it as safe. A person running their own node is the
 * safest configuration there is and must never be the one turned away.
 *
 * Off mainnet the transport rule does not apply at all.
 */
export function mainnetSigningTransportIsEligible(
  nodeUrl: string | null | undefined,
  networkMode: string | null | undefined,
): boolean {
  if (networkMode !== "mainnet") return true;
  const raw = nodeUrl?.trim();
  if (!raw) return false;
  let parsed: URL;
  try {
    parsed = new URL(raw);
  } catch {
    return false;
  }
  if (parsed.protocol === "https:") return true;
  if (parsed.protocol !== "http:") return false;
  return isLoopbackHost(parsed.hostname);
}

/** Mirrors `is_loopback_host` in crates/wallet-core/src/settings.rs. */
export function isLoopbackHost(host: string): boolean {
  const name = host.toLowerCase().replace(/^\[|\]$/g, "");
  if (name === "localhost") return true;
  if (name === "::1" || name === "0:0:0:0:0:0:0:1") return true;
  // The whole 127.0.0.0/8 block is loopback, not just 127.0.0.1.
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(name);
  if (!ipv4) return false;
  const octets = ipv4.slice(1).map(Number);
  if (octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    return false;
  }
  return octets[0] === 127;
}
