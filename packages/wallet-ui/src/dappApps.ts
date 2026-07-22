export type WalletDapp = Readonly<{
  id: "hacd-launchpad";
  name: string;
  descriptionKey: "dapp.hacdLaunchpadDescription";
  origin: "https://hacd.it";
  launchUrl: "https://hacd.it/launchpad";
}>;

/**
 * Reviewed dApps are compiled into the wallet. No URL or origin comes from
 * user input, remote metadata, or a page controlled by a dApp.
 */
export const WALLET_DAPP_CATALOG: readonly WalletDapp[] = Object.freeze([
  Object.freeze({
    id: "hacd-launchpad",
    name: "HACD Launchpad",
    descriptionKey: "dapp.hacdLaunchpadDescription",
    origin: "https://hacd.it",
    launchUrl: "https://hacd.it/launchpad",
  }),
]);

export type WalletDappId = WalletDapp["id"];

export function walletDappById(id: string | null): WalletDapp | null {
  return WALLET_DAPP_CATALOG.find((app) => app.id === id) ?? null;
}

export function isCatalogDappOrigin(origin: string): boolean {
  return WALLET_DAPP_CATALOG.some((app) => app.origin === origin);
}

export type DappConnectionState =
  | { status: "checking" }
  | { status: "disconnected" }
  | { status: "connecting" }
  | { status: "connected"; address: string }
  | { status: "disconnecting"; address: string }
  | { status: "error" };

export function canOpenDapp(connection: DappConnectionState): boolean {
  return connection.status === "connected";
}

export function shortWalletAddress(address: string): string {
  const clean = address.trim();
  if (clean.length <= 20) return clean;
  return `${clean.slice(0, 10)}...${clean.slice(-8)}`;
}
