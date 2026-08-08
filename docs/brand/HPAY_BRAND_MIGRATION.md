# HPAY Brand Migration Contract

## Approved master artwork

- Source supplied by the project owner: `hpay.png`
- Repository copy:
  `packages/wallet-ui/src/assets/hpay-wallet.png`
- Dimensions: 1254 by 1254 pixels
- Format: 24-bit RGB PNG, no alpha channel
- SHA-256:
  `EEF13D3596CF3E70F845B0F4016E18431AFC993D20BFCA87112446A24537F2E5`

The repository copy must remain byte-for-byte identical to the supplied master.

## Safe use

The owner has confirmed that HPAY is the product brand for the whole application.
My Wallet and the future AI Agent Wallet are independent security spaces inside
the same HPAY app. The master therefore represents the complete product and
contains:

- the detailed HPAY circuit mark,
- the `HPAY WALLET` lockup,
- the line `MY WALLET | AI AGENT WALLET`.

Approved presentation:

1. the complete artwork is used for welcome, unlock, splash, and unified-product
   presentation;
2. the mark-only asset is used for launcher icons, favicons, compact headers,
   notifications, and other small surfaces;
3. the app icon never includes the `HPAY` or `WALLET` letters.

The approved mark-only derivative is:

- `packages/wallet-ui/src/assets/hpay-mark.png`
- 1254 by 1254 pixels
- SHA-256:
  `304093A5C6FDE3F6BF1E60B145868D2EEBD3A1B85047AD2A1986C2C9442D0B48`

Fine embedded text must not be the only accessible label. UI text remains real,
localizable text.

## Compatibility identities that do not change

Branding must not change:

- desktop identifier `org.hacash.wallet`;
- mobile identifier/application ID/package `org.hacash.wallet.mobile`;
- Windows upgrade code `515DFC63-2FFB-5C5A-8E4F-DA9DFE4BE796`;
- Android signer and keystore identity;
- GitHub repository and updater release contract;
- `hacash-wallet-*` release asset names;
- deep-link schemes;
- the `HacashWallet` data directory;
- biometric AAD and cryptographic domain separators;
- backup magic, WebAuthn bindings, crate names, or binary names.

Changing the visible product name requires Windows, Linux, Android, updater,
and in-place-upgrade regression tests. A global replacement of “Hacash Wallet”
is prohibited because some occurrences are compatibility or security
identifiers rather than visible branding.

Branding is independent of Fast Pay. No L2 module needs to be deleted or
rewritten for this migration.
