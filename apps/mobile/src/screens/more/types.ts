import type {
  BillSummary,
  DustWhisperSettings,
  FastPayStatus,
  HubDiscoveryEntry,
  HubHealth,
  PlatformSecurityStatus,
  PrivacySettings,
  TxRecord,
  WalletSettings,
  WalletStatus,
} from "../../api";
import type { SavedContact } from "../../contacts";

export type MorePage =
  | "menu"
  | "history"
  | "bills"
  | "fastpay"
  | "settings"
  | "security"
  | "privacy"
  | "contacts"
  | "quantum"
  | "airgap"
  | "launchpad"
  | "whisper"
  | "messages";

export type MoreData = {
  history: TxRecord[];
  bills: BillSummary[];
  contacts: SavedContact[];
  dustWhisper?: DustWhisperSettings;
  privacy: PrivacySettings;
  settings: WalletSettings | null;
  hubHealth: HubHealth | null;
  platformSec: PlatformSecurityStatus | null;
  status: WalletStatus | null;
  fastPay: FastPayStatus | null;
  watchOnly: boolean;
  statusAddress?: string | null;
  clipboardSecs: number;
  busy: boolean;
};

export type MoreActions = {
  onBack: () => void;
  onNavigate: (page: MorePage) => void;
  onClearHistory: () => void;
  onSaveSettings: (
    nodeUrl: string,
    hubUrl: string,
    fallbackUrls: string[],
    autoFailover: boolean,
  ) => void;
  onApplyHub: (entry: HubDiscoveryEntry) => Promise<void>;
  onSaveWalletName: () => void;
  onChangePassphrase: (oldPass: string, newPass: string) => void;
  onResetWallet: () => void;
  onLock: () => void;
  onPersistPrivacy: (patch: Partial<PrivacySettings>) => void;
  onSelectContact: (c: SavedContact) => void;
  onGoPayPeer: (peer: string) => void;
  onGoLegacySend: () => void;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  onSelectBill: (bill: BillSummary) => void;
  onRefresh: () => Promise<void>;
  setBusy: (b: boolean) => void;
  setContacts: (c: SavedContact[]) => void;
  walletNameDraft: string;
  setWalletNameDraft: (v: string) => void;
};
