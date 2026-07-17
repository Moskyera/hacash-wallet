import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

export type AppLocale = "en" | "el";

const STORAGE_KEY = "hacash-wallet-locale";

const messages: Record<AppLocale, Record<string, string>> = {
  en: {
    "language.label": "Language",
    "language.english": "English",
    "language.greek": "Greek",
    "group.wallet": "Wallet",
    "group.tools": "Tools",
    "group.control": "Control",
    "nav.home": "Home",
    "nav.send": "Send assets",
    "nav.receive": "Receive",
    "nav.history": "History",
    "nav.fastpay": "Fast Pay",
    "nav.hacd": "HACD",
    "nav.quantum": "Quantum Lab",
    "nav.airgap": "Air-gap QR",
    "nav.security": "Security",
    "nav.privacy": "Privacy",
    "nav.settings": "Settings",
    "nav.advanced": "Advanced",
    "nav.pay": "Pay",
    "nav.messages": "Chat",
    "nav.more": "More",
    "privacy.hidden": "Wallet hidden",
    "privacy.focus": "Focus the window to view balances and addresses.",
    "more.wallet": "Wallet",
    "more.preferences": "Preferences",
    "more.transactions": "Transaction history",
    "more.bills": "Dispute bills",
    "more.contacts": "Contacts",
    "more.hacd": "HACD collection",
    "more.quantum": "Quantum Lab",
    "more.airgap": "Air-gap (L1 QR)",
    "more.launchpad": "HACD Launchpad",
    "quantum.lab.title": "Quantum Lab",
    "quantum.lab.tagline": "Experimental Type 4 / post-quantum workspace",
    "quantum.lab.disclaimer":
      "This is a lab, not a production quantum wallet. Type 4 (PQC/hybrid) accounts are experimental and are not fully supported on stock mainnet nodes. Create keys and test only on nodes that explicitly support Type 4. Do not send large amounts unless you understand the risk.",
    "hacd.title": "HACD",
    "hacd.subtitle": "Your diamonds as full on-chain metadata cards (Explorer style).",
    "hacd.refresh": "Refresh",
    "hacd.refreshing": "Refreshing…",
    "hacd.send": "Send HACD",
    "hacd.lookup": "Look up any diamond",
    "hacd.lookupHint": "4–6 letters. Owned diamonds load automatically; lookup works for any name on mainnet.",
    "hacd.lookupBadge": "Lookup (not in this wallet)",
    "hacd.empty": "No verified HACD found on the configured node.",
    "hacd.emptyHint": "Diamonds appear after the node lists them for your address. You can still look up a name above.",
    "hacd.unlockFirst": "Unlock the wallet to load your HACD collection.",
    "more.network": "Network settings",
    "more.language": "Language",
    "more.back": "Back",
    "node.official": "Official Hacash node",
    "node.officialUrl": "http://nodeapi.hacash.org",
    "node.usingOfficial": "Using the official public node API.",
    "node.change": "Change node",
    "node.useOfficial": "Use official node",
    "node.customTitle": "Custom node",
    "node.customHint": "Only change this if you run your own Hacash node or need a private endpoint.",
    "node.grapheneTitle": "GrapheneOS / de-Googled phones",
    "node.grapheneHelp":
      "Same APK as other Android. In app info enable Network permission. Install from Files if the browser blocks APKs. Official node uses plain HTTP (nodeapi.hacash.org) — VPN/filters can block it. No separate Graphene build is required.",
    "status.on": "on",
    "status.off": "off",
    "quantum.funding.title": "Fund quantum account",
    "quantum.funding.createFirst": "Create or import a quantum keystore first, then fund it from your legacy wallet.",
    "quantum.funding.warning": "Fund this address only on a network and node with active Type 4 support. Verify the balance check before sending legacy HAC.",
    "quantum.funding.balance": "Quantum balance",
    "quantum.funding.checking": "Checking Type 4 balance support...",
    "quantum.funding.verified": "Type 4 balance query verified.",
    "quantum.funding.unsupported": "The selected node rejected this Type 4 address. Do not fund it through this node.",
    "quantum.funding.failed": "Balance check failed",
    "quantum.funding.legacy": "Legacy wallet",
    "quantum.funding.copy": "Copy",
    "quantum.funding.openLegacy": "Open legacy payment",
    "quantum.funding.verifyFirst": "Verify Type 4 balance support first",
  },
  el: {
    "language.label": "Γλώσσα",
    "language.english": "Αγγλικά",
    "language.greek": "Ελληνικά",
    "group.wallet": "Πορτοφόλι",
    "group.tools": "Εργαλεία",
    "group.control": "Ρυθμίσεις",
    "nav.home": "Αρχική",
    "nav.send": "Αποστολή",
    "nav.receive": "Λήψη",
    "nav.history": "Ιστορικό",
    "nav.fastpay": "Fast Pay",
    "nav.hacd": "HACD",
    "nav.quantum": "Quantum Lab",
    "nav.airgap": "Air-gap QR",
    "nav.security": "Ασφάλεια",
    "nav.privacy": "Ιδιωτικότητα",
    "nav.settings": "Ρυθμίσεις",
    "nav.advanced": "Για προχωρημένους",
    "nav.pay": "Πληρωμή",
    "nav.messages": "Συνομιλία",
    "nav.more": "Περισσότερα",
    "privacy.hidden": "Το πορτοφόλι είναι κρυφό",
    "privacy.focus": "Εστίασε το παράθυρο για να δεις υπόλοιπα και διευθύνσεις.",
    "more.wallet": "Πορτοφόλι",
    "more.preferences": "Προτιμήσεις",
    "more.transactions": "Ιστορικό συναλλαγών",
    "more.bills": "Αποδείξεις διαφορών",
    "more.contacts": "Επαφές",
    "more.hacd": "Συλλογή HACD",
    "more.quantum": "Quantum Lab",
    "more.airgap": "Air-gap (L1 QR)",
    "more.launchpad": "HACD Launchpad",
    "quantum.lab.title": "Quantum Lab",
    "quantum.lab.tagline": "Πειραματικός χώρος Type 4 / post-quantum",
    "quantum.lab.disclaimer":
      "Είναι lab, όχι production quantum wallet. Οι λογαριασμοί Type 4 (PQC/hybrid) είναι πειραματικοί και δεν υποστηρίζονται πλήρως από τα stock mainnet nodes. Δημιούργησε κλειδιά και δοκίμασε μόνο σε nodes με ρητή υποστήριξη Type 4. Μην στέλνεις μεγάλα ποσά αν δεν καταλαβαίνεις τον κίνδυνο.",
    "hacd.title": "HACD",
    "hacd.subtitle": "Τα diamonds σου ως πλήρεις on-chain metadata cards (στυλ Explorer).",
    "hacd.refresh": "Ανανέωση",
    "hacd.refreshing": "Ανανέωση…",
    "hacd.send": "Αποστολή HACD",
    "hacd.lookup": "Αναζήτηση diamond",
    "hacd.lookupHint": "4–6 γράμματα. Τα δικά σου φορτώνουν αυτόματα· η αναζήτηση δουλεύει για οποιοδήποτε όνομα στο mainnet.",
    "hacd.lookupBadge": "Αναζήτηση (όχι σε αυτό το πορτοφόλι)",
    "hacd.empty": "Δεν βρέθηκαν επιβεβαιωμένα HACD στο ρυθμισμένο node.",
    "hacd.emptyHint": "Τα diamonds εμφανίζονται όταν το node τα επιστρέψει για τη διεύθυνσή σου. Μπορείς να ψάξεις όνομα παραπάνω.",
    "hacd.unlockFirst": "Ξεκλείδωσε το πορτοφόλι για να φορτωθεί η συλλογή HACD.",
    "more.network": "Ρυθμίσεις δικτύου",
    "more.language": "Γλώσσα",
    "more.back": "Πίσω",
    "node.official": "Επίσημο Hacash node",
    "node.officialUrl": "http://nodeapi.hacash.org",
    "node.usingOfficial": "Χρησιμοποιείται το επίσημο public node API.",
    "node.change": "Αλλαγή node",
    "node.useOfficial": "Χρήση επίσημου node",
    "node.customTitle": "Προσαρμοσμένο node",
    "node.customHint": "Άλλαξέ το μόνο αν τρέχεις δικό σου Hacash node ή ιδιωτικό endpoint.",
    "node.grapheneTitle": "GrapheneOS / de-Googled τηλέφωνα",
    "node.grapheneHelp":
      "Ίδιο APK με τα άλλα Android. Στις πληροφορίες εφαρμογής ενεργοποίησε Network permission. Εγκατάσταση από Files αν ο browser μπλοκάρει APK. Το επίσημο node είναι HTTP (nodeapi.hacash.org) — VPN/φίλτρα μπορεί να το κόβουν. Δεν χρειάζεται ξεχωριστό build για Graphene.",
    "status.on": "ενεργό",
    "status.off": "ανενεργό",
    "quantum.funding.title": "Χρηματοδότηση quantum λογαριασμού",
    "quantum.funding.createFirst": "Δημιούργησε ή εισήγαγε πρώτα ένα quantum keystore και μετά χρηματοδότησέ το από το κανονικό πορτοφόλι.",
    "quantum.funding.warning": "Χρηματοδότησε αυτή τη διεύθυνση μόνο σε δίκτυο και node με ενεργή υποστήριξη Type 4. Επιβεβαίωσε πρώτα τον έλεγχο υπολοίπου.",
    "quantum.funding.balance": "Quantum υπόλοιπο",
    "quantum.funding.checking": "Έλεγχος υποστήριξης Type 4...",
    "quantum.funding.verified": "Ο έλεγχος υπολοίπου Type 4 επιβεβαιώθηκε.",
    "quantum.funding.unsupported": "Το επιλεγμένο node απέρριψε αυτή τη διεύθυνση Type 4. Μην τη χρηματοδοτήσεις μέσω αυτού του node.",
    "quantum.funding.failed": "Ο έλεγχος υπολοίπου απέτυχε",
    "quantum.funding.legacy": "Κανονικό πορτοφόλι",
    "quantum.funding.copy": "Αντιγραφή",
    "quantum.funding.openLegacy": "Άνοιγμα κανονικής πληρωμής",
    "quantum.funding.verifyFirst": "Επιβεβαίωσε πρώτα την υποστήριξη Type 4",
  },
};

type LocaleContextValue = {
  locale: AppLocale;
  setLocale: (locale: AppLocale) => void;
  t: (key: string) => string;
};

const LocaleContext = createContext<LocaleContextValue | null>(null);

function initialLocale(): AppLocale {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved === "en" || saved === "el") return saved;
  } catch {
    // Storage can be disabled. Browser language remains a safe fallback.
  }
  return navigator.language.toLowerCase().startsWith("el") ? "el" : "en";
}

export function LocaleProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<AppLocale>(initialLocale);

  const setLocale = (next: AppLocale) => {
    setLocaleState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Keep the in-memory selection when storage is unavailable.
    }
  };

  useEffect(() => {
    document.documentElement.lang = locale;
  }, [locale]);

  const value = useMemo<LocaleContextValue>(
    () => ({
      locale,
      setLocale,
      t: (key) => messages[locale][key] ?? messages.en[key] ?? key,
    }),
    [locale],
  );

  return <LocaleContext.Provider value={value}>{children}</LocaleContext.Provider>;
}

export function useLocale(): LocaleContextValue {
  const value = useContext(LocaleContext);
  if (!value) throw new Error("useLocale must be used inside LocaleProvider");
  return value;
}

export function LanguageSwitcher({ className = "" }: { className?: string }) {
  const { locale, setLocale, t } = useLocale();
  return (
    <label className={`language-switcher ${className}`.trim()}>
      <span>{t("language.label")}</span>
      <select
        aria-label={t("language.label")}
        value={locale}
        onChange={(event) => setLocale(event.target.value as AppLocale)}
      >
        <option value="en">{t("language.english")}</option>
        <option value="el">{t("language.greek")}</option>
      </select>
    </label>
  );
}
