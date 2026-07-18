import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  messages,
  SUPPORTED_LOCALES,
  type AppLocale,
  type MessageKey,
} from "./locales";
export { SUPPORTED_LOCALES } from "./locales";
export type { AppLocale, MessageCatalog, MessageKey } from "./locales";

const STORAGE_KEY = "hacash-wallet-locale";

const localeByCode = new Map<string, AppLocale>(
  SUPPORTED_LOCALES.map(({ code }) => [code.toLowerCase(), code]),
);

export function normalizeLocaleTag(tag: string | null | undefined): AppLocale {
  const normalized = tag?.trim().replace(/_/g, "-").toLowerCase();
  if (!normalized) return "en";

  const exact = localeByCode.get(normalized);
  if (exact) return exact;

  if (
    normalized === "zh"
    || normalized.startsWith("zh-cn")
    || normalized.startsWith("zh-sg")
    || normalized.startsWith("zh-hans")
  ) {
    return "zh-CN";
  }

  return localeByCode.get(normalized.split("-")[0] ?? "") ?? "en";
}

export function localeDirection(locale: AppLocale): "ltr" | "rtl" {
  return SUPPORTED_LOCALES.find(({ code }) => code === locale)?.direction ?? "ltr";
}

export function applyDocumentLocale(
  locale: AppLocale,
  root: Pick<HTMLElement, "lang" | "dir"> = document.documentElement,
): void {
  root.lang = locale;
  root.dir = localeDirection(locale);
}

export function validateLocaleCatalogParity(): void {
  const englishKeys = Object.keys(messages.en).sort();
  const failures: string[] = [];

  for (const { code } of SUPPORTED_LOCALES) {
    const localeKeys = Object.keys(messages[code]).sort();
    const missing = englishKeys.filter((key) => !Object.prototype.hasOwnProperty.call(messages[code], key));
    const extra = localeKeys.filter((key) => !Object.prototype.hasOwnProperty.call(messages.en, key));
    if (missing.length > 0 || extra.length > 0) {
      failures.push(`${code}: missing [${missing.join(", ")}], extra [${extra.join(", ")}]`);
    }
  }

  if (failures.length > 0) {
    throw new Error(`Locale catalog mismatch: ${failures.join("; ")}`);
  }
}

export function validateLocaleCatalogContent(): void {
  const suspicious = /\uFFFD|\?{2,}|\?(?=\p{L})/u;
  const failures: string[] = [];

  for (const { code } of SUPPORTED_LOCALES) {
    if (code === "en") continue;
    for (const [key, value] of Object.entries(messages[code])) {
      if (suspicious.test(value)) failures.push(`${code}.${key}`);
    }
  }

  if (failures.length > 0) {
    throw new Error(
      `Locale catalog contains suspicious encoding corruption: ${failures.join(", ")}`,
    );
  }
}

validateLocaleCatalogParity();
validateLocaleCatalogContent();

export type TranslationParams = Readonly<Record<string, string | number>>;

export function translate(
  locale: AppLocale,
  key: string,
  params?: TranslationParams,
): string {
  const messageKey = key as MessageKey;
  const template = messages[locale][messageKey] ?? messages.en[messageKey];
  if (!template) return key;
  if (!params) return template;

  return template.replace(/\{([A-Za-z][A-Za-z0-9_]*)\}/g, (placeholder, name: string) => {
    const value = params[name];
    return value == null ? placeholder : String(value);
  });
}

type LocaleContextValue = {
  locale: AppLocale;
  setLocale: (locale: AppLocale) => void;
  t: (key: string, params?: TranslationParams) => string;
};

const LocaleContext = createContext<LocaleContextValue | null>(null);

function initialLocale(): AppLocale {
  try {
    const saved = window.localStorage.getItem(STORAGE_KEY);
    if (saved && localeByCode.has(saved.toLowerCase())) {
      return localeByCode.get(saved.toLowerCase()) ?? "en";
    }
  } catch {
    // Storage can be disabled. Browser language remains a safe fallback.
  }

  const browserLocales = navigator.languages.length > 0
    ? navigator.languages
    : [navigator.language];
  for (const browserLocale of browserLocales) {
    const resolved = normalizeLocaleTag(browserLocale);
    if (resolved !== "en" || browserLocale.toLowerCase().startsWith("en")) {
      return resolved;
    }
  }
  return "en";
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
    applyDocumentLocale(locale);
  }, [locale]);

  const value = useMemo<LocaleContextValue>(
    () => ({
      locale,
      setLocale,
      t: (key, params) => translate(locale, key, params),
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
        onChange={(event) => {
          const next = localeByCode.get(event.target.value.toLowerCase());
          if (next) setLocale(next);
        }}
      >
        {SUPPORTED_LOCALES.map(({ code, label, direction }) => (
          <option key={code} value={code} dir={direction}>
            {label}
          </option>
        ))}
      </select>
    </label>
  );
}
