export const SUPPORTED_LOCALES = [
  { code: "en", label: "English", direction: "ltr" },
  { code: "el", label: "Ελληνικά", direction: "ltr" },
  { code: "zh-CN", label: "简体中文", direction: "ltr" },
  { code: "ja", label: "日本語", direction: "ltr" },
  { code: "tr", label: "Türkçe", direction: "ltr" },
  { code: "vi", label: "Tiếng Việt", direction: "ltr" },
  { code: "ru", label: "Русский", direction: "ltr" },
  { code: "es", label: "Español", direction: "ltr" },
  { code: "fr", label: "Français", direction: "ltr" },
  { code: "pt", label: "Português", direction: "ltr" },
  { code: "ar", label: "العربية", direction: "rtl" },
  { code: "sv", label: "Svenska", direction: "ltr" },
  { code: "de", label: "Deutsch", direction: "ltr" },
] as const;

export type AppLocale = (typeof SUPPORTED_LOCALES)[number]["code"];
