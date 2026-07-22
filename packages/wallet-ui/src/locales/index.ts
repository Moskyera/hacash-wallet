import { en } from "./en";
import { el } from "./el";
import { zhCN } from "./zh-CN";
import { ja } from "./ja";
import { tr } from "./tr";
import { vi } from "./vi";
import { ru } from "./ru";
import { es } from "./es";
import { fr } from "./fr";
import { pt } from "./pt";
import { ar } from "./ar";
import { sv } from "./sv";
import { de } from "./de";
import type { AppLocale } from "./config";
import type { MessageCatalog } from "./types";

export const messages = {
  en,
  el,
  "zh-CN": zhCN,
  ja,
  tr,
  vi,
  ru,
  es,
  fr,
  pt,
  ar,
  sv,
  de,
} satisfies Record<AppLocale, MessageCatalog>;

export { SUPPORTED_LOCALES } from "./config";
export type { AppLocale } from "./config";
export type { MessageCatalog, MessageKey } from "./types";
