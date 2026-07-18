import type { en } from "./en";

export type MessageKey = keyof typeof en;
export type MessageCatalog = Readonly<Record<MessageKey, string>>;
