import { useLocale } from "../locale";

export type TabId = "home" | "pay" | "receive" | "hacd" | "more";
type NavItemId = "home" | "pay" | "receive" | "agent" | "more";

type Props = {
  active: TabId;
  onChange: (tab: TabId) => void;
  onOpenAgent?: () => void;
  watchOnly?: boolean;
};

const ITEMS: NavItemId[] = ["home", "pay", "receive", "agent", "more"];

export default function BottomNav({ active, onChange, onOpenAgent, watchOnly }: Props) {
  const { t } = useLocale();
  const label = (item: NavItemId): string => {
    if (item === "pay") return t("nav.send");
    if (item === "agent") return "Agent";
    if (item === "more") return t("nav.more");
    return t(`nav.${item}`);
  };
  return (
    <nav className="bottom-nav" aria-label={t("nav.mainLabel")}>
      {ITEMS.filter((item) => !(watchOnly && item === "pay")).map((item) => {
        const selected = item !== "agent" && active === item;
        return (
          <button
            key={item}
            type="button"
            className={`bottom-nav-item ${selected ? "active" : ""}`}
            aria-current={selected ? "page" : undefined}
            onClick={() => item === "agent" ? onOpenAgent?.() : onChange(item)}
          >
            <NavIcon kind={item} />
            <span>{label(item)}</span>
          </button>
        );
      })}
    </nav>
  );
}

function NavIcon({ kind }: { kind: NavItemId }) {
  if (kind === "home") return <svg className="bottom-nav-icon" viewBox="0 0 24 24" aria-hidden><path d="M3 11.5 12 4l9 7.5v8H6v-8" /><path d="M10 20v-5h4v5" /></svg>;
  if (kind === "pay") return <svg className="bottom-nav-icon" viewBox="0 0 24 24" aria-hidden><path d="M5 12h14M14 7l5 5-5 5" /><path d="M5 6v12" /></svg>;
  if (kind === "receive") return <svg className="bottom-nav-icon" viewBox="0 0 24 24" aria-hidden><path d="M12 4v13M7 12l5 5 5-5" /><path d="M5 20h14" /></svg>;
  if (kind === "agent") return <svg className="bottom-nav-icon" viewBox="0 0 24 24" aria-hidden><rect x="5" y="7" width="14" height="12" rx="3" /><path d="M12 3v4M8 12h.01M16 12h.01M9 16h6" /></svg>;
  return <svg className="bottom-nav-icon" viewBox="0 0 24 24" aria-hidden><rect x="4" y="4" width="6" height="6" rx="1" /><rect x="14" y="4" width="6" height="6" rx="1" /><rect x="4" y="14" width="6" height="6" rx="1" /><rect x="14" y="14" width="6" height="6" rx="1" /></svg>;
}