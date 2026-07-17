import { useLocale } from "../locale";
export type TabId = "home" | "pay" | "receive" | "hacd" | "more";

type Props = {
  active: TabId;
  onChange: (tab: TabId) => void;
  watchOnly?: boolean;
};

/** ASCII marks stay readable if the device font drops diamond glyphs. */
const ITEMS: { id: TabId; label: string; mark: string }[] = [
  { id: "home", label: "Home", mark: "H" },
  { id: "pay", label: "Pay", mark: "P" },
  { id: "receive", label: "Receive", mark: "R" },
  { id: "hacd", label: "HACD", mark: "D" },
  { id: "more", label: "More", mark: "M" },
];

export default function BottomNav({ active, onChange, watchOnly }: Props) {
  const { t } = useLocale();
  return (
    <nav className="bottom-nav" aria-label="Main navigation">
      {ITEMS.filter((item) => !(watchOnly && item.id === "pay")).map((item) => (
        <button
          key={item.id}
          type="button"
          className={`bottom-nav-item ${active === item.id ? "active" : ""}`}
          aria-current={active === item.id ? "page" : undefined}
          onClick={() => onChange(item.id)}
        >
          <span className="bottom-nav-icon" aria-hidden>{item.mark}</span>
          <span>{t(`nav.${item.id}`)}</span>
        </button>
      ))}
    </nav>
  );
}