import { useLocale } from "../locale";
export type TabId = "home" | "pay" | "receive" | "messages" | "more";

type Props = {
  active: TabId;
  onChange: (tab: TabId) => void;
  watchOnly?: boolean;
};

const ITEMS: { id: TabId; label: string; mark: string }[] = [
  { id: "home", label: "Home", mark: "⌂" },
  { id: "pay", label: "Pay", mark: "↑" },
  { id: "receive", label: "Receive", mark: "↓" },
  { id: "messages", label: "Chat", mark: "••" },
  { id: "more", label: "More", mark: "≡" },
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