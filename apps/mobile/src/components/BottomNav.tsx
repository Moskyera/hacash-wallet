export type TabId = "home" | "pay" | "receive" | "messages" | "more";

type Props = {
  active: TabId;
  onChange: (tab: TabId) => void;
  watchOnly?: boolean;
};

const ITEMS: { id: TabId; label: string; icon: string }[] = [
  { id: "home", label: "Home", icon: "⌂" },
  { id: "pay", label: "Pay", icon: "◎" },
  { id: "receive", label: "Receive", icon: "↗" },
  { id: "messages", label: "Chat", icon: "💬" },
  { id: "more", label: "More", icon: "☰" },
];

export default function BottomNav({ active, onChange, watchOnly }: Props) {
  return (
    <nav className="bottom-nav" aria-label="Main navigation">
      {ITEMS.filter((item) => !(watchOnly && item.id === "pay")).map((item) => (
        <button
          key={item.id}
          type="button"
          className={`bottom-nav-item ${active === item.id ? "active" : ""}`}
          onClick={() => onChange(item.id)}
        >
          <span className="bottom-nav-icon" aria-hidden>
            {item.icon}
          </span>
          <span>{item.label}</span>
        </button>
      ))}
    </nav>
  );
}