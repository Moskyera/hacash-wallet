type Props = {
  active: boolean;
};

export default function PrivacyShield({ active }: Props) {
  if (!active) return null;
  return (
    <div className="privacy-shield" aria-hidden>
      <div className="privacy-shield-inner">
        <span className="privacy-shield-icon">🔒</span>
        <p>Hacash Wallet</p>
      </div>
    </div>
  );
}