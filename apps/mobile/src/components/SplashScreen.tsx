import WalletLogo from "./WalletLogo";

export default function SplashScreen() {
  return (
    <div className="splash-screen" role="status" aria-live="polite" aria-label="Loading HPAY Wallet">
      <WalletLogo size="splash" />
    </div>
  );
}