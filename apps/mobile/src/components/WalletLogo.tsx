import fullLogoSrc from "../assets/hb-full.png";
import iconLogoSrc from "../assets/hb-icon.png";

type Props = {
  size?: "sm" | "lg";
  alt?: string;
};

export default function WalletLogo({ size = "lg", alt = "Hacash Wallet" }: Props) {
  const src = size === "sm" ? iconLogoSrc : fullLogoSrc;
  return (
    <img
      src={src}
      alt={alt}
      className={`wallet-logo wallet-logo-${size}`}
      draggable={false}
    />
  );
}