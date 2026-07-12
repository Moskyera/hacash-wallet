import iconLogoSrc from "../assets/hb-icon.png";

type Props = {
  size?: "sm" | "lg";
  alt?: string;
};

export default function WalletLogo({ size = "lg", alt = "Hacash Wallet" }: Props) {
  return (
    <img
      src={iconLogoSrc}
      alt={alt}
      className={`wallet-logo wallet-logo-${size}`}
      draggable={false}
    />
  );
}