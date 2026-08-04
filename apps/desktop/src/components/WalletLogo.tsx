import { hpayFullLogoUrl, hpayMarkLogoUrl } from "@hacash/wallet-ui";

type Props = {
  size?: "sm" | "lg";
  alt?: string;
};

export default function WalletLogo({ size = "lg", alt = "HPAY Wallet" }: Props) {
  const src = size === "sm" ? hpayMarkLogoUrl : hpayFullLogoUrl;

  return (
    <img
      src={src}
      alt={alt}
      className={`wallet-logo wallet-logo-${size}`}
      draggable={false}
    />
  );
}