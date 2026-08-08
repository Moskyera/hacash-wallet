import { hpayFullLogoUrl, hpayMarkLogoUrl } from "@hacash/wallet-ui";

type Props = {
  size?: "sm" | "lg" | "splash";
  /** full = glossy brand with text (welcome); mark = symbol only (header, launcher) */
  variant?: "full" | "mark";
  alt?: string;
};

export default function WalletLogo({
  size = "lg",
  variant = "full",
  alt = "HPAY Wallet",
}: Props) {
  const src = variant === "mark" ? hpayMarkLogoUrl : hpayFullLogoUrl;
  const markClass = variant === "mark" ? " wallet-logo-mark" : "";

  return (
    <img
      src={src}
      alt={alt}
      className={`wallet-logo wallet-logo-${size}${markClass}`}
      draggable={false}
    />
  );
}