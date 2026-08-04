import {
  NativeAssetSendForm,
  type NativeAssetBalance,
  type NativeAssetSendPreview,
} from "@hacash/wallet-ui";
import { api, type PlatformSecurityStatus, type WalletSettings } from "../api";
import { authorizePreparedOperation } from "../preparedAuthorization";
import { formatInvokeError } from "../formatInvokeError";
import { maskAddress } from "../privacy";
import { hapticSuccess } from "../utils/haptic";

type Props = {
  active: boolean;
  assets: readonly NativeAssetBalance[];
  busy: boolean;
  setBusy: (busy: boolean) => void;
  settings: WalletSettings | null;
  platformSec: PlatformSecurityStatus | null;
  hideBalances: boolean;
  hideAddresses: boolean;
  onToast: (message: string, kind: "success" | "info" | "error") => void;
  onRefresh: () => Promise<void>;
};

export default function NativeAssetSendPanel({
  active,
  assets,
  busy,
  setBusy,
  settings,
  platformSec,
  hideBalances,
  hideAddresses,
  onToast,
  onRefresh,
}: Props) {
  const confirm = async (preview: NativeAssetSendPreview) => {
    const prepared = await api.prepareSendNativeAsset(
      preview.to,
      preview.serial,
      preview.amount,
    );
    await authorizePreparedOperation(
      prepared,
      platformSec?.native_biometric_available ?? false,
      settings?.biometric_send_enabled ?? true,
    );
    const result = await api.executePreparedNativeAsset(prepared.id);
    onToast(`HIP-20 transfer submitted: ${result.tx_hash}`, "success");
    hapticSuccess();
    await onRefresh();
  };

  return (
    <NativeAssetSendForm
      active={active}
      assets={assets}
      busy={busy}
      hideBalances={hideBalances}
      formatAddress={(address) => maskAddress(address, hideAddresses)}
      onBusy={setBusy}
      loadMetadata={api.queryNativeAssetMetadata}
      onPreview={api.previewSendNativeAsset}
      onConfirm={confirm}
      onError={(error) => onToast(formatInvokeError(error), "error")}
    />
  );
}
