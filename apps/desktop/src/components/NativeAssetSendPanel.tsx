import {
  NativeAssetSendForm,
  type NativeAssetBalance,
  type NativeAssetSendPreview,
} from "@hacash/wallet-ui";
import { api } from "../api";
import { authorizePreparedOperation } from "../preparedAuthorization";
import { formatInvokeError } from "../formatInvokeError";
import { maskAddress } from "../privacy";

type Props = {
  active: boolean;
  assets: readonly NativeAssetBalance[];
  busy: boolean;
  setBusy: (busy: boolean) => void;
  nativeBioAvailable: boolean;
  watchOnly: boolean;
  hideBalances: boolean;
  hideAddresses: boolean;
  onNotify: (message: string, kind: "success" | "info" | "error") => void;
  onSent: () => Promise<void>;
};

export default function NativeAssetSendPanel({
  active,
  assets,
  busy,
  setBusy,
  nativeBioAvailable,
  watchOnly,
  hideBalances,
  hideAddresses,
  onNotify,
  onSent,
}: Props) {
  const confirm = async (preview: NativeAssetSendPreview) => {
    const prepared = await api.prepareSendNativeAsset(
      preview.to,
      preview.serial,
      preview.amount,
    );
    await authorizePreparedOperation(prepared, nativeBioAvailable);
    const result = await api.executePreparedNativeAsset(prepared.id);
    onNotify(`HIP-20 transfer submitted: ${result.tx_hash}`, "success");
    await onSent();
  };

  return (
    <NativeAssetSendForm
      active={active}
      assets={assets}
      busy={busy}
      watchOnly={watchOnly}
      hideBalances={hideBalances}
      formatAddress={(address) => maskAddress(address, hideAddresses)}
      onBusy={setBusy}
      loadMetadata={api.queryNativeAssetMetadata}
      onPreview={api.previewSendNativeAsset}
      onConfirm={confirm}
      onError={(error) => onNotify(formatInvokeError(error), "error")}
    />
  );
}
