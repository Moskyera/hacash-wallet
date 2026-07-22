import { useMemo } from "react";
import { openUrl } from "@tauri-apps/plugin-opener";
import {
  OwnedHacdGallery,
  translatedHacdMetadataCopy,
  translatedOwnedHacdGalleryCopy,
} from "@hacash/wallet-ui";

import { api } from "../api";
import { useLocale } from "../locale";

type Props = {
  locked: boolean;
  busy: boolean;
  onToast: (msg: string, kind: "success" | "info" | "error") => void;
  onGoPay?: () => void;
};

/** My HACD shows only metadata cards verified as owned by the active wallet. */
export default function HacdTab({ locked, busy, onToast }: Props) {
  const { t } = useLocale();
  const copy = useMemo(() => translatedOwnedHacdGalleryCopy(t), [t]);
  const metadataCopy = useMemo(() => translatedHacdMetadataCopy(t), [t]);

  return (
    <OwnedHacdGallery
      locked={locked}
      busy={busy}
      copy={copy}
      metadataCopy={metadataCopy}
      listOwned={api.listOwnedDiamonds}
      queryDiamond={api.queryDiamond}
      openExternal={openUrl}
      onError={() => onToast(copy.loadError, "error")}
    />
  );
}