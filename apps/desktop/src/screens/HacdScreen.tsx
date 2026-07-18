import { useMemo } from "react";
import { open } from "@tauri-apps/plugin-shell";
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
  onNotify: (msg: string, kind: "success" | "info" | "error") => void;
  onGoSend?: () => void;
};

/** My HACD shows only metadata cards verified as owned by the active wallet. */
export default function HacdScreen({ locked, busy, onNotify }: Props) {
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
      openExternal={open}
      onError={() => onNotify(copy.loadError, "error")}
    />
  );
}