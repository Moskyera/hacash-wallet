import { useMemo } from "react";
import {
  HacdDiamondVisual as SharedHacdDiamondVisual,
  translatedHacdMetadataCopy,
} from "@hacash/wallet-ui";
import { open } from "@tauri-apps/plugin-shell";

import { api } from "../api";
import { useLocale } from "../locale";

export default function HacdDiamondVisual({ name }: { name: string }) {
  const { t } = useLocale();
  const copy = useMemo(() => translatedHacdMetadataCopy(t), [t]);
  return (
    <SharedHacdDiamondVisual
      name={name}
      queryDiamond={api.queryDiamond}
      openExternal={open}
      copy={copy}
    />
  );
}