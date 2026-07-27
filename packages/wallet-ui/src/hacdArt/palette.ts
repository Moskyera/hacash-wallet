export type HacdColorPair = readonly [string, string];

/** Official Hacash HACD palette used by HIP-5, HIP-8 and the metadata card. */
export const HACD_COLOR_PAIRS: readonly HacdColorPair[] = [
  ["041B2D", "004E9A"],
  ["004E9A", "428CD4"],
  ["8A5082", "6F5F90"],
  ["6F5F90", "758EB7"],
  ["8A5082", "FF7B89"],
  ["FF7B89", "A5CAD2"],
  ["F7D6E0", "F2B5D4"],
  ["E5C1CD", "C9BBC8"],
  ["EFF7F6", "F7D6E0"],
  ["F3DBCF", "AAC9CE"],
  ["AAC9CE", "B6B4C2"],
  ["F2B5D4", "7BDFF2"],
  ["7BDFF2", "B2F7EF"],
  ["85CBCC", "A7D676"],
  ["DAAD7B", "F9E2AE"],
  ["F9E2AE", "A8DEE0"],
] as const;

export function hacdColorPair(nibble: string): HacdColorPair {
  const index = Number.parseInt(nibble, 16);
  return HACD_COLOR_PAIRS[Number.isInteger(index) ? index : 0] ?? HACD_COLOR_PAIRS[0];
}
