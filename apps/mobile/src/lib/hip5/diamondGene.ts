const LETTER_TO_HEX: Record<string, string> = {
  W: "0",
  T: "1",
  Y: "2",
  U: "3",
  I: "4",
  A: "5",
  H: "6",
  X: "7",
  V: "8",
  M: "9",
  E: "a",
  K: "b",
  B: "c",
  S: "d",
  Z: "e",
  N: "f",
};

const NIBBLE_TO_HEX = "0123456789abcdef".split("");

/** Convert life_gene + diamond name into HIP-5 visual gene (official Hacash algorithm). */
export function diamondLifeGeneToVisualGene(lifeGeneHex: string, diamondName: string): string {
  const visualGene = new Array<string>(20);
  let k = 2;
  for (let i = 0; i < 6; i++) {
    const letter = diamondName[i] ?? "W";
    visualGene[k] = LETTER_TO_HEX[letter] ?? "0";
    k++;
  }
  for (let i = 40; i < 62; i += 2) {
    const hexPair = lifeGeneHex[i] + lifeGeneHex[i + 1];
    const x = parseInt(hexPair, 16) % 16;
    visualGene[k] = NIBBLE_TO_HEX[x] ?? "0";
    k++;
  }
  visualGene[19] = "0";
  visualGene[0] = lifeGeneHex[62] ?? "0";
  visualGene[1] = lifeGeneHex[63] ?? "0";
  return visualGene.join("");
}