import { hacdColorPair } from "./palette";

const LIFE_GENE_RE = /^[0-9a-f]{64}$/i;
const SAFE_SVG_RE =
  /<(?:script|foreignObject|iframe|object|embed)\b|\bon[a-z]+\s*=|(?:href|src)\s*=\s*["']?\s*(?:javascript:|https?:|data:)/i;
const RAINBOW = ["red", "orange", "yellow", "green", "cyan", "blue", "purple"] as const;

type Shape = "rect" | "rounded" | "circle" | "rhombus" | "cube";

/**
 * Render the official HIP-9 initial Life Game image used in the Hacash metadata card.
 * This is deliberately static: the wallet shows metadata and never starts the CPU-heavy
 * animated game that the Explorer offers separately.
 */
export function renderHip9Svg(lifeGene: string, size = 100): string {
  const normalized = lifeGene.toLowerCase();
  if (!LIFE_GENE_RE.test(normalized)) throw new Error("Invalid HACD life gene");
  if (!Number.isInteger(size) || size < 32 || size > 1024) {
    throw new Error("Invalid HIP-9 image size");
  }

  const bytes = Uint8Array.from(
    normalized.match(/.{2}/g)?.map((pair) => Number.parseInt(pair, 16)) ?? [],
  );
  const bits = Array.from(bytes).flatMap((byte) =>
    Array.from({ length: 8 }, (_, bit) => (byte >> (7 - bit)) & 1),
  );
  let cursor = 0;
  const selected = (modulus: number) => (bytes[cursor++] ?? 0) % modulus === 1;

  let shape: Shape = "rect";
  let lifeColor = "green";
  let background = "black";
  let colorful: "part" | "full" | null = null;

  if (selected(11)) shape = "circle";
  if (selected(11)) shape = "rhombus";
  if (selected(41)) shape = "cube";
  if (selected(21)) lifeColor = "#cd0b20";
  if (selected(21)) colorful = "part";
  if (selected(41)) colorful = "full";
  if (selected(11) && shape === "rect") shape = "rounded";
  const roundedBackground = selected(11);
  if (selected(11)) background = "silver";
  if (selected(21)) background = "none";
  if (selected(41)) {
    background = "#daad7b";
    if (lifeColor === "green") lifeColor = `#${hacdColorPair(normalized[2])[0]}`;
  }
  const irregular = selected(41);
  if (irregular) background = `#${hacdColorPair(normalized[2])[0]}`;

  let colorCounter = 0;
  const colorAt = (x: number, y: number) => {
    if (colorful === "part" && x * y !== 0 && x !== 15 && y !== 15) return lifeColor;
    if (!colorful) return lifeColor;
    const color = RAINBOW[((x + 1) * y + colorCounter) % RAINBOW.length];
    colorCounter += 1;
    return color;
  };

  const content: string[] = [];
  content.push(
    `<rect x="0" y="0" width="180" height="180"${
      roundedBackground ? ' rx="20" ry="20"' : ""
    } fill="${background}"/>`,
  );

  for (let x = 0; x < 16; x += 1) {
    for (let y = 0; y < 16; y += 1) {
      if (!bits[16 * x + y]) continue;
      content.push(renderCell(shape, x, y, colorAt(x, y)));
    }
  }

  let backdrop = "";
  let groupStyle = "";
  let viewBox = 180;
  if (irregular) {
    groupStyle = ' style="transform:scale(0.66666666667);transform-origin:center"';
    viewBox = 200;
    const colors = [
      "#041B2D",
      "#004E9A",
      "#8A5082",
      "#6F5F90",
      "#8A5082",
      "#FF7B89",
      "#F7D6E0",
      "#E5C1CD",
      "#EFF7F6",
      "#F3DBCF",
      "#AAC9CE",
      "#F2B5D4",
      "#7BDFF2",
      "#85CBCC",
      "#F9E2AE",
      "#DAAD7B",
    ];
    if (bytes[29] % 2 === 0) colors.reverse();
    const centerX = bytes[31] % 2 === 0 ? 0 : 200;
    const centerY = bytes[30] % 2 === 0 ? 0 : 200;
    backdrop = `<g>${colors
      .map(
        (color, index) =>
          `<ellipse cx="${centerX}" cy="${centerY}" rx="${200 - 7 * index}" ry="${
            200 - 7 * index
          }" fill="${color}"/>`,
      )
      .join("")}<ellipse cx="${centerX}" cy="${centerY}" rx="88" ry="88" fill="${background}"/></g>`;
  }

  const svg = `<svg class="dvhip9" version="1.2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${viewBox} ${viewBox}" width="${size}" height="${size}">${backdrop}<g${groupStyle}>${content.join(
    "",
  )}</g></svg>`;
  if (SAFE_SVG_RE.test(svg)) throw new Error("Unsafe HIP-9 renderer output");
  return svg;
}

function renderCell(shape: Shape, x: number, y: number, color: string): string {
  let left = 10 + 10 * x;
  let top = 10 + 10 * y;
  const centerX = left + 5;
  const centerY = top + 5;
  switch (shape) {
    case "cube":
      return [
        `<polygon points="${left + 4},${top - 4} ${left + 8},${top} ${left + 8},${
          top + 8
        } ${left + 4},${top + 4}" fill="#10b310"/>`,
        `<polygon points="${left - 4},${top + 4} ${left},${top + 8} ${left + 8},${
          top + 8
        } ${left + 4},${top + 4}" fill="#015801"/>`,
        `<polygon points="${left - 4},${top - 4} ${left + 4},${top - 4} ${left + 4},${
          top + 4
        } ${left - 4},${top + 4}" fill="${color}"/>`,
      ].join("");
    case "circle":
      return `<circle cx="${centerX}" cy="${centerY}" r="4" fill="${color}"/>`;
    case "rhombus":
      return `<polygon points="${centerX},${centerY - 6} ${centerX + 6},${centerY} ${centerX},${
        centerY + 6
      } ${centerX - 6},${centerY}" fill="${color}"/>`;
    case "rounded":
      return `<rect x="${left}" y="${top}" width="10" height="10" rx="3" ry="3" fill="${color}"/>`;
    case "rect":
      return `<rect x="${left}" y="${top}" width="10" height="10" fill="${color}"/>`;
  }
}
