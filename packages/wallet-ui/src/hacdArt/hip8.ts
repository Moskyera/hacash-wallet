import { sha3_256 } from "js-sha3";

import { hacdColorPair } from "./palette";

const VISUAL_GENE_RE = /^[0-9a-f]{20}$/i;
const SAFE_ID_RE = /[^a-zA-Z0-9_-]/g;
const SAFE_SVG_RE =
  /<(?:script|foreignObject|iframe|object|embed)\b|\bon[a-z]+\s*=|(?:href|src)\s*=\s*["']?\s*(?:javascript:|https?:|data:)/i;

type Point = { x: number; y: number };

/** Official HIP-8 brilliance artwork used by the Hacash metadata card. */
export function renderHip8Svg(
  visualGene: string,
  size = 125,
  backColor = "#ffffff66",
  idSeed = "hacd",
): string {
  const gene = visualGene.toLowerCase();
  if (!VISUAL_GENE_RE.test(gene)) throw new Error("Invalid HACD visual gene");
  if (!Number.isInteger(size) || size < 32 || size > 1024) {
    throw new Error("Invalid HIP-8 image size");
  }
  if (!/^#[0-9a-f]{6}(?:[0-9a-f]{2})?$/i.test(backColor) && backColor !== "black") {
    throw new Error("Invalid HIP-8 background color");
  }

  const uid = `${idSeed}_${gene}`.replace(SAFE_ID_RE, "").slice(0, 96) || `hacd_${gene}`;
  const gradientId = (name: string) => `${uid}_${name}`;
  const randomBytes: number[] = [];
  let digest = hashBytes(gene);
  for (let round = 0; round < 64; round += 1) {
    randomBytes.push(...digest);
    digest = hashBytes(digest);
  }
  let cursor = 0;
  const take = (max: number, base = 0) => {
    const value = randomBytes[cursor++] ?? 0;
    return (value % max) + base;
  };

  const shapes: string[] = [
    '<polygon points="0,0 1200,0 1200,1200 0,1200" fill="black"/>',
  ];
  const cornerLights = [
    [3, 3, 2, 8, 8, 2, gene[14]],
    [9, 3, 2, 2, 8, 8, gene[15]],
    [9, 9, 8, 2, 2, 8, gene[16]],
    [3, 9, 8, 8, 2, 2, gene[17]],
  ] as const;
  cornerLights.forEach((entry, index) => {
    const color = hacdColorPair(entry[6]);
    const id = gradientId(`grad1_${index}`);
    shapes.push(
      `<linearGradient id="${id}" x1="${entry[2]}0%" y1="${entry[3]}0%" x2="${
        entry[4]
      }0%" y2="${entry[5]}0%"><stop offset="0%" style="stop-color:#${
        color[0]
      };stop-opacity:${take(60) / 100 + 0.2}"/><stop offset="100%" style="stop-color:#${
        color[1]
      };stop-opacity:${take(60) / 100 + 0.2}"/></linearGradient><circle style="filter:blur(${take(
        60,
        60,
      )}px)" cx="${entry[0]}00" cy="${entry[1]}00" r="${take(
        250,
        100,
      )}" fill="url(#${id})"/>`,
    );
  });

  const opacities = [
    take(40) / 100 + 0.1,
    take(40) / 100 + 0.1,
    take(20) / 100 + 0.08,
    take(40) / 100 + 0.2,
  ];
  const blurs = [take(40) / 10, take(60) / 10 + 2, take(100) / 10 + 4, take(50) / 10 + 1];
  const kiteA = [600 - take(100), take(100), 300 + take(200), 600 - take(200)];
  const kiteB = [600 - take(100), take(100), 300 + take(200), 600 - take(200)];
  const kiteC = [600 - take(100), take(100), 300 + take(200), 600 - take(200)];
  const kiteD = [
    100 + take(200),
    100 + take(300),
    take(220),
    120 + take(120),
    take(120),
    240 + take(200),
  ];
  const kiteE = [120 + take(200), 200 + take(200), take(160), 140 + take(100)];
  const mainColors = hacdColorPair(gene[2]);
  const tangentPoints: Point[] = [
    { x: 550, y: 100 },
    { x: 380, y: 70 },
    { x: 294, y: 206 },
    { x: 415.7, y: 155 },
    { x: 446, y: 228 },
    { x: 652, y: 57 },
    { x: 600, y: 300 },
    { x: 388, y: 388 },
    { x: 600, y: 100 },
    { x: 754, y: 228 },
    { x: 505, y: 369 },
    { x: 695, y: 369 },
  ];
  const tangentGroups: Array<readonly number[] | true> = [
    [3, 4, 5],
    true,
    [4, 6, 10, 7],
    [8, 4, 6, 9],
    [6, 10, 11],
  ];
  const centerPoints: Point[] = [
    { x: 505, y: 369 },
    { x: 695, y: 369 },
    { x: 831, y: 505 },
    { x: 831, y: 696 },
    { x: 695, y: 831 },
    { x: 505, y: 831 },
    { x: 369, y: 696 },
    { x: 369, y: 505 },
  ];

  const tangentPolygon = (index: number, mirror = false) => {
    const group = tangentGroups[index];
    if (!Array.isArray(group)) return "";
    return group
      .map((pointIndex) => {
        const point = tangentPoints[pointIndex];
        return `${mirror ? 1200 - point.x : point.x},${point.y}`;
      })
      .join(" ");
  };

  for (let segment = 0; segment < 8; segment += 1) {
    shapes.push(
      `<g style="transform:rotate(${45 * segment}deg);transform-origin:center"><g style="transform:rotate(22.5deg);transform-origin:center">`,
      `<polygon points="600,${kiteA[0]} ${600 - kiteA[1]},${kiteA[2]} 600,${
        kiteA[3]
      } ${600 + kiteA[1]},${300 + take(300)}" opacity="${
        take(40) / 100 + 0.1
      }" fill="#fff" style="filter:blur(${take(80) / 10 + 4}px)"/>`,
      `<polygon points="600,${kiteB[0]} ${600 - kiteB[1]},${kiteB[2]} 600,${
        kiteB[3]
      } ${600 + kiteB[1]},${kiteB[2]}" opacity="${
        take(40) / 100 + 0.1
      }" fill="#fff" style="filter:blur(${blurs[0]}px)"/>`,
      `<polygon points="600,${kiteC[0]} ${600 - kiteC[1]},${kiteC[2]} 600,${
        kiteC[3]
      } ${600 + kiteC[1]},${kiteC[2]}" opacity="${opacities[1]}" fill="#fff" style="filter:blur(${
        blurs[1]
      }px)"/>`,
      `<polygon points="600,${kiteD[0]} ${600 - kiteD[2]},${kiteD[3]} ${
        600 - kiteD[4]
      },${kiteD[5]} 600,${kiteD[1]} ${600 + kiteD[2]},${kiteD[3]}" opacity="${
        opacities[2]
      }" fill="#fff" style="fill-rule:nonzero;filter:blur(${blurs[2]}px)"/>`,
      `<polygon points="600,${kiteE[0]} ${600 - kiteE[2]},${kiteE[3]} 600,${
        kiteE[1]
      } ${600 + kiteE[2]},${kiteE[3]}" opacity="${
        opacities[3]
      }" fill="#fff" style="fill-rule:nonzero;filter:blur(${blurs[3]}px)"/></g>`,
    );

    const segmentColors = hacdColorPair(gene[3 + segment]);
    const segmentId = gradientId(`grad3_${segment}`);
    shapes.push(
      `<linearGradient id="${segmentId}" x1="${take(100)}%" y1="${take(
        100,
      )}%" x2="${take(100)}%" y2="${take(
        100,
      )}%"><stop offset="0%" style="stop-color:#${
        segmentColors[0]
      };stop-opacity:${take(70) / 100}"/><stop offset="100%" style="stop-color:#${
        segmentColors[1]
      };stop-opacity:${take(70) / 100}"/></linearGradient>`,
    );
    for (let scatter = 0; scatter < 4; scatter += 1) {
      const first = Array.from(
        { length: 4 },
        () => `${400 + scatter * 80 + take(100)},${200 + scatter * 40 + take(100)}`,
      );
      const second = Array.from(
        { length: 4 },
        () => `${400 + scatter * 60 + take(200)},${200 + scatter * 20 + take(200)}`,
      );
      shapes.push(
        `<polygon points="${first.join(" ")}" opacity="${
          take(60) / 100 + 0.2
        }" fill="url(#${segmentId})" style="filter:blur(${take(160) / 10 + 4}px)"/>`,
        `<polygon points="${second.join(" ")}" opacity="${
          take(60) / 100 + 0.2
        }" fill="url(#${segmentId})" style="filter:blur(${take(50) / 10 + 4}px)"/>`,
      );
    }

    tangentGroups.forEach((group, groupIndex) => {
      const id = gradientId(`grad2_${segment}_${groupIndex}`);
      shapes.push(
        `<linearGradient id="${id}" x1="${take(100)}%" y1="${take(
          100,
        )}%" x2="${take(100)}%" y2="${take(
          100,
        )}%"><stop offset="0%" style="stop-color:#${
          mainColors[0]
        };stop-opacity:${take(80) / 100 + 0.2}"/><stop offset="100%" style="stop-color:#${
          mainColors[1]
        };stop-opacity:${take(80) / 100 + 0.2}"/></linearGradient>`,
        `<polygon style="filter:blur(${take(40) / 10}px)" points="${
          group === true
            ? tangentPolygon(groupIndex - 1, true)
            : tangentPolygon(groupIndex)
        }" opacity="${take(80) / 100 + 0.2}" fill="url(#${id})"/>`,
      );
    });
    shapes.push("</g>");
  }

  for (let segment = 0; segment < 8; segment += 1) {
    shapes.push(
      `<polygon points="582,87 249,225 367,43" fill="${backColor}" style="transform:rotate(${
        45 * segment
      }deg);transform-origin:center"/>`,
    );
  }

  const centerId = gradientId("grad4");
  shapes.push(
    `<linearGradient id="${centerId}" x1="${take(50) + 5}%" y1="${
      take(50) + 5
    }%" x2="${take(50) + 5}%" y2="${
      take(50) + 5
    }%"><stop offset="0%" style="stop-color:#${mainColors[0]};stop-opacity:${
      take(100) / 100
    }"/><stop offset="100%" style="stop-color:#${mainColors[1]};stop-opacity:${
      take(100) / 100
    }"/></linearGradient>`,
    `<polygon style="filter:blur(${
      take(30) / 10 + 1
    }px)" points="${centerPoints.map((point) => `${point.x},${point.y}`).join(" ")}" opacity="${
      take(70) / 100
    }" fill="url(#${centerId})"/>`,
  );

  const lightA = String(take(9)).repeat(2);
  const lightB = String(take(9)).repeat(2);
  const svg = `<svg class="dvhip8" version="1.2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 1200" width="${size}" height="${size}" style="background-image:linear-gradient(to top,#${
    mainColors[0]
  }${lightA},#${mainColors[1]}${lightB})"><g>${shapes.join(
    "",
  )}<circle cx="600" cy="600" r="700" stroke="${backColor}" stroke-width="400" fill="none"/></g></svg>`;
  if (svg.length > 250_000 || SAFE_SVG_RE.test(svg)) {
    throw new Error("Unsafe HIP-8 renderer output");
  }
  return svg;
}

function hashBytes(input: string | Uint8Array): Uint8Array {
  return Uint8Array.from(sha3_256.array(input));
}
