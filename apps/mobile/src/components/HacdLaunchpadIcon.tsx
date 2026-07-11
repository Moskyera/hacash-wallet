type Props = {
  className?: string;
};

/** HACD Labs mark (gold swoosh) — transparent, scales like other quick-action icons. */
export default function HacdLaunchpadIcon({ className = "hacd-launchpad-icon" }: Props) {
  return (
    <svg
      className={className}
      viewBox="0 0 32 32"
      role="img"
      aria-label="HACD Launchpad"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id="hacdMark" x1="4" y1="6" x2="26" y2="26" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#E8C872" />
          <stop offset="45%" stopColor="#C9A04A" />
          <stop offset="100%" stopColor="#8B6914" />
        </linearGradient>
      </defs>
      <path
        fill="url(#hacdMark)"
        d="M6 8c6 0 9 3 11 7 2-1 4-1 6 0-3 5-8 9-14 11-1-6 0-12-3-18z"
      />
      <path
        fill="url(#hacdMark)"
        fillOpacity="0.72"
        d="M10 12c4 1 7 4 8 8 2-1 3-1 5 0-2 3-5 6-9 7-1-4 0-8-4-15z"
      />
      <path
        fill="url(#hacdMark)"
        fillOpacity="0.45"
        d="M14 16c2 1 4 3 5 5 1-1 2-1 3 0-1 2-3 4-5 4-1-3 0-5-3-9z"
      />
    </svg>
  );
}