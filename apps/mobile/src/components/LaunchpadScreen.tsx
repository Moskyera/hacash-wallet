import { useEffect, useRef, useState } from "react";

const LAUNCHPAD_URL = "https://hacd.it/launchpad";
const MOBILE_VIEWPORT_W = 390;

export default function LaunchpadScreen() {
  const shellRef = useRef<HTMLDivElement>(null);
  const [scale, setScale] = useState(1);
  const [frameH, setFrameH] = useState(640);

  useEffect(() => {
    const shell = shellRef.current;
    if (!shell) return;

    const update = () => {
      const w = shell.clientWidth;
      const h = shell.clientHeight;
      const nextScale = w > 0 ? w / MOBILE_VIEWPORT_W : 1;
      setScale(nextScale);
      setFrameH(h > 0 ? h / nextScale : 640);
    };

    update();
    const ro = new ResizeObserver(update);
    ro.observe(shell);
    return () => ro.disconnect();
  }, []);

  return (
    <div className="launchpad-shell" ref={shellRef}>
      <div
        className="launchpad-mobile-stage"
        style={{ transform: `scale(${scale})`, width: MOBILE_VIEWPORT_W, height: frameH }}
      >
        <iframe
          className="launchpad-frame"
          src={LAUNCHPAD_URL}
          title="HACD Launchpad"
          width={MOBILE_VIEWPORT_W}
          height={frameH}
          sandbox="allow-scripts allow-same-origin allow-popups allow-forms"
        />
      </div>
    </div>
  );
}